import { randomUUID } from "node:crypto";
import type { FleetErrorEnvelope } from "@prime-agent/web-protocol/chat-protocol";
import { NETWORK_DISCONNECTED_MESSAGE } from "@prime-agent/web-protocol/chat-protocol";
import type { RequestPolicyErrorField } from "@prime-agent/web-protocol/request-policy";
import { ZodError } from "zod/v4";
import { admitRequest } from "./request-policy";

function getResponseStatus(error: unknown): number {
	if (error && typeof error === "object" && "status" in error) {
		const status = (error as { status?: unknown }).status;
		if (typeof status === "number" && status >= 400 && status < 600) return status;
	}
	return 500;
}

function getErrorMessage(error: unknown): string {
	if (error instanceof Error) return error.message;
	if (typeof error === "string") return error;
	try {
		return JSON.stringify(error);
	} catch {
		return String(error);
	}
}

/** Keep local filesystem details out of API errors rendered by the browser. */
export function safeErrorMessage(error: unknown): string {
	const message = getErrorMessage(error);
	return message
		.replace(/(['"])(\/(?!\/)[^'"\n]*|[A-Za-z]:\\[^'"\n]*)\1/g, "$1[local path]$1")
		.replace(/(^|[\s'"(])\/(?!\/)[^'"\s)]+/g, "$1[local path]")
		.replace(/[A-Za-z]:\\[^'"\s)]+/g, "[local path]");
}

const DAEMON_DISCONNECT_PATTERNS = [/cannot send daemon command/i, /daemon is not connected/i];

/**
 * The upstream daemon SDK reports transport failures as free-form message
 * strings carrying socket and log paths. Recognize them by shape so the raw
 * detail never reaches the browser.
 */
export function isDaemonDisconnectError(error: unknown): boolean {
	const message = getErrorMessage(error);
	return DAEMON_DISCONNECT_PATTERNS.some((pattern) => pattern.test(message));
}

/** Typed error envelope shared by the REST and stream error surfaces. */
export function chatErrorEnvelope(error: unknown): FleetErrorEnvelope {
	if (isDaemonDisconnectError(error)) {
		return {
			code: "NETWORK_DISCONNECTED",
			message: NETWORK_DISCONNECTED_MESSAGE,
			remediation: { action: "reconnect", label: "Reconnect runtime" },
		};
	}
	return { code: "UNKNOWN_ERROR", message: safeErrorMessage(error) };
}

/** Request-boundary envelope: no submitted values, stack traces or paths. */
function requestPolicyError(
	status: number,
	code: "INVALID_REQUEST" | "INTERNAL_ERROR",
	message: string,
	fields?: RequestPolicyErrorField[],
): Response {
	return Response.json(
		{ error: { code, message, retryable: code === "INTERNAL_ERROR", requestId: randomUUID(), fields } },
		{ status, headers: { "cache-control": "no-store" } },
	);
}

function zodFieldIssues(error: ZodError): RequestPolicyErrorField[] {
	return error.issues.map((issue) => ({
		path: issue.path.map((segment) => String(segment)).join("."),
		code: String(issue.code ?? "invalid"),
	}));
}

/**
 * Fail closed when a mounted API route receives a method it does not
 * implement (request-boundary spec RB-06). Without an explicit catch-all the
 * framework falls through to the SPA shell with 200, which is not a safe
 * answer at the API boundary. Wired as the `ANY` handler on every API route.
 */
export function methodNotAllowed(): Response {
	return Response.json(
		{
			error: {
				code: "METHOD_NOT_ALLOWED",
				message: "Method not allowed",
				retryable: false,
				requestId: randomUUID(),
			},
		},
		{ status: 405, headers: { "cache-control": "no-store" } },
	);
}

/**
 * Admits the request through the request-boundary policy, then runs the
 * handler. Admission happens before any body parsing or side effect; schema
 * and framing failures map to 400/415/413/500 envelopes that never echo
 * submitted values.
 */
export function wrapApiHandler(request: Request, handler: () => Promise<Response>): Promise<Response> {
	const admission = admitRequest(request);
	if (!admission.ok) return Promise.resolve(admission.response);
	return handler().catch((error: unknown) => {
		if (error instanceof ZodError) {
			return requestPolicyError(400, "INVALID_REQUEST", "Request failed schema validation", zodFieldIssues(error));
		}
		if (error instanceof SyntaxError) {
			return requestPolicyError(400, "INVALID_REQUEST", "Malformed JSON body");
		}
		if (isDaemonDisconnectError(error)) {
			// Raw transport detail stays server-side.
			process.stderr.write(`[api] daemon transport failure: ${getErrorMessage(error)}\n`);
			return Response.json(chatErrorEnvelope(error), { status: getResponseStatus(error) });
		}
		const status = getResponseStatus(error);
		if (status !== 500) {
			// Handler-declared status: legacy flat envelope, scrubbed message.
			return Response.json(chatErrorEnvelope(error), { status });
		}
		const requestId = randomUUID();
		process.stderr.write(`[api] internal error (${requestId}): ${getErrorMessage(error)}\n`);
		return requestPolicyError(500, "INTERNAL_ERROR", "Internal server error");
	});
}
