import type {
	ChatSessionMetadata,
	ChatStreamEvent,
	FleetErrorCode,
	FleetErrorRemediation,
} from "@prime-agent/web-protocol/chat-protocol";
import { ChatStreamEventSchema } from "@prime-agent/web-protocol/chat-protocol.zod";
import {
	REQUEST_POLICY_PROTOCOL_HEADER,
	type RequestPolicyBootstrapResponse,
} from "@prime-agent/web-protocol/request-policy";
import { RequestPolicyBootstrapResponseSchema } from "@prime-agent/web-protocol/request-policy.zod";
import type { ZodType } from "zod";
import { resolveChatApiUrl } from "@/lib/pi/chat-runtime-url";

// Request-boundary transport (request-boundary spec): the admission grant is
// obtained from GET /api/bootstrap and held only in this module's memory —
// never in URLs, storage, cookies or logs. Renewal is single-flight.
type GrantState = { grant: string; launchId: string; expiresAtMs: number };
let grantState: GrantState | null = null;
let inflightBootstrap: Promise<GrantState | null> | null = null;
const GRANT_RENEW_MARGIN_MS = 60_000;

async function fetchBootstrap(): Promise<GrantState | null> {
	try {
		const response = await fetch(resolveChatApiUrl("/api/bootstrap"), {
			cache: "no-store",
			credentials: "omit",
		});
		if (!response.ok) return null;
		const data: RequestPolicyBootstrapResponse = RequestPolicyBootstrapResponseSchema.parse(await response.json());
		grantState = { grant: data.grant, launchId: data.launchId, expiresAtMs: Date.parse(data.expiresAt) };
		return grantState;
	} catch {
		return null;
	}
}

function clearChatAuthBearerTokenCache(): void {
	grantState = null;
}

async function getChatAuthBearerToken(): Promise<string | null> {
	if (grantState && Date.now() < grantState.expiresAtMs - GRANT_RENEW_MARGIN_MS) {
		return grantState.grant;
	}
	if (!inflightBootstrap) {
		inflightBootstrap = fetchBootstrap().finally(() => {
			inflightBootstrap = null;
		});
	}
	const state = await inflightBootstrap;
	return state ? state.grant : null;
}

export class ChatRequestError extends Error {
	readonly status: number;
	readonly body: string;
	readonly code: string | undefined;
	readonly remediation: FleetErrorRemediation | undefined;

	constructor(status: number, body: string) {
		super(formatChatRequestErrorMessage(status, body));
		this.name = "ChatRequestError";
		this.status = status;
		this.body = body;
		const envelope = parseErrorEnvelope(body);
		this.code = envelope?.code;
		this.remediation = envelope?.remediation;
	}
}

function isFleetErrorRemediation(value: unknown): value is FleetErrorRemediation {
	return (
		typeof value === "object" &&
		value !== null &&
		typeof (value as { action?: unknown }).action === "string" &&
		typeof (value as { label?: unknown }).label === "string"
	);
}

function parseErrorEnvelope(body: string): { code: string; remediation?: FleetErrorRemediation } | null {
	const trimmed = body.trim();
	if (!trimmed) return null;
	try {
		const parsed = JSON.parse(trimmed) as {
			code?: unknown;
			error?: unknown;
			remediation?: unknown;
		};
		// Current: { error: { code, ... } } request-boundary wrapper. Legacy: flat envelope.
		const source =
			parsed.error && typeof parsed.error === "object"
				? (parsed.error as { code?: unknown; remediation?: unknown })
				: parsed;
		if (typeof source.code === "string") {
			return {
				code: source.code,
				remediation: isFleetErrorRemediation(source.remediation) ? source.remediation : undefined,
			};
		}
	} catch {
		// Server did not return a JSON error envelope.
	}
	return null;
}

function formatChatRequestErrorMessage(status: number, body: string) {
	const envelope = parseErrorEnvelope(body);
	if (envelope?.code === "CONTRACT_UPGRADE_REQUIRED") {
		return "Fleet was updated. Reload this page to continue.";
	}
	if (envelope?.code === "AUTH_REQUIRED") {
		return "Your Fleet session expired. Reloading the page will fix this.";
	}
	const trimmed = body.trim();
	if (!trimmed) return `Request failed (${status})`;
	try {
		const parsed = JSON.parse(trimmed) as { message?: unknown; error?: { message?: unknown } };
		const message = parsed.error && typeof parsed.error === "object" ? parsed.error.message : parsed.message;
		if (typeof message === "string" && message.length > 0) {
			return message;
		}
	} catch {
		// Keep raw body when the server did not return JSON.
	}
	return trimmed;
}

export function isForbiddenSessionError(error: unknown) {
	const body = error instanceof ChatRequestError ? error.body : error instanceof Error ? error.message : String(error);
	return body.includes("Session belongs to another user");
}

/** True when the server no longer knows the session (404 from session loads). */
export function isUnknownSessionError(error: unknown): boolean {
	return error instanceof ChatRequestError && error.status === 404;
}

/** True for daemon transport failures, typed (envelope code) or legacy (raw upstream message). */
export function isDaemonDisconnectError(error: unknown): boolean {
	if (!(error instanceof Error)) return false;
	if ((error as { code?: unknown }).code === "NETWORK_DISCONNECTED") return true;
	return /daemon is not connected/i.test(error.message) || /cannot send daemon command/i.test(error.message);
}

/** Stream error events drop their typed envelope when re-thrown; keep the code attached. */
export function chatErrorFromStreamEvent(event: { message: string; code?: FleetErrorCode }): Error {
	const error = new Error(event.message) as Error & { code?: FleetErrorCode };
	if (event.code) error.code = event.code;
	return error;
}

async function withChatRequestHeaders(init?: RequestInit) {
	const headers = new Headers(init?.headers);

	const bearer = await getChatAuthBearerToken();
	if (bearer) {
		headers.set("Authorization", `Bearer ${bearer}`);
		headers.set(REQUEST_POLICY_PROTOCOL_HEADER, "2");
	}

	return headers;
}

/**
 * Fetch with request-boundary credentials: the admission grant (when held) and
 * protocol header are attached, and a single 401 retry re-bootstraps once.
 *
 * A 401 is an admission rejection: the handler never ran, so retrying a
 * mutation after renewal cannot double-execute it.
 */
export async function authorizedFetch(url: string, init?: RequestInit): Promise<Response> {
	const resolvedUrl = resolveChatApiUrl(url);
	const attempt = async (allowRetry: boolean): Promise<Response> => {
		const headers = await withChatRequestHeaders(init);
		const response = await fetch(resolvedUrl, { ...init, headers });
		if (response.status === 401 && allowRetry) {
			clearChatAuthBearerTokenCache();
			return attempt(false);
		}
		return response;
	};
	return attempt(true);
}

export async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
	const response = await authorizedFetch(url, init);
	if (!response.ok) {
		const body = await response.text();
		throw new ChatRequestError(response.status, body);
	}
	return (await response.json()) as T;
}

// --- SSE over authorized fetch -------------------------------------------
//
// The native EventSource API cannot send Authorization headers, so the request
// boundary (which requires the grant on every non-bootstrap API route) breaks
// it. FetchEventSource preserves the surface the event hooks rely on
// (onmessage with { data, lastEventId }, onerror, close) while carrying the
// admission headers. Reconnect cadence stays owned by the hooks, exactly as
// with native EventSource.

export type FetchEventMessage = { data: string; lastEventId: string | null };

function parseSseFrame(frame: string): FetchEventMessage | null {
	const data: string[] = [];
	let lastEventId: string | null = null;
	for (const line of frame.split("\n")) {
		if (line.startsWith(":")) continue; // comment / heartbeat
		if (line.startsWith("id:")) lastEventId = line.slice(3).trim();
		else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
	}
	if (data.length === 0) return null;
	return { data: data.join("\n"), lastEventId };
}

/**
 * The structural surface the event hooks depend on. Kept as an interface
 * (not `typeof FetchEventSource`) because the class carries private members,
 * which would make the type nominally incompatible with the lightweight stubs
 * tests install via setEventStreamConstructorForTests.
 */
export interface EventStreamLike {
	onopen?: (() => void) | null;
	onmessage?: ((event: FetchEventMessage) => void) | null;
	onerror?: (() => void) | null;
	close(): void;
}

export type EventStreamConstructor = new (url: string) => EventStreamLike;

/**
 * The stream class the event hooks instantiate. Tests swap this via
 * setEventStreamConstructorForTests to inject a controllable stub; production
 * always uses FetchEventSource.
 */
export let eventStreamConstructor: EventStreamConstructor;

export function setEventStreamConstructorForTests(replacement: EventStreamConstructor | null): void {
	eventStreamConstructor = replacement ?? FetchEventSource;
}

export class FetchEventSource implements EventStreamLike {
	private readonly controller = new AbortController();
	private closed = false;
	onopen: (() => void) | null = null;
	onmessage: ((event: FetchEventMessage) => void) | null = null;
	onerror: (() => void) | null = null;

	constructor(url: string) {
		void this.run(url);
	}

	private async run(url: string): Promise<void> {
		try {
			const response = await authorizedFetch(url, {
				method: "GET",
				headers: { accept: "text/event-stream" },
				cache: "no-store",
				signal: this.controller.signal,
			});
			if (!response.ok || !response.body) {
				this.onerror?.();
				return;
			}
			this.onopen?.();
			const reader = response.body.getReader();
			const decoder = new TextDecoder();
			let buffer = "";
			for (;;) {
				const { value, done } = await reader.read();
				if (done) break;
				buffer += decoder.decode(value, { stream: true });
				let separator = buffer.indexOf("\n\n");
				while (separator !== -1) {
					const rawFrame = buffer.slice(0, separator);
					buffer = buffer.slice(separator + 2);
					const message = parseSseFrame(rawFrame);
					if (message) this.onmessage?.(message);
					separator = buffer.indexOf("\n\n");
				}
			}
			// Server-closed stream: surface as an error so the hook reconnects,
			// matching how the hooks treated EventSource failures.
			if (!this.closed) this.onerror?.();
		} catch {
			if (!this.closed) this.onerror?.();
		}
	}

	close(): void {
		this.closed = true;
		this.controller.abort();
	}
}

eventStreamConstructor = FetchEventSource;

export async function fetchValidatedJson<T>(url: string, schema: ZodType<T>, init?: RequestInit): Promise<T> {
	const data = await fetchJson<unknown>(url, init);
	return parseWithSchema(schema, data, `Response from ${url}`);
}

/**
 * Reads newline-delimited chat events from a response stream and delivers them to a callback.
 *
 * @param response - The response containing the chat event stream
 * @param onEvent - Callback invoked for each parsed chat event
 */
export async function readChatStream(response: Response, onEvent: (event: ChatStreamEvent) => void) {
	const reader = response.body?.getReader();
	if (!reader) throw new Error("Chat response did not include a stream");

	const decoder = new TextDecoder();
	let buffer = "";

	// Sequence tracking for critical events to detect reordering/duplication
	const expectedSequenceNumbers = new Map<string, number>();

	/** Track event sequence per session */
	function trackSequence(sessionId: string, eventType: string, seq: number) {
		const current = expectedSequenceNumbers.get(`${sessionId}:${eventType}`) ?? 0;
		if (seq > current + 1) {
			console.warn(
				`[chat-sequence] Gap detected in ${eventType} sequence for session ${sessionId}: ` +
					`expected ${current + 1}, got ${seq}`,
			);
		}
		expectedSequenceNumbers.set(`${sessionId}:${eventType}`, seq);
	}

	// Fast path: JSON.parse without Zod for high-frequency delta events
	const handleLine = (line: string) => {
		const trimmed = line.trim();
		if (!trimmed) return;

		const data = JSON.parse(trimmed) as unknown;
		const eventType =
			typeof data === "object" && data !== null
				? "type" in data && (data as Record<string, unknown>).type
				: undefined;

		// Extract session ID and sequence number for tracking
		const sessionId =
			typeof data === "object" && data !== null && "sessionId" in data ? String((data as any).sessionId) : undefined;
		const sequenceNumber =
			typeof data === "object" && data !== null && "sequenceNumber" in data
				? Number((data as any).sequenceNumber)
				: undefined;

		// Validate only low-frequency events that carry schema-critical structure
		if (
			eventType === "start" ||
			eventType === "done" ||
			eventType === "error" ||
			eventType === "plan" ||
			eventType === "state" ||
			eventType === "tool" ||
			eventType === "queue" ||
			eventType === "reasoning" ||
			eventType === "compaction" ||
			eventType === "retry" ||
			eventType === "payload" ||
			eventType === "session_snapshot"
		) {
			const validatedEvent = parseWithSchema(ChatStreamEventSchema, data, "Chat stream event");

			// Track sequence for critical structural events
			if (sessionId && sequenceNumber !== undefined) {
				trackSequence(sessionId, String(validatedEvent.type), sequenceNumber);
			}

			onEvent(validatedEvent);
		} else {
			// Fast path: assume delta and legacy compatibility events are well-formed NDJSON
			onEvent(data as ChatStreamEvent);
		}
	};

	for (;;) {
		const { value, done } = await reader.read();
		if (done) break;
		const chunk = decoder.decode(value, { stream: true });
		buffer += chunk;

		let newlineIndex = buffer.indexOf("\n");
		while (newlineIndex >= 0) {
			handleLine(buffer.slice(0, newlineIndex));
			buffer = buffer.slice(newlineIndex + 1);
			newlineIndex = buffer.indexOf("\n");
		}
	}

	buffer += decoder.decode();
	handleLine(buffer);
}

export function parseWithSchema<T>(schema: ZodType<T>, data: unknown, label: string): T {
	const parsed = schema.safeParse(data);
	if (parsed.success) return parsed.data;

	throw new Error(`${label} did not match the expected contract`);
}

export function metadataUrl(metadata: ChatSessionMetadata) {
	const params = new URLSearchParams();
	if (metadata.sessionId) params.set("sessionId", metadata.sessionId);
	if (metadata.projectId) params.set("projectId", metadata.projectId);
	if (metadata.openUI) params.set("openUI", "true");
	return params.toString();
}

/**
 * Mirror of the TUI's working-loader labels. The TUI cycles between
 * "Working", "Waiting", "Thinking", "Writing", "Executing" (a weighted
 * random pick per turn) plus elapsed seconds and token counts. The web port
 * surfaces deterministic labels driven by stream state so the composer
 * loader matches what the agent is actually doing.
 */
export function labelForState(state: ChatStreamEvent["type"] | string) {
	switch (state) {
		case "agent_start":
			return "Working";
		case "turn_start":
			return "Waiting";
		case "message_start":
			return "Thinking";
		case "message_end":
			return "Writing";
		case "tool_start":
		case "tool_execution_start":
		case "tool_execution":
			return "Executing";
		case "tool_end":
		case "tool_execution_end":
			return "Writing";
		case "turn_end":
			return "Turn finished";
		case "agent_end":
			return undefined;
		default:
			return undefined;
	}
}

export type QueueState = {
	steering: Array<string>;
	followUp: Array<string>;
};
