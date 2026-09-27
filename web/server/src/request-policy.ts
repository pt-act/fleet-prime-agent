import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import {
	evaluateRequestOrigin,
	parseHostAuthority,
	REQUEST_POLICY_BOUND_ORIGIN_HEADER,
	REQUEST_POLICY_DECLARED_LENGTH_HEADER,
	REQUEST_POLICY_PROTOCOL_HEADER,
	REQUEST_POLICY_PROTOCOL_VERSION,
	type RequestPolicyAdmittedContext,
	type RequestPolicyError,
	type RequestPolicyErrorCode,
	type RequestPolicyErrorEnvelope,
} from "@prime-agent/web-protocol/request-policy";

/**
 * Request-boundary policy authority (spec `request-boundary`).
 *
 * Both launch paths — the packaged launcher and the Vite dev middleware —
 * terminate in the same route handlers, so admission is decided exactly once,
 * here. The launch paths only run a thin exact-origin pre-gate and inject the
 * trusted bound-origin header this module reads.
 */

export type RouteClass = "bootstrap" | "read" | "mutation" | "upload";

const DEFAULT_GRANT_TTL_MS = 30 * 60 * 1000;

/**
 * Grants live for 30 minutes; a new bootstrap invalidates the previous grant.
 * The env override is a test seam: it may only SHORTEN grants (clamped to the
 * 30-minute spec maximum), never extend them.
 */
export const REQUEST_POLICY_GRANT_TTL_MS = (() => {
	const raw = process.env.FLEET_REQUEST_POLICY_GRANT_TTL_MS;
	if (raw === undefined) return DEFAULT_GRANT_TTL_MS;
	const parsed = Number(raw);
	if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_GRANT_TTL_MS;
	return Math.min(parsed, DEFAULT_GRANT_TTL_MS);
})();
const GRANT_BYTES = 32;

/** Transport-level body budgets. The 100 MiB per-turn attachment semantic limit
 * stays in the attachments handler; this pre-check only leaves form overhead. */
export const JSON_BODY_LIMIT_BYTES = 1024 * 1024;
export const UPLOAD_BODY_LIMIT_BYTES = 128 * 1024 * 1024;

const LOOPBACK_SCHEME = "http";

// --- launch + grant state (memory-only; never persisted or logged) ---

const launchId = randomUUID();
let currentGrant: { value: string; expiresAt: number } | null = null;

export function getLaunchId(): string {
	return launchId;
}

/** Mints a fresh grant, invalidating any previous one (one active per launch). */
export function mintBootstrapGrant(): { grant: string; expiresAt: string } {
	const value = randomBytes(GRANT_BYTES).toString("base64url");
	const expiresAt = Date.now() + REQUEST_POLICY_GRANT_TTL_MS;
	currentGrant = { value, expiresAt };
	return { grant: value, expiresAt: new Date(expiresAt).toISOString() };
}

/**
 * Pure grant check: decides against the PASSED grant state, never the module
 * singleton — decideAdmission must be a pure function of its inputs (PBT P1/P2
 * depend on this; the singleton is only read by admitRequest).
 */
function grantIsValid(
	authorization: string | null,
	grant: { value: string; expiresAt: number } | null,
	now: number,
): boolean {
	if (!authorization?.startsWith("Bearer ")) return false;
	if (!grant || now >= grant.expiresAt) return false;
	const presented = Buffer.from(authorization.slice("Bearer ".length));
	const expected = Buffer.from(grant.value);
	return presented.length === expected.length && timingSafeEqual(presented, expected);
}

// --- route classification (unknown route/method fails closed) ---

const ROUTE_REGISTRY: ReadonlyMap<string, RouteClass> = new Map<string, RouteClass>([
	["GET /api/bootstrap", "bootstrap"],
	["GET /api/health", "read"],
	["POST /api/chat", "mutation"],
	["POST /api/chat/abort", "mutation"],
	["PUT /api/chat/artifacts", "mutation"],
	["POST /api/chat/command", "mutation"],
	["GET /api/chat/commands", "read"],
	["GET /api/chat/events", "read"],
	["POST /api/chat/model", "mutation"],
	["GET /api/chat/models", "read"],
	["POST /api/chat/models/discover", "mutation"],
	["POST /api/chat/new", "mutation"],
	["GET /api/chat/providers", "read"],
	["POST /api/chat/providers", "mutation"],
	["DELETE /api/chat/providers", "mutation"],
	["POST /api/chat/providers/oauth", "mutation"],
	["POST /api/chat/question", "mutation"],
	["GET /api/chat/resources", "read"],
	["POST /api/chat/resume", "mutation"],
	["GET /api/chat/session", "read"],
	["POST /api/chat/session", "upload"],
	["PUT /api/chat/session", "mutation"],
	["PATCH /api/chat/session", "mutation"],
	["GET /api/chat/sessions", "read"],
	["DELETE /api/chat/sessions", "mutation"],
	["PATCH /api/chat/sessions", "mutation"],
	["GET /api/chat/settings", "read"],
	["PATCH /api/chat/settings", "mutation"],
	["GET /api/projects", "read"],
	["POST /api/projects", "mutation"],
	["PATCH /api/projects", "mutation"],
	["DELETE /api/projects", "mutation"],
	["GET /api/projects/browse", "read"],
	["POST /api/projects/fork", "mutation"],
	["GET /api/workspace/browse", "read"],
	["GET /api/workspace/file", "read"],
	["POST /api/workspace/root", "mutation"],
	["GET /api/workspace/tree", "read"],
]);

export function classifyRequest(method: string, pathname: string): RouteClass | undefined {
	return ROUTE_REGISTRY.get(`${method.toUpperCase()} ${pathname}`);
}

// --- pure admission decision (PBT surface) ---

export type AdmissionInputs = {
	routeClass: RouteClass | undefined;
	/** Port the server actually listens on; null when no trusted boundary configured it. */
	boundPort: number | null;
	origin: string | null;
	host: string | null;
	secFetchSite: string | null;
	authorization: string | null;
	protocolHeader: string | null;
	contentType: string | null;
	contentLength: string | null;
	chunked: boolean;
	now: number;
	grant: { value: string; expiresAt: number } | null;
};

export type AdmissionDecision = { ok: true } | { ok: false; status: number; code: RequestPolicyErrorCode };

const RETRYABLE_CODES: ReadonlySet<string> = new Set(["AUTH_REQUIRED", "INTERNAL_ERROR"]);

/** Check order: classify → Host/Origin → bootstrap fetch-metadata → grant →
 * protocol → media type → length. The first failure decides the response. */
export function decideAdmission(input: AdmissionInputs): AdmissionDecision {
	if (input.routeClass === undefined) return { ok: false, status: 404, code: "NOT_FOUND" };
	if (input.boundPort === null) return { ok: false, status: 500, code: "INTERNAL_ERROR" };
	if (!evaluateRequestOrigin({ origin: input.origin, host: input.host, boundPort: input.boundPort })) {
		return { ok: false, status: 403, code: "ORIGIN_DENIED" };
	}
	if (input.routeClass === "bootstrap" && input.secFetchSite !== null && input.secFetchSite !== "same-origin") {
		return { ok: false, status: 403, code: "ORIGIN_DENIED" };
	}
	if (input.routeClass !== "bootstrap" && !grantIsValid(input.authorization, input.grant, input.now)) {
		return { ok: false, status: 401, code: "AUTH_REQUIRED" };
	}
	const carriesBody = input.routeClass === "mutation" || input.routeClass === "upload";
	if (carriesBody && input.protocolHeader !== "2") {
		return { ok: false, status: 426, code: "CONTRACT_UPGRADE_REQUIRED" };
	}
	const declaredLength = input.contentLength === null ? null : Number(input.contentLength);
	if (input.contentLength !== null && (!Number.isFinite(declaredLength) || (declaredLength as number) < 0)) {
		return { ok: false, status: 400, code: "INVALID_REQUEST" };
	}
	const hasBody = input.chunked || (declaredLength ?? 0) > 0 || input.contentType !== null;
	if (input.routeClass === "upload") {
		if (!input.contentType?.toLowerCase().startsWith("multipart/form-data")) {
			return { ok: false, status: 415, code: "UNSUPPORTED_MEDIA_TYPE" };
		}
	} else if (input.routeClass === "mutation" && hasBody) {
		const mediaType = input.contentType?.split(";")[0]?.trim().toLowerCase();
		if (mediaType !== "application/json") {
			return { ok: false, status: 415, code: "UNSUPPORTED_MEDIA_TYPE" };
		}
	}
	const limit = input.routeClass === "upload" ? UPLOAD_BODY_LIMIT_BYTES : JSON_BODY_LIMIT_BYTES;
	if (declaredLength !== null && declaredLength > limit) {
		return { ok: false, status: 413, code: "PAYLOAD_TOO_LARGE" };
	}
	return { ok: true };
}

// --- policy error responses ---

export function policyErrorResponse(
	status: number,
	code: RequestPolicyErrorCode,
	message: string,
	options?: { retryable?: boolean },
): Response {
	const error: RequestPolicyError = {
		code,
		message,
		retryable: options?.retryable ?? RETRYABLE_CODES.has(code),
		requestId: randomUUID(),
	};
	const body: RequestPolicyErrorEnvelope = { error };
	return Response.json(body, { status, headers: { "cache-control": "no-store" } });
}

const DENIAL_MESSAGES: Record<RequestPolicyErrorCode, string> = {
	ORIGIN_DENIED: "Same-origin loopback requests only",
	AUTH_REQUIRED: "Admission grant missing or expired; re-bootstrap and retry",
	CONTRACT_UPGRADE_REQUIRED: "This client is out of date; reload to upgrade the protocol",
	INVALID_REQUEST: "Invalid request framing",
	UNSUPPORTED_MEDIA_TYPE: "Unsupported media type",
	PAYLOAD_TOO_LARGE: "Request body exceeds the transport limit",
	INTERNAL_ERROR: "Internal server error",
	NOT_FOUND: "Unknown API route",
};

// --- admission against a live Request ---

export type AdmissionResult = { ok: true; context: RequestPolicyAdmittedContext } | { ok: false; response: Response };

const admittedContexts = new WeakMap<Request, RequestPolicyAdmittedContext>();

/** Admitted context for a request previously passed through `admitRequest`. */
export function getAdmittedContext(request: Request): RequestPolicyAdmittedContext | undefined {
	return admittedContexts.get(request);
}

function trustedBoundPort(request: Request): number | null {
	// Trusted only because the launcher and dev middleware overwrite this
	// header before the request reaches route handlers.
	const boundOrigin = request.headers.get(REQUEST_POLICY_BOUND_ORIGIN_HEADER);
	if (!boundOrigin) return null;
	try {
		const { port } = parseHostAuthority(new URL(boundOrigin).host);
		return port === null ? null : Number(port);
	} catch {
		return null;
	}
}

export function admitRequest(request: Request): AdmissionResult {
	const url = new URL(request.url);
	const declaredLength =
		request.headers.get("content-length") ?? request.headers.get(REQUEST_POLICY_DECLARED_LENGTH_HEADER);
	const decision = decideAdmission({
		routeClass: classifyRequest(request.method, url.pathname),
		boundPort: trustedBoundPort(request),
		origin: request.headers.get("origin"),
		host: request.headers.get("host"),
		secFetchSite: request.headers.get("sec-fetch-site"),
		authorization: request.headers.get("authorization"),
		protocolHeader: request.headers.get(REQUEST_POLICY_PROTOCOL_HEADER),
		contentType: request.headers.get("content-type"),
		contentLength: declaredLength,
		chunked: request.headers.has("transfer-encoding"),
		now: Date.now(),
		grant: currentGrant,
	});
	if (decision.ok) {
		const context: RequestPolicyAdmittedContext = {
			launchId,
			principal: "local-operator",
			requestId: randomUUID(),
		};
		admittedContexts.set(request, context);
		return { ok: true, context };
	}
	return {
		ok: false,
		response: policyErrorResponse(decision.status, decision.code, DENIAL_MESSAGES[decision.code]),
	};
}

export const REQUEST_POLICY_LOOPBACK_SCHEME = LOOPBACK_SCHEME;
export const REQUEST_POLICY_PROTOCOL_VERSION_VALUE = REQUEST_POLICY_PROTOCOL_VERSION;
