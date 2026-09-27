import { z } from "./z";

/**
 * RequestPolicy — request-boundary DTO contract (spec `request-boundary` v1.0.0).
 *
 * REQUEST_POLICY_SHAPE below is the normative shape block from the spec.
 * REQUEST_POLICY_FINGERPRINT is the SHA-256 of that exact UTF-8 text
 * (excluding code fences and any trailing newline). Changing the shape
 * requires a spec version bump and explicit consumer review.
 */
export const REQUEST_POLICY_CONTRACT_VERSION = "1.0.0";
export const REQUEST_POLICY_PROTOCOL_VERSION = 2;

export const REQUEST_POLICY_SHAPE = `type RequestPolicy = {
  protocolVersion: 2;
  bootstrap: { launchId: string; grant: string; expiresAt: string };
  authenticatedHeaders: { Authorization: \`Bearer \${string}\`; "X-Fleet-Protocol": "2" };
  admittedContext: { launchId: string; principal: "local-operator"; requestId: string };
  error: { error: { code: string; message: string; retryable: boolean; requestId: string;
    fields?: { path: string; code: string }[] } };
};`;

export const REQUEST_POLICY_FINGERPRINT = "e440435d7fed126e37734afa40a17c0f4585633a9dd61369f903e575c71d0d9f";

/** Header carrying the current protocol major on every authenticated API call. */
export const REQUEST_POLICY_PROTOCOL_HEADER = "x-fleet-protocol";

/**
 * Trusted header carrying the origin the server actually bound to. Only the
 * packaged launcher and the Vite dev middleware may set it; both overwrite any
 * client-supplied value before the request reaches route handlers.
 */
export const REQUEST_POLICY_BOUND_ORIGIN_HEADER = "x-fleet-bound-origin";

/**
 * Trusted header carrying the transport-level declared Content-Length. The
 * Vite dev middleware injects it because fetch-Request construction inside the
 * dev pipeline drops the original content-length header; the packaged
 * launcher's Requests keep the real header, which takes precedence.
 */
export const REQUEST_POLICY_DECLARED_LENGTH_HEADER = "x-fleet-declared-length";

// ---------------------------------------------------------------------------
// DTO schemas
// ---------------------------------------------------------------------------

export const RequestPolicyBootstrapResponseSchema = z
	.object({
		protocolVersion: z.literal(REQUEST_POLICY_PROTOCOL_VERSION),
		launchId: z.string().min(1),
		grant: z.string().min(1),
		expiresAt: z.string().min(1),
	})
	.openapi({ description: "Bootstrap response minting a short-lived admission grant" });

export const RequestPolicyErrorCodeSchema = z
	.enum([
		"ORIGIN_DENIED",
		"AUTH_REQUIRED",
		"CONTRACT_UPGRADE_REQUIRED",
		"INVALID_REQUEST",
		"UNSUPPORTED_MEDIA_TYPE",
		"PAYLOAD_TOO_LARGE",
		"INTERNAL_ERROR",
		"NOT_FOUND",
	])
	.openapi({ description: "Machine-readable request-boundary error code" });

export const RequestPolicyErrorFieldSchema = z
	.object({
		path: z.string(),
		code: z.string(),
	})
	.openapi({ description: "Schema-validation failure location and reason (never the submitted value)" });

export const RequestPolicyErrorSchema = z
	.object({
		code: RequestPolicyErrorCodeSchema,
		message: z.string(),
		retryable: z.boolean(),
		requestId: z.string(),
		fields: z.array(RequestPolicyErrorFieldSchema).optional(),
	})
	.openapi({ description: "Request-boundary error envelope payload" });

export const RequestPolicyErrorEnvelopeSchema = z
	.object({
		error: RequestPolicyErrorSchema,
	})
	.openapi({ description: "Wire wrapper for request-boundary errors" });

export const RequestPolicyAdmittedContextSchema = z
	.object({
		launchId: z.string().min(1),
		principal: z.literal("local-operator"),
		requestId: z.string().min(1),
	})
	.openapi({ description: "Server-internal admission context; only requestId is ever serialized to browsers" });

export const RequestPolicyAuthenticatedHeadersSchema = z
	.object({
		Authorization: z.string().refine((value) => value.startsWith("Bearer "), "Expected a Bearer grant"),
		"X-Fleet-Protocol": z.literal("2"),
	})
	.openapi({ description: "Headers every authenticated API call must carry" });

export type RequestPolicyBootstrapResponse = z.infer<typeof RequestPolicyBootstrapResponseSchema>;
export type RequestPolicyErrorCode = z.infer<typeof RequestPolicyErrorCodeSchema>;
export type RequestPolicyErrorField = z.infer<typeof RequestPolicyErrorFieldSchema>;
export type RequestPolicyError = z.infer<typeof RequestPolicyErrorSchema>;
export type RequestPolicyErrorEnvelope = z.infer<typeof RequestPolicyErrorEnvelopeSchema>;
export type RequestPolicyAdmittedContext = z.infer<typeof RequestPolicyAdmittedContextSchema>;
export type RequestPolicyAuthenticatedHeaders = z.infer<typeof RequestPolicyAuthenticatedHeadersSchema>;

// ---------------------------------------------------------------------------
// Exact-origin evaluation (pure; shared by launcher pre-gate, Vite dev
// middleware and the server-side policy — the launcher keeps a dependency-free
// copy in scripts/prime-agent-web-launcher.mjs)
// ---------------------------------------------------------------------------

const LOOPBACK_HOSTNAMES = new Set(["127.0.0.1", "localhost", "::1"]);

export function isLoopbackHostname(hostname: string): boolean {
	return LOOPBACK_HOSTNAMES.has(hostname.trim().toLowerCase());
}

/** Parses a Host-header authority ("host" or "host:port", IPv6 in brackets). */
export function parseHostAuthority(authority: string): { hostname: string; port: string | null } {
	let host = authority.trim();
	let port: string | null = null;
	const bracketEnd = host.indexOf("]");
	if (host.startsWith("[") && bracketEnd !== -1) {
		const suffix = host.slice(bracketEnd + 1);
		if (suffix.startsWith(":")) port = suffix.slice(1);
		host = host.slice(1, bracketEnd);
	} else if (host.indexOf(":") === host.lastIndexOf(":") && host.includes(":")) {
		const colon = host.indexOf(":");
		port = host.slice(colon + 1);
		host = host.slice(0, colon);
	}
	if (port !== null && !/^\d+$/.test(port)) port = null;
	return { hostname: host.toLowerCase(), port };
}

export type RequestOriginCheck = {
	/** Origin header value, when the client sent one. */
	origin: string | null | undefined;
	/** Host header value. */
	host: string | null | undefined;
	/** The port the server actually listens on. */
	boundPort: number | string;
};

/**
 * Exact-origin admission for a request:
 *
 * - the Host authority must be a loopback hostname on the bound port; and
 * - when an Origin header is present, it must be exactly `http://` plus the
 *   request's own Host authority (a same-origin request by definition).
 *
 * Absent Origin is allowed (non-browser local clients); the opaque origin
 * "null" and every cross-origin/lookalike/non-loopback value are denied.
 */
export function evaluateRequestOrigin({ origin, host, boundPort }: RequestOriginCheck): boolean {
	if (!host) return false;
	const { hostname, port } = parseHostAuthority(host);
	if (!isLoopbackHostname(hostname)) return false;
	if (port === null || Number(port) !== Number(boundPort)) return false;
	if (origin === undefined || origin === null || origin === "") return true;
	if (origin === "null") return false;

	let parsed: URL;
	try {
		parsed = new URL(origin);
	} catch {
		return false;
	}
	if (parsed.protocol !== "http:") return false;
	// Node's URL keeps IPv6 brackets in .hostname ("[::1]"); strip before comparing.
	const originHostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
	if (!isLoopbackHostname(originHostname)) return false;
	const originPort = parsed.port || "80";
	return originPort === port && originHostname === hostname;
}
