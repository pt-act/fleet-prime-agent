import { mintBootstrapGrant } from "../request-policy";

let cachedGrant: string | null = null;

function currentGrant(): string {
	if (cachedGrant === null) cachedGrant = mintBootstrapGrant().grant;
	return cachedGrant;
}

/**
 * Builds a Request that passes request-boundary admission: a loopback
 * exact-origin Host/Origin pair, the trusted bound-origin header a real
 * launch path (packaged launcher or Vite dev middleware) injects, and the
 * current admission grant. The URL must carry an explicit port, exactly like
 * the real launch paths.
 */
export function testRequest(url: string, init?: RequestInit): Request {
	const parsed = new URL(url);
	const headers = new Headers(init?.headers);
	headers.set("host", parsed.host);
	if (!headers.has("origin")) headers.set("origin", parsed.origin);
	headers.set("authorization", `Bearer ${currentGrant()}`);
	if (!headers.has("x-fleet-bound-origin")) headers.set("x-fleet-bound-origin", parsed.origin);
	const method = init?.method ?? "GET";
	const mutating = method !== "GET" && method !== "HEAD";
	if (mutating) {
		if (!headers.has("x-fleet-protocol")) headers.set("x-fleet-protocol", "2");
		// FormData bodies pick up their multipart content type from the body itself.
		if (typeof init?.body === "string" && !headers.has("content-type")) {
			headers.set("content-type", "application/json");
		}
	}
	return new Request(url, { ...init, headers });
}
