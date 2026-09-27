import { NETWORK_DISCONNECTED_MESSAGE } from "@prime-agent/web-protocol/chat-protocol";
import { describe, expect, it } from "vitest";
import { z } from "zod/v4";
import { mintBootstrapGrant } from "../request-policy";
import { chatErrorEnvelope, isDaemonDisconnectError, wrapApiHandler } from "../wrap-api-handler";

const DAEMON_DISCONNECT_ERROR = new Error(
	'Cannot send daemon command "get_messages" because the Prime Agent daemon is not connected. Socket: /tmp/prime.sock Daemon log: /Users/example/prime.log',
);

/** A request that passes request-boundary admission (loopback exact-origin + current grant). */
function admittedRequest(): Request {
	const { grant } = mintBootstrapGrant();
	return new Request("http://127.0.0.1:3000/api/health", {
		method: "GET",
		headers: {
			host: "127.0.0.1:3000",
			origin: "http://127.0.0.1:3000",
			authorization: `Bearer ${grant}`,
			"x-fleet-bound-origin": "http://127.0.0.1:3000",
		},
	});
}

describe("wrapApiHandler", () => {
	it("maps daemon transport failures to the typed NETWORK_DISCONNECTED envelope", async () => {
		const response = await wrapApiHandler(admittedRequest(), async () => {
			throw DAEMON_DISCONNECT_ERROR;
		});

		expect(response.status).toBe(500);
		const body = (await response.json()) as Record<string, unknown>;
		expect(body.code).toBe("NETWORK_DISCONNECTED");
		expect(body.message).toBe(NETWORK_DISCONNECTED_MESSAGE);
		expect(body.remediation).toEqual({ action: "reconnect", label: "Reconnect runtime" });
		expect(JSON.stringify(body)).not.toContain("/tmp/prime.sock");
		expect(JSON.stringify(body)).not.toContain("/Users/example");
	});

	it("maps unexpected failures to INTERNAL_ERROR without echoing detail", async () => {
		const response = await wrapApiHandler(admittedRequest(), async () => {
			throw new Error("Failed to read /Users/example/secret.json");
		});

		expect(response.status).toBe(500);
		const body = (await response.json()) as { error: { code: string; message: string; requestId: string } };
		expect(body.error.code).toBe("INTERNAL_ERROR");
		expect(body.error.message).toBe("Internal server error");
		expect(typeof body.error.requestId).toBe("string");
		expect(JSON.stringify(body)).not.toContain("/Users/example");
		expect(JSON.stringify(body)).not.toContain("secret.json");
	});

	it("maps schema failures to 400 INVALID_REQUEST with field issues, never values", async () => {
		const response = await wrapApiHandler(admittedRequest(), async () => {
			z.object({ sessionId: z.uuid() }).parse({ sessionId: "attacker-controlled-not-a-uuid" });
			return Response.json({ ok: true });
		});

		expect(response.status).toBe(400);
		const body = (await response.json()) as {
			error: { code: string; fields?: Array<{ path: string; code: string }> };
		};
		expect(body.error.code).toBe("INVALID_REQUEST");
		expect(body.error.fields?.some((field) => field.path === "sessionId")).toBe(true);
		expect(JSON.stringify(body)).not.toContain("attacker-controlled");
	});

	it("preserves handler-declared status codes", async () => {
		const response = await wrapApiHandler(admittedRequest(), async () => {
			throw Object.assign(new Error("Session belongs to another user"), { status: 403 });
		});

		expect(response.status).toBe(403);
	});

	it("rejects cross-origin requests before the handler runs", async () => {
		const { grant } = mintBootstrapGrant();
		const request = new Request("http://127.0.0.1:3000/api/chat/new", {
			method: "POST",
			headers: {
				host: "127.0.0.1:3000",
				origin: "http://127.0.0.1:9999",
				authorization: `Bearer ${grant}`,
				"x-fleet-protocol": "2",
				"content-type": "application/json",
				"x-fleet-bound-origin": "http://127.0.0.1:3000",
			},
			body: "{}",
		});
		let handlerRan = false;
		const response = await wrapApiHandler(request, async () => {
			handlerRan = true;
			return Response.json({});
		});

		expect(response.status).toBe(403);
		const body = (await response.json()) as { error: { code: string } };
		expect(body.error.code).toBe("ORIGIN_DENIED");
		expect(handlerRan).toBe(false);
	});

	it("classifies daemon disconnects by message shape", () => {
		expect(isDaemonDisconnectError(DAEMON_DISCONNECT_ERROR)).toBe(true);
		expect(isDaemonDisconnectError(new Error("the Prime Agent daemon is not connected"))).toBe(true);
		expect(isDaemonDisconnectError(new Error("Project no longer exists"))).toBe(false);
		expect(chatErrorEnvelope(new Error("boom")).code).toBe("UNKNOWN_ERROR");
	});
});
