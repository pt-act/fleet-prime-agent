import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * Request-boundary client transport tests: grant bootstrap is single-flight,
 * admission headers attach to every call, 401 renews once, 426 never retries,
 * and the fetch-based SSE parser handles the server's exact frame format.
 */

type FetchCall = { url: string; init: RequestInit };

function installFetch(handler: (call: FetchCall) => Response | Promise<Response>) {
	const calls: FetchCall[] = [];
	const mock = vi.fn(async (url: string, init?: RequestInit) => {
		calls.push({ url, init: init ?? {} });
		return handler({ url, init: init ?? {} });
	});
	vi.stubGlobal("fetch", mock);
	return { calls, mock };
}

function jsonResponse(status: number, body: unknown): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json" },
	});
}

const BOOTSTRAP = {
	protocolVersion: 2,
	launchId: "launch-1",
	grant: "grant-abc",
	expiresAt: new Date(Date.now() + 30 * 60_000).toISOString(),
};

afterEach(() => {
	vi.unstubAllGlobals();
	vi.resetModules();
});

describe("authorizedFetch request-boundary transport", () => {
	it("bootstraps once for concurrent calls (single-flight)", async () => {
		const { calls } = installFetch(({ url }) => {
			if (url.includes("/api/bootstrap")) return jsonResponse(200, BOOTSTRAP);
			return jsonResponse(200, { ok: true });
		});
		const { authorizedFetch } = await import("./chat-fetch");

		await Promise.all([
			authorizedFetch("/api/health"),
			authorizedFetch("/api/chat/sessions"),
			authorizedFetch("/api/chat/sessions"),
		]);

		const bootstraps = calls.filter((call) => call.url.includes("/api/bootstrap"));
		expect(bootstraps).toHaveLength(1);
		// Every API call after bootstrap carries the grant + protocol header.
		const apiCalls = calls.filter((call) => !call.url.includes("/api/bootstrap"));
		expect(apiCalls.length).toBeGreaterThanOrEqual(3);
		for (const call of apiCalls) {
			const headers = call.init.headers as Headers;
			expect(headers.get("authorization")).toBe("Bearer grant-abc");
			expect(headers.get("x-fleet-protocol")).toBe("2");
		}
	});

	it("retries exactly once on 401 after renewal", async () => {
		let grantValue = "grant-one";
		const { calls } = installFetch(({ url, init }) => {
			if (url.includes("/api/bootstrap")) {
				return jsonResponse(200, { ...BOOTSTRAP, grant: grantValue });
			}
			const headers = init.headers as Headers;
			if (headers.get("authorization") !== `Bearer ${grantValue}`) {
				return jsonResponse(401, {
					error: { code: "AUTH_REQUIRED", message: "expired", retryable: true, requestId: "r" },
				});
			}
			return jsonResponse(200, { ok: true });
		});
		const { authorizedFetch } = await import("./chat-fetch");

		const first = await authorizedFetch("/api/chat/sessions");
		expect(first.status).toBe(200);

		// Simulate server-side rotation: the old grant is no longer valid.
		grantValue = "grant-two";
		const second = await authorizedFetch("/api/chat/sessions");
		expect(second.status).toBe(200);

		// First call: 1 bootstrap + 1 API. Second call: 1 failed attempt +
		// 1 bootstrap + 1 retried attempt (no more).
		const apiAttempts = calls.filter((call) => call.url.includes("/api/chat/sessions"));
		const bootstraps = calls.filter((call) => call.url.includes("/api/bootstrap"));
		expect(apiAttempts).toHaveLength(3);
		expect(bootstraps).toHaveLength(2);
	});

	it("does not retry a 426 contract upgrade rejection", async () => {
		const { calls } = installFetch(({ url }) => {
			if (url.includes("/api/bootstrap")) return jsonResponse(200, BOOTSTRAP);
			return jsonResponse(426, {
				error: { code: "CONTRACT_UPGRADE_REQUIRED", message: "reload", retryable: false, requestId: "r" },
			});
		});
		const { authorizedFetch } = await import("./chat-fetch");

		const response = await authorizedFetch("/api/chat/new", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: "{}",
		});
		expect(response.status).toBe(426);
		const attempts = calls.filter((call) => call.url.includes("/api/chat/new"));
		expect(attempts).toHaveLength(1);
	});
});

describe("FetchEventSource SSE parsing", () => {
	it("parses id/data frames, ignores heartbeats, and reports stream end as error", async () => {
		const encoder = new TextEncoder();
		const stream = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(encoder.encode(": heartbeat\n\n"));
				controller.enqueue(encoder.encode('id: 7\nevent: message\ndata: {"type":"state"}\n\n'));
				controller.enqueue(encoder.encode('id: 8\ndata: {"type":"queue"}\n\n'));
				controller.close();
			},
		});
		installFetch(({ url }) => {
			if (url.includes("/api/bootstrap")) return jsonResponse(200, BOOTSTRAP);
			return new Response(stream, { status: 200, headers: { "content-type": "text/event-stream" } });
		});
		const { FetchEventSource } = await import("./chat-fetch");

		const messages: Array<{ data: string; lastEventId: string | null }> = [];
		let errored = false;
		const source = new FetchEventSource("/api/chat/events?sessionId=s1");
		source.onmessage = (event) => messages.push(event);
		source.onerror = () => {
			errored = true;
		};
		await new Promise((resolve) => setTimeout(resolve, 50));

		expect(messages).toHaveLength(2);
		expect(messages[0]?.lastEventId).toBe("7");
		expect(JSON.parse(messages[0]!.data).type).toBe("state");
		expect(messages[1]?.lastEventId).toBe("8");
		expect(errored).toBe(true);
		source.close();
	});
});
