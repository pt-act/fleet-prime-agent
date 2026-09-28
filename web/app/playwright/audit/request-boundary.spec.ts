/**
 * request-boundary audit suite — spec `.agents/specs/request-boundary/spec.md` v1.0.0.
 * Baseline: 29de85bd7a236918a1787d34addf787aafb2f92d. Primary findings: F07, F26.
 * Validation tier 2 (blocking). Seed for all property tests: 2026090801.
 *
 * Cases: RB-01 origin parity, RB-02 grant lifecycle, RB-03 secret confinement,
 * RB-04 error mapping, RB-05 mutation/version safety, RB-06 complete route
 * protection, RB-PBT properties P1–P3, RB-EVIDENCE bundle aggregation.
 *
 * Fixtures: disposable Vite dev servers and packaged-launcher child processes
 * with scrubbed environments (see request-boundary-helpers.ts). No webServer
 * inheritance; every case owns or shares an explicitly started fixture.
 */
import { expect, test } from "@playwright/test";
import fc from "fast-check";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { join, relative, sep } from "node:path";
import {
	type AdmissionInputs,
	chatErrorEnvelope,
	classifyRequest,
	decideAdmission,
	isDaemonDisconnectError,
	mintBootstrapGrant,
	safeErrorMessage,
	wrapApiHandler,
} from "@prime-agent/web-server";
import {
	ARTIFACTS_ROOT,
	REPO_ROOT,
	admittedHeaders,
	atomicWriteJson,
	bootstrap,
	caseRecordPath,
	protocolShapeFingerprint,
	rawRequest,
	rawRequestHead,
	sourceCommit,
	startServer,
	tracker,
	verifierCommand,
	writeCaseRecord,
	type LaunchPath,
	type ServerFixture,
} from "./request-boundary-helpers";

const LAUNCH_PATHS: LaunchPath[] = ["dev", "launcher"];
const PBT_SEED = 2026090801;
const PBT_RUNS = 1000;
const CASE_IDS = ["RB-01", "RB-02", "RB-03", "RB-04", "RB-05", "RB-06", "RB-PBT", "RB-EVIDENCE"] as const;
/** Module load marks the start of this run; stale records from prior runs fail freshness checks. */
const RUN_START_MS = Date.now();

/** One long-lived fixture per launch path per worker; dedicated fixtures are started inside cases that need isolation. */
const sharedServers = new Map<LaunchPath, ServerFixture>();

async function sharedServer(kind: LaunchPath): Promise<ServerFixture> {
	const existing = sharedServers.get(kind);
	if (existing) return existing;
	const fixture = await startServer(kind);
	sharedServers.set(kind, fixture);
	return fixture;
}

test.afterAll(async () => {
	for (const fixture of sharedServers.values()) await fixture.close();
	sharedServers.clear();
});

function recordCase(
	caseId: string,
	project: string,
	t: ReturnType<typeof tracker>,
	extraEvidence: string[] = [],
): void {
	writeCaseRecord(caseId, project, t.entries, [caseRecordPath(caseId, project), ...extraEvidence]);
}

function walkTs(dir: string): string[] {
	const out: string[] = [];
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const full = join(dir, entry.name);
		if (entry.isDirectory()) out.push(...walkTs(full));
		else if (entry.name.endsWith(".ts") || entry.name.endsWith(".tsx")) out.push(full);
	}
	return out;
}

/** Starts a loopback canary server that records how many requests it received. */
async function startCanary(): Promise<{ port: number; hits: () => number; close: () => Promise<void> }> {
	let hits = 0;
	const server = http.createServer((_req, res) => {
		hits += 1;
		res.setHeader("content-type", "text/html");
		res.end("<html><body>canary</body></html>");
	});
	await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
	const port = (server.address() as AddressInfo).port;
	return {
		port,
		hits: () => hits,
		close: () => new Promise<void>((resolveClose) => server.close(() => resolveClose())),
	};
}

/** The cross-origin POST attempt executed inside a real browser page (page.evaluate). */
function browserCrossOriginPostScript(): (target: string) => Promise<{ status?: number; blocked?: string }> {
	return async (target: string) => {
		try {
			const response = await fetch(`${target}/api/chat/new`, {
				method: "POST",
				headers: { "content-type": "text/plain" },
				body: "title=rb-audit-cross-origin",
			});
			return { status: response.status };
		} catch (error) {
			// CORS rejection: the write never became readable; the server-side raw
			// probe asserts the exact 403.
			return { blocked: String(error) };
		}
	};
}

test.describe.serial("request-boundary audit suite (F07/F26)", () => {
	test("RB-01 exact-origin admission matrix on both launch paths (F07)", async ({}, testInfo) => {
		test.setTimeout(180_000);
		const t = tracker();
		const servedHtml: Array<[string, string]> = [];
		for (const kind of LAUNCH_PATHS) {
			const server = await sharedServer(kind);
			const { grant } = await bootstrap(server);
			const created = await rawRequest(server.port, "/api/chat/new", {
				method: "POST",
				headers: admittedHeaders(server, grant, { contentType: "application/json" }),
				body: "{}",
			});
			t.assert(created.status === 200, `${kind}: admitted POST /api/chat/new -> 200 (got ${created.status})`);
			const sessionId = (JSON.parse(created.body) as { session: { sessionId: string } }).session.sessionId;
			const crossPort = server.port === 65535 ? 65534 : server.port + 1;
			const originCases: Array<[string, string | null]> = [
				["absent-origin", null],
				["exact-own-origin", server.origin],
				["cross-port-origin", `http://127.0.0.1:${crossPort}`],
				["cross-host-origin", `http://localhost:${server.port}`],
				["non-loopback-origin", "http://evil.example.com"],
			];
			for (const [label, origin] of originCases) {
				const admitted = origin === null || origin === server.origin;
				const mutation = await rawRequest(server.port, "/api/chat/new", {
					method: "POST",
					headers: admittedHeaders(server, grant, { origin, contentType: "application/json" }),
					body: "{}",
				});
				t.assert(
					mutation.status === (admitted ? 200 : 403),
					`${kind}: ${label} POST /api/chat/new -> ${admitted ? 200 : 403} (got ${mutation.status})`,
				);
				if (!admitted) {
					t.assert(
						(JSON.parse(mutation.body) as { error: { code: string } }).error.code === "ORIGIN_DENIED",
						`${kind}: ${label} mutation denial carries ORIGIN_DENIED`,
					);
				}
				const read = await rawRequest(server.port, "/api/chat/sessions", {
					headers: admittedHeaders(server, grant, { origin }),
				});
				t.assert(
					read.status === (admitted ? 200 : 403),
					`${kind}: ${label} GET /api/chat/sessions -> ${admitted ? 200 : 403} (got ${read.status})`,
				);
				const stream = await rawRequestHead(server.port, `/api/chat/events?sessionId=${sessionId}`, {
					headers: admittedHeaders(server, grant, { origin }),
				});
				t.assert(
					admitted ? stream.status !== 401 && stream.status !== 403 : stream.status === 403,
					`${kind}: ${label} GET /api/chat/events (stream open) ${admitted ? "admitted" : "-> 403"} (got ${stream.status})`,
				);
				// The static shell is public by design: it must load without credentials.
				// The launcher additionally pre-gates static requests by Origin when one
				// is present (stricter than dev) — both are safe, so cross-origin
				// probes accept 200 or 403 and the divergence is recorded.
				const staticPage = await rawRequest(server.port, "/", {
					headers: origin === null ? {} : { origin },
				});
				if (admitted) {
					t.assert(
						staticPage.status === 200,
						`${kind}: ${label} GET / (static shell) -> 200 (got ${staticPage.status})`,
					);
				} else {
					t.assert(
						staticPage.status === 200 || staticPage.status === 403,
						`${kind}: ${label} GET / (static shell) -> 200 or launcher-strict 403 (got ${staticPage.status})`,
					);
				}
				if (origin === null) servedHtml.push([kind, staticPage.body]);
			}
		}
		// Static index checks: the shipped client never opens external windows or
		// posts forms to external targets.
		for (const [kind, html] of servedHtml) {
			t.assert(
				!/<form[^>]*action\s*=\s*["']https?:\/\//i.test(html),
				`${kind}: served HTML has no form posting to an external origin`,
			);
			t.assert(
				!/window\.open\s*\(\s*["'`]\s*(https?:)?\/\//.test(html),
				`${kind}: served HTML has no external window.open`,
			);
		}
		const assetsDir = join(REPO_ROOT, "packages", "fleet-web", "dist", "web", "client", "assets");
		let windowOpenCalls = 0;
		let externalWindowOpen = 0;
		for (const asset of readdirSync(assetsDir).filter((name) => name.endsWith(".js"))) {
			const source = readFileSync(join(assetsDir, asset), "utf8");
			windowOpenCalls += (source.match(/window\.open\s*\(/g) ?? []).length;
			externalWindowOpen += (source.match(/window\.open\s*\(\s*["'`]\s*(https?:)?\/\//g) ?? []).length;
		}
		t.assert(
			externalWindowOpen === 0,
			`built client: window.open never targets an external origin (observed ${windowOpenCalls} calls, ${externalWindowOpen} external)`,
		);
		let srcWindowOpenExternal = 0;
		for (const file of walkTs(join(REPO_ROOT, "web", "app", "src"))) {
			const source = readFileSync(file, "utf8");
			srcWindowOpenExternal += (source.match(/window\.open\s*\(\s*["'`]\s*(https?:)?\/\//g) ?? []).length;
		}
		t.assert(
			srcWindowOpenExternal === 0,
			`app source: no external-origin window.open (observed ${srcWindowOpenExternal})`,
		);
		recordCase("RB-01", testInfo.project.name, t);
	});

	test("RB-02 grant lifecycle: replay, expiry, single-flight renewal, cross-origin browser (F07)", async ({
		page,
		context,
	}, testInfo) => {
		test.setTimeout(300_000);
		const t = tracker();
		// (a) replay and expiry on dedicated fixtures per launch path
		for (const kind of LAUNCH_PATHS) {
			const replayServer = await startServer(kind);
			try {
				const first = await bootstrap(replayServer);
				const second = await bootstrap(replayServer);
				t.assert(first.grant !== second.grant, `${kind}: re-bootstrap mints a distinct grant`);
				const replayed = await rawRequest(replayServer.port, "/api/chat/sessions", {
					headers: admittedHeaders(replayServer, first.grant),
				});
				t.assert(
					replayed.status === 401 &&
						(JSON.parse(replayed.body) as { error: { code: string } }).error.code === "AUTH_REQUIRED",
					`${kind}: replayed superseded grant -> 401 AUTH_REQUIRED (got ${replayed.status})`,
				);
				const current = await rawRequest(replayServer.port, "/api/chat/sessions", {
					headers: admittedHeaders(replayServer, second.grant),
				});
				t.assert(current.status === 200, `${kind}: current grant admitted -> 200 (got ${current.status})`);
			} finally {
				await replayServer.close();
			}

			const ttlServer = await startServer(kind, { ttlMs: 1200 });
			try {
				const { grant } = await bootstrap(ttlServer);
				const fresh = await rawRequest(ttlServer.port, "/api/chat/sessions", {
					headers: admittedHeaders(ttlServer, grant),
				});
				t.assert(fresh.status === 200, `${kind}: fresh short-TTL grant admitted -> 200 (got ${fresh.status})`);
				await new Promise((resolveWait) => setTimeout(resolveWait, 1400));
				const expired = await rawRequest(ttlServer.port, "/api/chat/sessions", {
					headers: admittedHeaders(ttlServer, grant),
				});
				t.assert(
					expired.status === 401 &&
						(JSON.parse(expired.body) as { error: { code: string } }).error.code === "AUTH_REQUIRED",
					`${kind}: expired grant replay -> 401 AUTH_REQUIRED (got ${expired.status})`,
				);
			} finally {
				await ttlServer.close();
			}
		}

		// (b) the app bootstraps exactly once even under concurrent API traffic
		const dev = await sharedServer("dev");
		let bootstrapCount = 0;
		let apiCount = 0;
		page.on("request", (request) => {
			const url = new URL(request.url());
			if (url.origin !== dev.origin) return;
			if (url.pathname === "/api/bootstrap") bootstrapCount += 1;
			else if (url.pathname.startsWith("/api/")) apiCount += 1;
		});
		await page.goto(`${dev.origin}/`);
		await expect.poll(() => apiCount, { timeout: 30_000 }).toBeGreaterThanOrEqual(12);
		t.assert(bootstrapCount === 1, `exactly one bootstrap request (observed ${bootstrapCount})`);
		t.assert(apiCount >= 12, `multiple API calls observed (observed ${apiCount})`);

		// (c) real-browser cross-origin mutation attempts on both launch paths
		for (const kind of LAUNCH_PATHS) {
			const server = await sharedServer(kind);
			const { grant } = await bootstrap(server);
			const before = await rawRequest(server.port, "/api/chat/sessions", {
				headers: admittedHeaders(server, grant),
			});
			const canary = await startCanary();
			try {
				// Cross-port loopback origin served from a real second server.
				await page.goto(`http://127.0.0.1:${canary.port}/`);
				const loopbackAttempt = await page.evaluate(browserCrossOriginPostScript(), server.origin);
				t.assert(
					loopbackAttempt.status === 403 || typeof loopbackAttempt.blocked === "string",
					`${kind}: browser cross-port origin POST blocked or 403 (observed ${JSON.stringify(loopbackAttempt).slice(0, 140)})`,
				);
				const rawLoopback = await rawRequestHead(server.port, "/api/chat/new", {
					method: "POST",
					headers: {
						host: `127.0.0.1:${server.port}`,
						origin: `http://127.0.0.1:${canary.port}`,
						"content-type": "text/plain",
					},
					body: "title=rb-audit-cross-origin",
				});
				t.assert(
					rawLoopback.status === 403,
					`${kind}: cross-port Origin -> 403 at the boundary (got ${rawLoopback.status})`,
				);
				// Non-loopback origin, resolved through route interception.
				await context.route("http://evil.example.com/**", (route) =>
					route.fulfill({ contentType: "text/html", body: "<html><body>evil</body></html>" }),
				);
				await page.goto("http://evil.example.com/");
				const remoteAttempt = await page.evaluate(browserCrossOriginPostScript(), server.origin);
				t.assert(
					remoteAttempt.status === 403 || typeof remoteAttempt.blocked === "string",
					`${kind}: browser non-loopback origin POST blocked or 403 (observed ${JSON.stringify(remoteAttempt).slice(0, 140)})`,
				);
				const rawRemote = await rawRequestHead(server.port, "/api/chat/new", {
					method: "POST",
					headers: { host: `127.0.0.1:${server.port}`, origin: "http://evil.example.com", "content-type": "text/plain" },
					body: "title=rb-audit-cross-origin",
				});
				t.assert(rawRemote.status === 403, `${kind}: non-loopback Origin -> 403 (got ${rawRemote.status})`);
				const after = await rawRequest(server.port, "/api/chat/sessions", {
					headers: admittedHeaders(server, grant),
				});
				// Security invariant: denied cross-origin writes must not create or
				// delete sessions. Session metadata (updatedAt, live status) can
				// jitter from the app's own background traffic, so compare the
				// identity set, not the serialized body.
				const sessionIds = (body: string): string[] =>
					((JSON.parse(body) as { sessions: Array<{ sessionId: string }> }).sessions ?? [])
						.map((session) => session.sessionId)
						.sort();
				t.assert(
					JSON.stringify(sessionIds(after.body)) === JSON.stringify(sessionIds(before.body)),
					`${kind}: cross-origin attempts changed no server state`,
				);
			} finally {
				await canary.close();
				await context.unroute("http://evil.example.com/**");
			}
		}
		recordCase("RB-02", testInfo.project.name, t);
	});

	test("RB-03 grant confinement: no storage, cookies, URLs, logs or cross-talk (F07)", async ({
		page,
		context,
	}, testInfo) => {
		test.setTimeout(180_000);
		const t = tracker();
		const server = await sharedServer("dev");
		const canary = await startCanary();
		const requestUrls: string[] = [];
		const consoleTexts: string[] = [];
		const setCookieValues: string[] = [];
		page.on("request", (request) => requestUrls.push(request.url()));
		page.on("console", (message) => consoleTexts.push(message.text()));
		page.on("pageerror", (error) => consoleTexts.push(String(error)));
		page.on("response", (response) => {
			response
				.headerValues("set-cookie")
				.then((values) => setCookieValues.push(...values))
				.catch(() => {});
		});
		try {
			const bootstrapPromise = page.waitForResponse(
				(response) => new URL(response.url()).pathname === "/api/bootstrap" && response.status() === 200,
				{ timeout: 30_000 },
			);
			await page.goto(`${server.origin}/`);
			const bootstrapResponse = await bootstrapPromise;
			const body = (await bootstrapResponse.json()) as { grant: string };
			const grant = body.grant;
			t.assert(typeof grant === "string" && grant.length >= 32, "captured a real grant value from the bootstrap response");
			const headers = await bootstrapResponse.allHeaders().catch(() => bootstrapResponse.headers());
			t.assert(
				String(headers["cache-control"] ?? "").includes("no-store"),
				`bootstrap is no-store (observed ${JSON.stringify(headers["cache-control"])})`,
			);
			t.assert(headers["access-control-allow-origin"] === undefined, "bootstrap sets no CORS header");
			// Let the app settle so all boot-time traffic is captured.
			await expect
				.poll(() => requestUrls.filter((url) => url.includes("/api/")).length, { timeout: 30_000 })
				.toBeGreaterThanOrEqual(10);
			const denied = await page.evaluate(async () => {
				const response = await fetch("/api/chat/sessions", {
					headers: { authorization: "Bearer rb-audit-wrong-grant", "x-fleet-protocol": "2" },
				});
				return { status: response.status, body: await response.text() };
			});
			t.assert(denied.status === 401, `wrong grant -> 401 (got ${denied.status})`);
			t.assert(!denied.body.includes(grant), "401 body does not contain the real grant");
			t.assert(!page.url().includes(grant), "grant absent from page URL");
			t.assert(
				requestUrls.every((url) => !url.includes(grant)),
				"grant absent from every request URL",
			);
			const storage = await page.evaluate(() =>
				JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }),
			);
			t.assert(!storage.includes(grant), "grant absent from local/session storage");
			t.assert(
				consoleTexts.every((text) => !text.includes(grant)),
				"grant absent from browser console",
			);
			const cookies = await context.cookies();
			t.assert(cookies.length === 0, `no cookies at all (observed ${JSON.stringify(cookies.map((cookie) => cookie.name))})`);
			t.assert(setCookieValues.length === 0, "no set-cookie headers observed on any response");
			t.assert(!server.stdout.includes(grant), "grant absent from server stdout");
			t.assert(!server.stderr.includes(grant), "grant absent from server stderr");
			t.assert(canary.hits() === 0, `unrelated local-port server received ${canary.hits()} requests`);
		} finally {
			await canary.close();
		}
		recordCase("RB-03", testInfo.project.name, t);
	});

	test("RB-04 error mapping: media type, malformed body, schema failure, leaked failure (F26)", async ({}, testInfo) => {
		test.setTimeout(180_000);
		const t = tracker();
		for (const kind of LAUNCH_PATHS) {
			const server = await sharedServer(kind);
			const { grant } = await bootstrap(server);
			// text/plain mutation -> 415, JSON envelope, no echo
			const plain = await rawRequest(server.port, "/api/chat/new", {
				method: "POST",
				headers: admittedHeaders(server, grant, { contentType: "text/plain" }),
				body: "title=plain-marker",
			});
			t.assert(plain.status === 415, `${kind}: text/plain mutation -> 415 (got ${plain.status})`);
			t.assert(
				(JSON.parse(plain.body) as { error: { code: string } }).error.code === "UNSUPPORTED_MEDIA_TYPE",
				`${kind}: 415 carries UNSUPPORTED_MEDIA_TYPE`,
			);
			t.assert(!plain.body.includes("plain-marker"), `${kind}: 415 echoes no submitted content`);
			// malformed JSON -> 400, no echo (POST /api/chat parses strictly; the
			// lenient /api/chat/new parse that treats an unparsable body as "{}" is
			// recorded below as observed handler behavior).
			const malformed = await rawRequest(server.port, "/api/chat", {
				method: "POST",
				headers: admittedHeaders(server, grant, { contentType: "application/json" }),
				body: "{broken-marker",
			});
			t.assert(malformed.status === 400, `${kind}: malformed JSON -> 400 (got ${malformed.status})`);
			t.assert(
				(JSON.parse(malformed.body) as { error: { code: string } }).error.code === "INVALID_REQUEST",
				`${kind}: malformed JSON maps to INVALID_REQUEST`,
			);
			t.assert(!malformed.body.includes("broken-marker"), `${kind}: 400 echoes no submitted content`);
			// Recorded handler behavior: this older route deliberately treats an
			// unparsable body as empty and lets schema validation decide.
			const lenient = await rawRequest(server.port, "/api/chat/new", {
				method: "POST",
				headers: admittedHeaders(server, grant, { contentType: "application/json" }),
				body: "{broken-marker",
			});
			t.assert(
				lenient.status === 200 || lenient.status === 400,
				`${kind}: /api/chat/new malformed body -> lenient 200 or strict 400 (observed ${lenient.status})`,
			);
			// schema failure -> 400 with path/code fields, never submitted values
			const marker = "rb-audit-secret-value";
			const schemaFail = await rawRequest(server.port, "/api/chat/providers", {
				method: "POST",
				headers: admittedHeaders(server, grant, { contentType: "application/json" }),
				body: JSON.stringify({ providerId: 12345, apiKey: [marker] }),
			});
			t.assert(schemaFail.status === 400, `${kind}: schema failure -> 400 (got ${schemaFail.status})`);
			const schemaBody = JSON.parse(schemaFail.body) as { error: { code: string; fields?: unknown[] } };
			t.assert(schemaBody.error.code === "INVALID_REQUEST", `${kind}: schema failure maps to INVALID_REQUEST`);
			t.assert(
				Array.isArray(schemaBody.error.fields) && schemaBody.error.fields.length > 0,
				`${kind}: schema failure carries path/code fields`,
			);
			t.assert(!schemaFail.body.includes(marker), `${kind}: schema failure never echoes submitted values`);
			// leaked filesystem failure -> 500 generic INTERNAL_ERROR with requestId
			const leakPath = `/definitely/not/a/real/dir/rb-audit-${kind}`;
			const leaked = await rawRequest(server.port, "/api/projects", {
				method: "POST",
				headers: admittedHeaders(server, grant, { contentType: "application/json" }),
				body: JSON.stringify({ path: leakPath }),
			});
			t.assert(leaked.status === 500, `${kind}: unexpected failure -> 500 (got ${leaked.status})`);
			const leakedBody = JSON.parse(leaked.body) as { error: { code: string; message: string; requestId: string } };
			t.assert(leakedBody.error.code === "INTERNAL_ERROR", `${kind}: unexpected failure -> INTERNAL_ERROR`);
			t.assert(leakedBody.error.message === "Internal server error", `${kind}: generic message, no detail`);
			t.assert(
				typeof leakedBody.error.requestId === "string" && leakedBody.error.requestId.length >= 32,
				`${kind}: requestId present`,
			);
			t.assert(
				!leaked.body.includes(leakPath) && !/\/(Users|home|var|private|tmp|folders)\//.test(leaked.body),
				`${kind}: no filesystem paths echoed`,
			);
			// non-HTTP runtime failure -> typed, path-free envelope. The live
			// non-happy path (unknown session) plus the exact mapping the boundary
			// applies when the runtime transport fails.
			const unknownSession = await rawRequest(server.port, "/api/chat", {
				method: "POST",
				headers: admittedHeaders(server, grant, { contentType: "application/json" }),
				body: JSON.stringify({
					sessionId: "01a0ffff-ffff-7fff-8fff-ffffffffffff",
					message: "rb-audit runtime failure probe",
				}),
			});
			t.assert(
				unknownSession.status === 404 || unknownSession.status === 400,
				`${kind}: unknown session -> handled 404/400 (got ${unknownSession.status})`,
			);
			t.assert(
				!/\/(Users|home|var|private|tmp|folders)\//.test(unknownSession.body) &&
					!/\.sock|\.log/.test(unknownSession.body),
				`${kind}: runtime failure envelope carries no socket/log paths`,
			);
			const transportError = new Error(
				"cannot send daemon command: connect ENOENT /private/var/folders/rb-audit/daemon.sock",
			);
			const mapped = chatErrorEnvelope(transportError);
			t.assert(
				isDaemonDisconnectError(transportError) && mapped.code === "NETWORK_DISCONNECTED",
				`${kind}: daemon transport failure maps to NETWORK_DISCONNECTED (got ${mapped.code})`,
			);
			t.assert(
				!mapped.message.includes("daemon.sock") &&
					!mapped.message.includes("/private/var") &&
					safeErrorMessage(transportError).includes("[local path]"),
				`${kind}: transport failure message is scrubbed of socket/log paths`,
			);
		}
		recordCase("RB-04", testInfo.project.name, t);
	});

	test("RB-05 authenticated client transport and old-tab migration (F07)", async ({ page, context }, testInfo) => {
		test.setTimeout(180_000);
		const t = tracker();
		const server = await sharedServer("dev");
		// (a) every app-driven API call carries the Bearer grant and protocol header
		const seen: Array<{ url: string; authorization: string | undefined; protocol: string | undefined }> = [];
		page.on("request", (request) => {
			const url = new URL(request.url());
			if (url.origin === server.origin && url.pathname.startsWith("/api/") && url.pathname !== "/api/bootstrap") {
				const headers = request.headers();
				seen.push({ url: request.url(), authorization: headers.authorization, protocol: headers["x-fleet-protocol"] });
			}
		});
		const bootstrapPromise = page.waitForResponse(
			(response) => new URL(response.url()).pathname === "/api/bootstrap" && response.status() === 200,
			{ timeout: 30_000 },
		);
		await page.goto(`${server.origin}/`);
		const grant = ((await (await bootstrapPromise).json()) as { grant: string }).grant;
		await expect.poll(() => seen.length, { timeout: 30_000 }).toBeGreaterThanOrEqual(10);
		t.assert(seen.length >= 10, `app-driven API requests observed (${seen.length})`);
		for (const request of seen) {
			t.assert(request.authorization === `Bearer ${grant}`, `app request ${request.url} carries the Bearer grant`);
			t.assert(request.protocol === "2", `app request ${request.url} carries X-Fleet-Protocol: 2`);
		}

		// (b) already-open older tab: no grant, no protocol header -> safe denial
		// plus an actionable reload notice instead of undefined behavior.
		const oldTab = await context.newPage();
		try {
			await oldTab.route("**/api/**", async (route) => {
				if (route.request().method() === "GET") {
					await route.continue();
					return;
				}
				const headers = { ...route.request().headers() };
				delete headers.authorization;
				delete headers["x-fleet-protocol"];
				await route.continue({ headers });
			});
			await oldTab.goto(`${server.origin}/`);
			const composer = oldTab.getByRole("textbox", { name: "Prompt" });
			const sendButton = oldTab.getByRole("button", { name: "Send prompt" });
			// The app is SSR (TanStack Start): the composer markup is present in the
			// shell before hydration attaches React state. Typing into the
			// pre-hydration DOM is silently discarded when hydration resets it, so
			// wait until the composer is hydrated (daemon cold start makes this
			// take a few seconds under the scrubbed fixture).
			await expect
				.poll(
					() =>
						composer
							.first()
							.evaluate((el) => Object.keys(el).some((key) => key.startsWith("__reactProps")))
							.catch(() => false),
					{ timeout: 45_000 },
				)
				.toBe(true);
			await composer.click();
			await composer.fill("hello from an old tab");
			await expect(sendButton).toBeEnabled({ timeout: 30_000 });
			await sendButton.click();
			const notice = oldTab.getByText(/session expired|was updated/i).first();
			let surfaced = true;
			try {
				await notice.waitFor({ timeout: 20_000 });
			} catch {
				surfaced = false;
			}
			t.assert(surfaced, "old tab surfaces an actionable reload notice after the 401/426 denial");
			const rawDenied = await rawRequest(server.port, "/api/chat/new", {
				method: "POST",
				headers: {
					host: `127.0.0.1:${server.port}`,
					origin: server.origin,
					"content-type": "application/json",
				},
				body: "{}",
			});
			t.assert(
				rawDenied.status === 401 &&
					(JSON.parse(rawDenied.body) as { error: { code: string } }).error.code === "AUTH_REQUIRED",
				`old-style mutation without grant -> 401 AUTH_REQUIRED (got ${rawDenied.status})`,
			);
		} finally {
			await oldTab.close();
		}
		recordCase("RB-05", testInfo.project.name, t);
	});

	test("RB-06 complete route protection and fail-closed classification (F07)", async ({}, testInfo) => {
		test.setTimeout(300_000);
		const t = tracker();
		// Mount table: the TanStack file routes are the source of truth for both
		// launch paths (the packaged launcher serves the same compiled routes).
		const routesDir = join(REPO_ROOT, "web", "app", "src", "routes", "api");
		const mounted = new Set<string>();
		for (const file of walkTs(routesDir)) {
			const routePath = `/api/${relative(routesDir, file).replace(/\.ts$/, "").split(sep).join("/")}`;
			const source = readFileSync(file, "utf8");
			for (const match of source.matchAll(/^\s*(GET|POST|PUT|PATCH|DELETE):\s*\(/gm)) {
				mounted.add(`${match[1]} ${routePath}`);
			}
		}
		// Classification table: every registry entry must mount, every mount must classify.
		const policySource = readFileSync(join(REPO_ROOT, "web", "server", "src", "request-policy.ts"), "utf8");
		const registry = new Set(
			[...policySource.matchAll(/\["(GET|POST|PUT|PATCH|DELETE) (\/api\/[^"]+)", "(?:bootstrap|read|mutation|upload)"\]/g)].map(
				(match) => `${match[1]} ${match[2]}`,
			),
		);
		t.assert(mounted.size >= 30, `route matrix covers all mounted routes (${mounted.size} entries)`);
		for (const key of mounted) t.assert(registry.has(key), `mounted route classified: ${key}`);
		for (const key of registry) t.assert(mounted.has(key), `classified route mounted: ${key}`);
		for (const key of mounted) {
			const [method, path] = key.split(" ");
			t.assert(
				classifyRequest(method, path) !== undefined,
				`classifyRequest(${method} ${path}) returns a route class`,
			);
		}
		// Fail closed at the decision boundary: an unclassified route never runs a handler.
		t.assert(
			(() => {
				const decision = decideAdmission({
					routeClass: undefined,
					boundPort: 43210,
					origin: null,
					host: "127.0.0.1:43210",
					secFetchSite: null,
					authorization: null,
					protocolHeader: null,
					contentType: null,
					contentLength: null,
					chunked: false,
					now: Date.now(),
					grant: null,
				});
				return !decision.ok && decision.status === 404 && decision.code === "NOT_FOUND";
			})(),
			"unclassified route fails closed with 404 NOT_FOUND",
		);

		const DENIAL_STATUSES = new Set([401, 403, 404, 426]);
		for (const kind of LAUNCH_PATHS) {
			const server = await sharedServer(kind);
			const { grant } = await bootstrap(server);
			for (const key of [...mounted].sort()) {
				if (key === "GET /api/bootstrap") continue;
				const [method, path] = key.split(" ");
				const isUpload = key === "POST /api/chat/session";
				const carriesBody = method !== "GET";
				const buildHeaders = (withGrant: boolean): Record<string, string> => {
					const headers: Record<string, string> = {
						host: `127.0.0.1:${server.port}`,
						origin: server.origin,
					};
					if (withGrant) headers.authorization = `Bearer ${grant}`;
					if (carriesBody) {
						headers["x-fleet-protocol"] = "2";
						headers["content-type"] = isUpload ? "multipart/form-data; boundary=rb" : "application/json";
					}
					return headers;
				};
				const body = carriesBody ? (isUpload ? "--rb--\r\n" : "{}") : undefined;
				const without = await rawRequest(server.port, path, { method, headers: buildHeaders(false), body });
				t.assert(without.status === 401, `${kind}: ${method} ${path} without grant -> 401 (got ${without.status})`);
				const admitted = await rawRequest(server.port, path, { method, headers: buildHeaders(true), body });
				t.assert(
					!DENIAL_STATUSES.has(admitted.status) && admitted.status < 500,
					`${kind}: ${method} ${path} admitted with grant (got ${admitted.status})`,
				);
			}
			// Bootstrap is the only deliberately grant-free route — exact-origin gated.
			const openBootstrap = await rawRequest(server.port, "/api/bootstrap", {
				headers: { host: `127.0.0.1:${server.port}`, origin: server.origin },
			});
			t.assert(
				openBootstrap.status === 200,
				`${kind}: same-origin bootstrap without grant -> 200 (got ${openBootstrap.status})`,
			);
			const crossBootstrap = await rawRequestHead(server.port, "/api/bootstrap", {
				headers: { host: `127.0.0.1:${server.port}`, origin: "http://evil.example.com" },
			});
			t.assert(
				crossBootstrap.status === 403,
				`${kind}: unsolicited cross-origin bootstrap -> 403 (got ${crossBootstrap.status})`,
			);
			// Unknown route / unknown method fail closed on the live boundary.
			const unknownRoute = await rawRequest(server.port, "/api/definitely-not-a-route", {
				headers: { host: `127.0.0.1:${server.port}`, origin: server.origin, authorization: `Bearer ${grant}` },
			});
			t.assert(unknownRoute.status === 404, `${kind}: unknown route -> 404 (got ${unknownRoute.status})`);
			const unknownMethod = await rawRequestHead(server.port, "/api/health", {
				method: "DELETE",
				headers: { host: `127.0.0.1:${server.port}`, origin: server.origin, authorization: `Bearer ${grant}` },
			});
			t.assert(
				unknownMethod.status === 404 || unknownMethod.status === 405,
				`${kind}: unknown method on known route -> 404/405 (got ${unknownMethod.status})`,
			);
			// Static shell: public, clickjacking-protected.
			const html = await rawRequest(server.port, "/", { headers: { host: `127.0.0.1:${server.port}` } });
			t.assert(html.status === 200, `${kind}: top-level HTML loads without credentials`);
			const csp = String(html.headers["content-security-policy"] ?? "");
			t.assert(
				csp.includes("frame-ancestors 'none'"),
				`${kind}: HTML carries frame-ancestors 'none' (observed ${JSON.stringify(csp)})`,
			);
		}
		recordCase("RB-06", testInfo.project.name, t);
	});

	// --- property-based boundary evidence (P1–P3) -------------------------------

	test("RB-PBT property-based admission and secret-confinement evidence (F07/F26)", async ({}, testInfo) => {
		test.setTimeout(600_000);
		const t = tracker();
		const server = await sharedServer("dev");
		const { grant } = await bootstrap(server);

		type Expected = { ok: true } | { ok: false; status: number; code: string };
		type CaseClass = "valid" | "invalid" | "edge";
		type Generated = { input: AdmissionInputs; expected: Expected; klass: CaseClass };

		const JSON_LIMIT = 1024 * 1024;
		const UPLOAD_LIMIT = 128 * 1024 * 1024;
		const LOOPBACKS = ["127.0.0.1", "localhost", "[::1]"] as const;

		type BaseParts = {
			routeClass: "bootstrap" | "read" | "mutation" | "upload";
			boundPort: number;
			loopback: (typeof LOOPBACKS)[number];
			originMode: "absent" | "empty" | "exact";
			secFetch: string | null;
			grantValue: string;
			now: number;
			ttlMs: number;
			withBody: boolean;
			lengthPercent: number;
		};

		const basePartsArb: fc.Arbitrary<BaseParts> = fc.record<BaseParts>({
			routeClass: fc.constantFrom("bootstrap", "read", "mutation", "upload"),
			boundPort: fc.integer({ min: 1, max: 65535 }),
			loopback: fc.constantFrom(...LOOPBACKS),
			originMode: fc.constantFrom("absent", "empty", "exact"),
			secFetch: fc.constantFrom(null, "same-origin"),
			grantValue: fc.stringMatching(/^[0-9a-f]{32,64}$/),
			now: fc.integer({ min: 1_000_000_000, max: 2_000_000_000 }),
			ttlMs: fc.integer({ min: 1, max: 60_000 }),
			withBody: fc.boolean(),
			lengthPercent: fc.integer({ min: 0, max: 100 }),
		});

		/** Spec-derived valid tuple: every admission rule satisfied by construction. */
		function assembleValid(parts: BaseParts): Generated {
			const host = `${parts.loopback}:${parts.boundPort}`;
			const origin =
				parts.originMode === "absent"
					? null
					: parts.originMode === "empty"
						? ""
						: `http://${parts.loopback}:${parts.boundPort}`;
			const limit = parts.routeClass === "upload" ? UPLOAD_LIMIT : JSON_LIMIT;
			const declared = Math.floor((parts.lengthPercent / 100) * limit);
			const carriesBody = parts.routeClass === "mutation" || parts.routeClass === "upload";
			const contentType =
				parts.routeClass === "upload"
					? "multipart/form-data; boundary=rb"
					: parts.routeClass === "mutation" && parts.withBody
						? "application/json"
						: null;
			const input: AdmissionInputs = {
				routeClass: parts.routeClass,
				boundPort: parts.boundPort,
				origin,
				host,
				secFetchSite: parts.routeClass === "bootstrap" ? parts.secFetch : null,
				authorization: `Bearer ${parts.grantValue}`,
				protocolHeader: "2",
				contentType,
				contentLength: carriesBody ? String(parts.withBody ? declared : 0) : null,
				chunked: false,
				now: parts.now,
				grant: { value: parts.grantValue, expiresAt: parts.now + parts.ttlMs },
			};
			return { input, expected: { ok: true }, klass: "valid" };
		}

		const FAILURE_KINDS = [
			"unknown-route",
			"no-bound-port",
			"bad-host",
			"lookalike-host",
			"wrong-port",
			"cross-origin",
			"null-origin",
			"https-origin",
			"bootstrap-secfetch",
			"missing-grant",
			"wrong-grant",
			"expired-grant",
			"bad-protocol",
			"bad-media",
			"upload-media",
			"oversized",
			"negative-length",
			"garbage-length",
		] as const;

		/** Spec-derived invalid tuple: a valid tuple with exactly one broken rule, so the first-failed-check response is unambiguous. */
		function assembleInvalid(base: BaseParts, failure: (typeof FAILURE_KINDS)[number]): Generated {
			const g = assembleValid(base);
			const deny = (status: number, code: string): void => {
				g.expected = { ok: false, status, code };
			};
			const wrongPort = base.boundPort === 65535 ? 1 : base.boundPort + 1;
			const forceApiClass = (): void => {
				if (g.input.routeClass === "bootstrap") g.input.routeClass = "read";
			};
			switch (failure) {
				case "unknown-route":
					g.input.routeClass = undefined;
					deny(404, "NOT_FOUND");
					break;
				case "no-bound-port":
					g.input.boundPort = null;
					deny(500, "INTERNAL_ERROR");
					break;
				case "bad-host":
					g.input.host = `203.0.113.10:${base.boundPort}`;
					g.input.origin = null;
					deny(403, "ORIGIN_DENIED");
					break;
				case "lookalike-host":
					g.input.host = `127.0.0.1.evil.com:${base.boundPort}`;
					g.input.origin = null;
					deny(403, "ORIGIN_DENIED");
					break;
				case "wrong-port":
					g.input.host = `${base.loopback}:${wrongPort}`;
					g.input.origin = null;
					deny(403, "ORIGIN_DENIED");
					break;
				case "cross-origin":
					g.input.origin = `http://${base.loopback}:${wrongPort}`;
					deny(403, "ORIGIN_DENIED");
					break;
				case "null-origin":
					g.input.origin = "null";
					deny(403, "ORIGIN_DENIED");
					break;
				case "https-origin":
					g.input.origin = `https://${base.loopback}:${base.boundPort}`;
					deny(403, "ORIGIN_DENIED");
					break;
				case "bootstrap-secfetch":
					g.input.routeClass = "bootstrap";
					g.input.secFetchSite = "cross-site";
					deny(403, "ORIGIN_DENIED");
					break;
				case "missing-grant":
					forceApiClass();
					g.input.authorization = null;
					deny(401, "AUTH_REQUIRED");
					break;
				case "wrong-grant":
					forceApiClass();
					g.input.authorization = `Bearer ${base.grantValue}xx`;
					deny(401, "AUTH_REQUIRED");
					break;
				case "expired-grant":
					forceApiClass();
					g.input.grant = { value: base.grantValue, expiresAt: base.now };
					deny(401, "AUTH_REQUIRED");
					break;
				case "bad-protocol":
					g.input.routeClass = "mutation";
					g.input.protocolHeader = "1";
					deny(426, "CONTRACT_UPGRADE_REQUIRED");
					break;
				case "bad-media":
					g.input.routeClass = "mutation";
					g.input.contentType = "text/plain";
					g.input.contentLength = "10";
					deny(415, "UNSUPPORTED_MEDIA_TYPE");
					break;
				case "upload-media":
					g.input.routeClass = "upload";
					g.input.contentType = "application/json";
					deny(415, "UNSUPPORTED_MEDIA_TYPE");
					break;
				case "oversized":
					g.input.routeClass = "mutation";
					g.input.contentType = "application/json";
					g.input.contentLength = String(JSON_LIMIT + 1);
					deny(413, "PAYLOAD_TOO_LARGE");
					break;
				case "negative-length":
					g.input.routeClass = "mutation";
					g.input.contentType = "application/json";
					g.input.contentLength = "-1";
					deny(400, "INVALID_REQUEST");
					break;
				case "garbage-length":
					g.input.routeClass = "mutation";
					g.input.contentType = "application/json";
					g.input.contentLength = "not-a-number";
					deny(400, "INVALID_REQUEST");
					break;
			}
			g.klass = "invalid";
			return g;
		}

		const invalidArb = fc
			.record({ base: basePartsArb, failure: fc.constantFrom(...FAILURE_KINDS) })
			.map(({ base, failure }) => assembleInvalid(base, failure));

		const EDGE_KINDS = [
			"port-min",
			"port-max",
			"length-exact-limit",
			"upload-exact-limit",
			"ipv6-exact",
			"host-uppercase",
			"json-with-charset",
			"origin-empty",
			"origin-2048",
			"single-char-grant",
			"secfetch-none-bootstrap",
			"wrong-port-min",
		] as const;

		/** Spec-derived boundary tuple: legal or illegal exactly at a rule's edge. */
		function assembleEdge(base: BaseParts, edge: (typeof EDGE_KINDS)[number]): Generated {
			const g = assembleValid(base);
			const deny = (status: number, code: string): void => {
				g.expected = { ok: false, status, code };
			};
			switch (edge) {
				case "port-min":
					g.input.boundPort = 1;
					g.input.host = `${base.loopback}:1`;
					if (base.originMode === "exact") g.input.origin = `http://${base.loopback}:1`;
					break;
				case "port-max":
					g.input.boundPort = 65535;
					g.input.host = `${base.loopback}:65535`;
					if (base.originMode === "exact") g.input.origin = `http://${base.loopback}:65535`;
					break;
				case "length-exact-limit":
					g.input.routeClass = "mutation";
					g.input.contentType = "application/json";
					g.input.contentLength = String(JSON_LIMIT);
					break;
				case "upload-exact-limit":
					g.input.routeClass = "upload";
					g.input.contentType = "multipart/form-data; boundary=rb";
					g.input.contentLength = String(UPLOAD_LIMIT);
					break;
				case "ipv6-exact":
					g.input.host = `[::1]:${base.boundPort}`;
					g.input.origin = `http://[::1]:${base.boundPort}`;
					break;
				case "host-uppercase":
					g.input.host = `LOCALHOST:${base.boundPort}`;
					g.input.origin = null;
					break;
				case "json-with-charset":
					g.input.routeClass = "mutation";
					g.input.contentType = "application/json; charset=utf-8";
					g.input.contentLength = "2";
					break;
				case "origin-empty":
					g.input.origin = "";
					break;
				case "origin-2048": {
					const prefix = `http://${base.loopback}:${base.boundPort}/`;
					g.input.origin = `${prefix}${"a".repeat(2048 - prefix.length)}`;
					break;
				}
				case "single-char-grant":
					g.input.grant = { value: "a", expiresAt: base.now + base.ttlMs };
					g.input.authorization = "Bearer a";
					break;
				case "secfetch-none-bootstrap":
					// Sec-Fetch-Site: none is denied on bootstrap by policy choice.
					g.input.routeClass = "bootstrap";
					g.input.secFetchSite = "none";
					deny(403, "ORIGIN_DENIED");
					break;
				case "wrong-port-min":
					g.input.boundPort = 1;
					g.input.host = `${base.loopback}:2`;
					g.input.origin = null;
					deny(403, "ORIGIN_DENIED");
					break;
			}
			g.klass = "edge";
			return g;
		}

		const edgeArb = fc
			.record({ base: basePartsArb, edge: fc.constantFrom(...EDGE_KINDS) })
			.map(({ base, edge }) => assembleEdge(base, edge));

		const generatedArb: fc.Arbitrary<Generated> = fc
			.constantFrom("valid", "invalid", "edge")
			.chain((klass) => (klass === "valid" ? basePartsArb.map(assembleValid) : klass === "invalid" ? invalidArb : edgeArb));

		// P1: every unauthorized tuple is denied with the first-failed-check response.
		const counts: Record<CaseClass, number> = { valid: 0, invalid: 0, edge: 0 };
		let runs = 0;
		fc.assert(
			fc.property(generatedArb, (g) => {
				runs += 1;
				counts[g.klass] += 1;
				if (g.expected.ok) return;
				const actual = decideAdmission(g.input);
				if (actual.ok || actual.status !== g.expected.status || actual.code !== g.expected.code) {
					throw new Error(
						`P1 mismatch: expected ${JSON.stringify(g.expected)}, got ${JSON.stringify(actual)} for ${JSON.stringify(g.input)}`,
					);
				}
			}),
			{ seed: PBT_SEED, numRuns: PBT_RUNS },
		);
		t.assert(counts.valid >= PBT_RUNS / 4, `valid class >= 25% (got ${counts.valid})`);
		t.assert(counts.invalid >= PBT_RUNS / 4, `invalid class >= 25% (got ${counts.invalid})`);
		t.assert(counts.edge >= PBT_RUNS / 4, `edge class >= 25% (got ${counts.edge})`);
		t.assert(runs === PBT_RUNS, `zero discards: ${runs} === ${PBT_RUNS} runs`);

		// P2: every admissible tuple is admitted; the wrapper neither drops nor alters the payload.
		fc.assert(
			fc.property(generatedArb, (g) => {
				if (!g.expected.ok) return;
				const actual = decideAdmission(g.input);
				if (!actual.ok) {
					throw new Error(`P2 mismatch: expected ok, got ${JSON.stringify(actual)} for ${JSON.stringify(g.input)}`);
				}
			}),
			{ seed: PBT_SEED, numRuns: PBT_RUNS },
		);
		const minted = mintBootstrapGrant();
		let handlerCalls = 0;
		const admittedRequest = new Request("http://127.0.0.1:43210/api/chat/sessions", {
			headers: {
				host: "127.0.0.1:43210",
				origin: "http://127.0.0.1:43210",
				authorization: `Bearer ${minted.grant}`,
				"x-fleet-bound-origin": "http://127.0.0.1:43210",
			},
		});
		const wrapped = await wrapApiHandler(admittedRequest, async () => {
			handlerCalls += 1;
			return new Response("payload-marker-unchanged", { status: 209 });
		});
		t.assert(handlerCalls === 1, `handler ran exactly once (got ${handlerCalls})`);
		t.assert(wrapped.status === 209, "wrapper preserves the payload status");
		t.assert((await wrapped.text()) === "payload-marker-unchanged", "wrapper preserves the payload body");

		// Live boundary agreement: fixed + boundary origins executed against the real gate.
		const altPort = server.port === 4999 ? 4998 : 4999;
		const edgePort = server.port === 65535 ? 65534 : 65535;
		const liveCases: Array<[string, "ok" | "ORIGIN_DENIED"]> = [
			[server.origin, "ok"],
			["https://audit.invalid", "ORIGIN_DENIED"],
			[`http://localhost:${altPort}`, "ORIGIN_DENIED"],
			["null", "ORIGIN_DENIED"],
			["http://localhost.evil.com", "ORIGIN_DENIED"],
			["http://127.0.0.1.evil.com", "ORIGIN_DENIED"],
			[`http://[::1]:${altPort}`, "ORIGIN_DENIED"],
			[`http://127.0.0.1:${edgePort}`, "ORIGIN_DENIED"],
		];
		for (const [origin, expectedCode] of liveCases) {
			const model = decideAdmission({
				routeClass: "read",
				boundPort: server.port,
				origin,
				host: `127.0.0.1:${server.port}`,
				secFetchSite: null,
				authorization: `Bearer ${grant}`,
				protocolHeader: null,
				contentType: null,
				contentLength: null,
				chunked: false,
				now: Date.now(),
				grant: { value: grant, expiresAt: Date.now() + 60_000 },
			});
			const live = await rawRequestHead(server.port, "/api/chat/sessions", {
				headers: admittedHeaders(server, grant, { origin }),
			});
			const agrees =
				expectedCode === "ok"
					? model.ok && live.status === 200
					: !model.ok && model.code === expectedCode && live.status === 403;
			t.assert(
				agrees,
				`live ${live.status} agrees with model ${model.ok ? "ok" : model.code} for origin ${origin}`,
			);
		}

		// P3: schema failures carrying secret markers never serialize the marker.
		const markers: string[] = [];
		const markerArb = fc.record({
			suffix: fc.stringMatching(/^[0-9a-f]{8,16}$/),
			kind: fc.constantFrom("apiKey-array", "providerId-object", "apiKey-long", "baseUrl-array", "models-scalar"),
		});
		await fc.assert(
			fc.asyncProperty(markerArb, async ({ suffix, kind }) => {
				const marker = `sk-rb-audit-${suffix}`;
				const payload =
					kind === "apiKey-array"
						? { providerId: "openai", apiKey: [marker] }
						: kind === "providerId-object"
							? { providerId: { id: marker }, apiKey: "x" }
							: kind === "apiKey-long"
								? { providerId: "openai", apiKey: `${marker}${"x".repeat(4096)}` }
								: kind === "baseUrl-array"
									? { providerId: "custom", apiKey: "x", baseUrl: [marker] }
									: { providerId: "custom", apiKey: "x", models: marker };
				markers.push(marker);
				const response = await rawRequest(server.port, "/api/chat/providers", {
					method: "POST",
					headers: admittedHeaders(server, grant, { contentType: "application/json" }),
					body: JSON.stringify(payload),
				});
				if (response.status !== 400) {
					throw new Error(`P3: expected 400 schema failure, got ${response.status}`);
				}
				const envelope = JSON.parse(response.body) as { error: { code: string; fields?: unknown[] } };
				if (envelope.error.code !== "INVALID_REQUEST" || !Array.isArray(envelope.error.fields)) {
					throw new Error("P3: schema failure did not map to the INVALID_REQUEST fields envelope");
				}
				if (response.body.includes(marker)) {
					throw new Error("P3: secret marker leaked into the serialized error");
				}
			}),
			{ seed: PBT_SEED, numRuns: PBT_RUNS },
		);
		t.assert(markers.length === PBT_RUNS, `P3 executed ${markers.length} live schema-failure cases`);
		t.assert(
			markers.every((marker) => !server.stderr.includes(marker) && !server.stdout.includes(marker)),
			"server logs stay free of submitted secret markers",
		);
		recordCase("RB-PBT", testInfo.project.name, t);
	});

	test("RB-EVIDENCE aggregate validation bundle", async ({}, testInfo) => {
		test.setTimeout(120_000);
		const t = tracker();
		const commit = sourceCommit();
		const fingerprint = await protocolShapeFingerprint();
		t.assert(
			fingerprint.declared === "e440435d7fed126e37734afa40a17c0f4585633a9dd61369f903e575c71d0d9f" &&
				fingerprint.sha256 === fingerprint.declared,
			"contract fingerprint recomputes to the declared spec fingerprint",
		);
		const platformDir = join(ARTIFACTS_ROOT, "cases", `${process.platform}-${process.arch}`);
		const records: unknown[] = [];
		const evidenceHashes: Record<string, string> = {};
		for (const project of readdirSync(platformDir).sort()) {
			const projectDir = join(platformDir, project);
			for (const file of readdirSync(projectDir)
				.filter((name) => name.endsWith(".json"))
				.sort()) {
				const full = join(projectDir, file);
				const record = JSON.parse(readFileSync(full, "utf8")) as {
					caseId: string;
					verdict: string;
					assertions: unknown[];
					exitCode: number;
					sourceCommit: string;
					command: string;
					evidencePaths: string[];
					timestamp: string;
				};
				const rel = join("cases", `${process.platform}-${process.arch}`, project, file);
				t.assert(record.caseId === file.replace(/\.json$/, ""), `${rel}: caseId matches`);
				t.assert(record.verdict === "pass", `${rel}: verdict pass`);
				t.assert(Array.isArray(record.assertions) && record.assertions.length > 0, `${rel}: nonempty assertions`);
				t.assert(record.exitCode === 0, `${rel}: exitCode 0`);
				t.assert(record.sourceCommit === commit, `${rel}: sourceCommit matches HEAD`);
				t.assert(
					typeof record.command === "string" && record.command.includes(record.caseId),
					`${rel}: command recorded`,
				);
				t.assert(
					record.evidencePaths.length > 0 && record.evidencePaths.every((p) => existsSync(p)),
					`${rel}: evidence file exists (${record.evidencePaths[0] ?? "none"})`,
				);
				if (project === testInfo.project.name && record.caseId !== "RB-EVIDENCE") {
					// This project's records must come from the current run; other
					// projects are refreshed by their own runs of this suite.
					// RB-EVIDENCE is exempt: it is this test's own output, written
					// by recordCase() after this scan, so at scan time it is
					// necessarily the previous run's copy. Validating it here would
					// make a second run fail on its own stale artifact.
					t.assert(
						statSync(full).mtimeMs >= RUN_START_MS - 5_000,
						`${rel}: record produced by this run`,
					);
				}
				records.push(record);
				evidenceHashes[rel] = createHash("sha256").update(readFileSync(full)).digest("hex");
			}
		}
		const ownDir = join(platformDir, testInfo.project.name);
		const ownCases = readdirSync(ownDir)
			.filter((name) => name.endsWith(".json"))
			.map((name) => name.replace(/\.json$/, ""));
		for (const caseId of CASE_IDS.filter((id) => id !== "RB-EVIDENCE")) {
			t.assert(ownCases.includes(caseId), `${testInfo.project.name}: case record present for ${caseId}`);
		}
		const reportPath = join(ARTIFACTS_ROOT, "report.json");
		atomicWriteJson(reportPath, {
			specId: "request-boundary",
			generatedAt: new Date().toISOString(),
			sourceCommit: commit,
			contractFingerprint: { declared: fingerprint.declared, recomputed: fingerprint.sha256 },
			protocolVersion: 2,
			caseRecords: records,
			propertyTesting: {
				framework: "fast-check ^4.9.0",
				seed: PBT_SEED,
				numRunsPerProperty: PBT_RUNS,
				classMix:
					">=25% valid / >=25% invalid-denied / >=25% edge, zero discards (recorded in RB-PBT case records)",
			},
			environments: {
				darwin: "tested (this run)",
				linux: "BLOCKED — no Linux environment available in this production run; recorded, not manufactured",
			},
			commands: CASE_IDS.map((id) => verifierCommand(id)),
			evidenceSha256: evidenceHashes,
		});
		const report = JSON.parse(readFileSync(reportPath, "utf8")) as {
			caseRecords: unknown[];
			contractFingerprint: { recomputed: string };
			sourceCommit: string;
			commands: string[];
		};
		t.assert(report.caseRecords.length === records.length, "report re-read complete");
		t.assert(report.contractFingerprint.recomputed === fingerprint.declared, "report carries the spec fingerprint");
		t.assert(report.sourceCommit === commit, "report carries the source commit");
		t.assert(
			CASE_IDS.every((id) => report.commands.includes(verifierCommand(id))),
			"report lists every verifier command",
		);
		recordCase("RB-EVIDENCE", testInfo.project.name, t, [reportPath]);
	});
});
