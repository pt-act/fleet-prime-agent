import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import {
	closeSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	openSync,
	renameSync,
	writeSync,
} from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

/**
 * Shared fixtures for the request-boundary audit suite: disposable launch-path
 * servers (Vite dev + packaged launcher) with scrubbed environments, raw HTTP
 * requests with exact Host/Origin control, and the atomic evidence writer.
 */

export type LaunchPath = "dev" | "launcher";

export type ServerFixture = {
	kind: LaunchPath;
	origin: string;
	port: number;
	home: string;
	process: ChildProcess;
	stdout: string;
	stderr: string;
	close(): Promise<void>;
};

const REPO_ROOT = resolve(process.cwd(), "../..");
const WEB_APP_ROOT = join(REPO_ROOT, "web", "app");
const LAUNCHER_ENTRY = join(REPO_ROOT, "packages", "fleet-web", "dist", "web", "launcher.mjs");
// Spawn Vite directly: the pnpm shim bootstraps the pinned pnpm into each
// fixture's disposable HOME (slow, network-dependent, and fragile in scrubbed
// environments). The workspace-local vite binary has no such indirection.
const VITE_ENTRY = join(WEB_APP_ROOT, "node_modules", "vite", "bin", "vite.js");
export const ARTIFACTS_ROOT = join(REPO_ROOT, "artifacts", "audit-remediation", "request-boundary");

const SCRUB_PATTERN =
	/API_KEY|TOKEN|SECRET|CREDENTIAL|ANTHROPIC|OPENAI|GEMINI|GOOGLE_API|BEDROCK|AZURE|COHERE|MISTRAL|GROQ|XAI|_KEY$/i;

function disposableEnv(extra?: Record<string, string>): { env: NodeJS.ProcessEnv; home: string } {
	const home = mkdtempSync(join(tmpdir(), "rb-audit-home-"));
	const env: NodeJS.ProcessEnv = {};
	for (const [key, value] of Object.entries(process.env)) {
		if (value === undefined || SCRUB_PATTERN.test(key)) continue;
		env[key] = value;
	}
	env.HOME = home;
	env.XDG_CONFIG_HOME = join(home, ".config");
	env.XDG_CACHE_HOME = join(home, ".cache");
	env.XDG_DATA_HOME = join(home, ".local", "share");
	env.PRIME_AGENT_CODING_AGENT_DIR = mkdtempSync(join(tmpdir(), "rb-audit-agent-"));
	env.PRIME_AGENT_WORKSPACE_ROOT = mkdtempSync(join(tmpdir(), "rb-audit-workspace-"));
	for (const [key, value] of Object.entries(extra ?? {})) env[key] = value;
	return { env, home };
}

function waitFor(predicate: () => boolean | Promise<boolean>, timeoutMs: number, label: string): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	return new Promise((resolvePromise, rejectPromise) => {
		const tick = async () => {
			try {
				if (await predicate()) return resolvePromise();
			} catch {
				// A throwing predicate is just "not ready yet" until the deadline.
			}
			if (Date.now() > deadline) return rejectPromise(new Error(`timeout waiting for ${label}`));
			setTimeout(() => void tick(), 100);
		};
		void tick();
	});
}

export async function startServer(kind: LaunchPath, options?: { ttlMs?: number }): Promise<ServerFixture> {
	const extraEnv: Record<string, string> =
		kind === "dev" ? { VITE_FLEET_DISABLE_AGENTATION: "1" } : {};
	if (options?.ttlMs !== undefined) extraEnv.FLEET_REQUEST_POLICY_GRANT_TTL_MS = String(options.ttlMs);
	const { env, home } = disposableEnv(extraEnv);

	const command =
		kind === "dev"
			? { file: process.execPath, args: [VITE_ENTRY, "dev", "--port", "0", "--strictPort", "--host", "127.0.0.1"], cwd: WEB_APP_ROOT }
			: { file: process.execPath, args: [LAUNCHER_ENTRY, "--host", "127.0.0.1", "--port", "0"], cwd: REPO_ROOT };

	if (kind === "dev" && !existsSync(VITE_ENTRY)) {
		throw new Error(`Vite binary missing at ${VITE_ENTRY} — run pnpm install first`);
	}

	if (kind === "launcher" && !existsSync(LAUNCHER_ENTRY)) {
		throw new Error(`Packaged launcher missing at ${LAUNCHER_ENTRY} — run pnpm run build:web:release first`);
	}

	const child = spawn(command.file, command.args, { cwd: command.cwd, env, stdio: ["ignore", "pipe", "pipe"] });
	const fixture: ServerFixture = {
		kind,
		origin: "",
		port: 0,
		home,
		process: child,
		stdout: "",
		stderr: "",
		async close() {
			child.kill("SIGTERM");
			await new Promise<void>((resolveClose) => {
				const done = () => resolveClose();
				child.once("exit", done);
				setTimeout(() => {
					child.kill("SIGKILL");
					setTimeout(done, 500);
				}, 3000);
			});
			// Scratch dirs are intentionally NOT removed: the per-user prime-agent
			// daemon a fixture may have spawned keeps its supervisor registry under
			// this HOME, and deleting that registry wedges the daemon for every
			// later fixture ("registry entry is missing") until it is restarted.
			// The dirs are small temp files; the OS reclaims them.
		},
	};
	child.stdout?.on("data", (chunk: Buffer) => {
		fixture.stdout += chunk.toString();
	});
	child.stderr?.on("data", (chunk: Buffer) => {
		fixture.stderr += chunk.toString();
	});

	try {
		await waitFor(() => {
			// Strip ANSI: Vite colorizes the startup line when the parent process
			// advertises color support (e.g. FORCE_COLOR in Playwright workers).
			const match = fixture.stdout.replace(/\x1b\[[0-9;]*m/g, "").match(/http:\/\/127\.0\.0\.1:(\d+)/);
			if (!match) return false;
			fixture.port = Number(match[1]);
			fixture.origin = `http://127.0.0.1:${fixture.port}`;
			return true;
		}, 60_000, `${kind} server startup line`);
	} catch (error) {
		// A half-started fixture must not outlive the failure: orphaned servers
		// fight later fixtures over the per-user daemon socket/registry.
		child.kill("SIGKILL");
		// Diagnostics stay honest: surface exactly what the fixture emitted.
		throw new Error(
			`${error instanceof Error ? error.message : String(error)}\n--- ${kind} stdout tail ---\n${fixture.stdout.slice(-800)}\n--- ${kind} stderr tail ---\n${fixture.stderr.slice(-800)}`,
		);
	}

	await waitFor(() => {
		return new Promise<boolean>((resolveReady) => {
			const probe = http.get({ host: "127.0.0.1", port: fixture.port, path: "/" }, (res) => {
				res.resume();
				resolveReady(res.statusCode !== undefined && res.statusCode < 500);
			});
			probe.on("error", () => resolveReady(false));
		});
	}, 60_000, `${kind} server HTTP readiness`);

	return fixture;
}

// --- raw HTTP with exact header control -------------------------------------

export type RawResponse = { status: number; headers: http.IncomingHttpHeaders; body: string };

/**
 * Resolves as soon as response HEADERS arrive (status), then destroys the
 * socket. Required for routes whose body never ends (SSE) and for fast
 * admitted/denied status probes.
 */
export function rawRequestHead(
	port: number,
	path: string,
	options?: { method?: string; headers?: Record<string, string>; body?: string; timeoutMs?: number },
): Promise<{ status: number; headers: http.IncomingHttpHeaders }> {
	const timeoutMs = options?.timeoutMs ?? 15_000;
	return new Promise((resolvePromise, rejectPromise) => {
		const request = http.request(
			{
				host: "127.0.0.1",
				port,
				path,
				method: options?.method ?? "GET",
				headers: options?.headers ?? {},
				// Dedicated connections: a 413/403 whose body the server never read
				// poisons shared keep-alive sockets for subsequent requests.
				agent: false,
			},
			(response) => {
				const result = { status: response.statusCode ?? 0, headers: response.headers };
				request.destroy();
				resolvePromise(result);
			},
		);
		request.setTimeout(timeoutMs, () => {
			request.destroy(new Error(`rawRequestHead timeout after ${timeoutMs}ms: ${options?.method ?? "GET"} ${path}`));
		});
		request.on("error", (error) => {
			// Post-resolution destroys surface here; only fail if unresolved.
			rejectPromise(error);
		});
		if (options?.body !== undefined) request.write(options.body);
		request.end();
	});
}

export function rawRequest(
	port: number,
	path: string,
	options?: {
		method?: string;
		headers?: Record<string, string>;
		body?: string;
		responseTimeoutMs?: number;
	},
): Promise<RawResponse> {
	// 45 s covers the shared daemon's cold start: a request that first touches a
	// session may wait on daemon/kernel bring-up, which is not what these cases
	// measure (their 20 s/15 s budgets are for header-level probes only).
	const timeoutMs = options?.responseTimeoutMs ?? 45_000;
	return new Promise((resolvePromise, rejectPromise) => {
		const request = http.request(
			{
				host: "127.0.0.1",
				port,
				path,
				method: options?.method ?? "GET",
				headers: options?.headers ?? {},
				// Dedicated connections: a 413/403 whose body the server never read
				// poisons shared keep-alive sockets for subsequent requests.
				agent: false,
			},
			(response) => {
				let body = "";
				response.setEncoding("utf8");
				response.on("data", (chunk: string) => {
					body += chunk;
				});
				response.on("end", () => {
					resolvePromise({ status: response.statusCode ?? 0, headers: response.headers, body });
				});
			},
		);
		request.setTimeout(timeoutMs, () => {
			request.destroy(new Error(`rawRequest timeout after ${timeoutMs}ms: ${options?.method ?? "GET"} ${path}`));
		});
		request.on("error", rejectPromise);
		if (options?.body !== undefined) {
			// Node would otherwise send chunked framing; the boundary's transport
			// pre-check reads the declared length, so make it explicit.
			request.setHeader("content-length", String(Buffer.byteLength(options.body, "utf8")));
			request.write(options.body);
		}
		request.end();
	});
}

/**
 * Sends a POST whose declared Content-Length vastly exceeds the bytes actually
 * written, then stalls. Used to prove the 413 pre-check rejects on headers
 * alone, before the body is read.
 */
export function rawStalledUpload(
	port: number,
	path: string,
	headers: Record<string, string>,
	timeoutMs = 15_000,
): Promise<number> {
	return new Promise((resolvePromise, rejectPromise) => {
		const request = http.request(
			{
				host: "127.0.0.1",
				port,
				path,
				method: "POST",
				headers,
				// A prior request whose body the server rejected (413) poisons the
				// shared keep-alive socket; use a dedicated connection.
				agent: false,
			},
			(response) => {
				const status = response.statusCode ?? 0;
				response.resume();
				request.destroy();
				resolvePromise(status);
			},
		);
		request.setTimeout(timeoutMs, () => {
			request.destroy(new Error("stalled upload: no response within timeout"));
		});
		request.on("error", (error) => {
			// Destroy after resolution races an ECONNRESET; only reject pre-response failures.
			if (!request.destroyed || request.socket === null) rejectPromise(error);
			else resolvePromise(-1);
		});
		request.write("x".repeat(1024));
		// Intentionally never end() — the server must reject on headers alone.
	});
}

export type BootstrapResult = { protocolVersion: number; launchId: string; grant: string; expiresAt: string };

export async function bootstrap(server: ServerFixture): Promise<BootstrapResult> {
	const response = await rawRequest(server.port, "/api/bootstrap", {
		headers: { host: `127.0.0.1:${server.port}`, origin: server.origin },
	});
	if (response.status !== 200) {
		throw new Error(`bootstrap failed on ${server.kind}: ${response.status} ${response.body.slice(0, 200)}`);
	}
	return JSON.parse(response.body) as BootstrapResult;
}

/** Standard admission headers for an authenticated API call. */
export function admittedHeaders(
	server: ServerFixture,
	grant: string,
	options?: { origin?: string | null; protocol?: boolean; contentType?: string; contentLength?: number },
): Record<string, string> {
	const headers: Record<string, string> = {
		host: `127.0.0.1:${server.port}`,
		authorization: `Bearer ${grant}`,
	};
	if (options?.origin !== null) headers.origin = options?.origin ?? server.origin;
	if (options?.protocol !== false) headers["x-fleet-protocol"] = "2";
	if (options?.contentType) headers["content-type"] = options.contentType;
	if (options?.contentLength !== undefined) headers["content-length"] = String(options.contentLength);
	return headers;
}

// --- evidence ----------------------------------------------------------------

export type AssertionEntry = { observed: string; expected: string; pass: boolean };

export type CaseRecord = {
	caseId: string;
	verdict: "pass";
	assertions: AssertionEntry[];
	command: string;
	exitCode: 0;
	sourceCommit: string;
	environment: Record<string, string>;
	evidencePaths: string[];
	timestamp: string;
};

export function sourceCommit(): string {
	const result = spawnSync("git", ["rev-parse", "HEAD"], { cwd: REPO_ROOT, encoding: "utf8" });
	if (result.status !== 0) throw new Error(`git rev-parse HEAD failed: ${result.stderr}`);
	return result.stdout.trim();
}

export function verifierCommand(caseId: string): string {
	return `pnpm --filter @prime-agent/web exec playwright test --config=playwright/audit/request-boundary.config.ts --grep "(^| )${caseId}( |$)"`;
}

/** Atomic JSON write: serialize to a temp file in the same directory, then rename. */
export function atomicWriteJson(path: string, value: unknown): void {
	mkdirSync(join(path, ".."), { recursive: true });
	const tempPath = `${path}.tmp-${process.pid}-${Date.now()}`;
	const descriptor = openSync(tempPath, "w");
	try {
		writeSync(descriptor, `${JSON.stringify(value, null, "\t")}\n`);
	} finally {
		closeSync(descriptor);
	}
	renameSync(tempPath, path);
}

export function caseRecordPath(caseId: string, project: string): string {
	return join(ARTIFACTS_ROOT, "cases", `${process.platform}-${process.arch}`, project, `${caseId}.json`);
}

export function writeCaseRecord(
	caseId: string,
	project: string,
	assertions: AssertionEntry[],
	evidencePaths: string[],
): void {
	if (assertions.length === 0) throw new Error(`refusing to write an empty assertion list for ${caseId}`);
	atomicWriteJson(caseRecordPath(caseId, project), {
		caseId,
		verdict: "pass",
		assertions,
		command: verifierCommand(caseId),
		exitCode: 0,
		sourceCommit: sourceCommit(),
		environment: {
			platform: `${process.platform} ${process.arch}`,
			node: process.version,
			project,
			launchPaths: "dev+launcher",
		},
		evidencePaths,
		timestamp: new Date().toISOString(),
	} satisfies CaseRecord);
}

/** Assertion tracker: every entry is checked immediately; nothing is swallowed. */
export function tracker() {
	const assertions: AssertionEntry[] = [];
	return {
		assert(observed: unknown, expected: string): void {
			const pass = Boolean(observed);
			assertions.push({ observed: render(observed), expected, pass });
			if (!pass) throw new Error(`assertion failed — expected: ${expected}`);
		},
		entries: assertions,
	};
}

function render(value: unknown): string {
	if (typeof value === "string") return value.slice(0, 300);
	try {
		return JSON.stringify(value)?.slice(0, 300) ?? String(value);
	} catch {
		return String(value);
	}
}

/** Verifies the shipped shape constant against its declared fingerprint. */
export async function protocolShapeFingerprint(): Promise<{ shape: string; declared: string; sha256: string }> {
	const policy = await import("@prime-agent/web-protocol/request-policy");
	const sha256 = createHash("sha256").update(policy.REQUEST_POLICY_SHAPE, "utf8").digest("hex");
	return { shape: policy.REQUEST_POLICY_SHAPE, declared: policy.REQUEST_POLICY_FINGERPRINT, sha256 };
}

export { REPO_ROOT };
