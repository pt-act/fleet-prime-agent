#!/usr/bin/env node

import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, relative, resolve, sep } from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import webServer from "./server/server.js";

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 3000;
const MAX_PORT = 65535;
const clientRoot = resolve(fileURLToPath(new URL("./client/", import.meta.url)));

const options = parseArgs(process.argv.slice(2));
const httpServer = createServer((request, response) => {
	void handleRequest(request, response);
});

let shuttingDown = false;
let serverAddress = null;

httpServer.on("error", (error) => {
	if (!shuttingDown) {
		console.error(`Web server error: ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 1;
	}
});

await listen(httpServer, options.host, options.port);
const address = httpServer.address();
if (!address || typeof address === "string") {
	throw new Error("Web server did not report a TCP address");
}
serverAddress = address;
console.log(`Fleet Prime interface: http://${formatHost(address.address)}:${address.port}`);

const shutdown = (signal) => {
	if (shuttingDown) return;
	shuttingDown = true;
	process.exitCode = signal === "SIGINT" ? 130 : 143;
	httpServer.close(() => {
		process.exitCode = signal === "SIGINT" ? 130 : 143;
	});
	httpServer.closeIdleConnections?.();
};

process.once("SIGINT", () => shutdown("SIGINT"));
process.once("SIGTERM", () => shutdown("SIGTERM"));

async function handleRequest(request, response) {
	try {
		if (!isAllowedRequest(request)) {
			response.statusCode = 403;
			response.setHeader("content-type", "application/json; charset=utf-8");
			response.setHeader("cache-control", "no-store");
			response.end(
				JSON.stringify({
					error: {
						code: "ORIGIN_DENIED",
						message: "Same-origin loopback requests only",
						retryable: false,
						requestId: "launcher-gate",
					},
				}),
			);
			return;
		}
		const requestUrl = new URL(
			request.url || "/",
			`http://${request.headers.host || `${options.host}:${options.port}`}`,
		);
		const staticPath = resolveStaticPath(requestUrl.pathname);
		if (staticPath) {
			serveStaticFile(request, response, staticPath);
			return;
		}

		const headers = new Headers();
		for (const [name, value] of Object.entries(request.headers)) {
			if (Array.isArray(value)) {
				for (const item of value) headers.append(name, item);
			} else if (value !== undefined) {
				headers.set(name, value);
			}
		}

		// Trusted header: only this launcher may state the bound origin.
		// Any client-supplied value is dropped and overwritten.
		headers.delete(BOUND_ORIGIN_HEADER);
		if (serverAddress && typeof serverAddress === "object") {
			headers.set(BOUND_ORIGIN_HEADER, `http://${formatHost(serverAddress.address)}:${serverAddress.port}`);
		}

		const hasBody = request.method !== "GET" && request.method !== "HEAD";
		const webRequest = new Request(requestUrl, {
			method: request.method,
			headers,
			body: hasBody ? Readable.toWeb(request) : undefined,
			duplex: hasBody ? "half" : undefined,
		});
		const webResponse = await webServer.fetch(webRequest);

		response.statusCode = webResponse.status;
		const cookies = webResponse.headers.getSetCookie?.();
		for (const [name, value] of webResponse.headers) {
			if (name === "set-cookie") continue;
			response.setHeader(name, value);
		}
		const responseContentType = webResponse.headers.get("content-type");
		if (responseContentType && responseContentType.includes("text/html")) {
			response.setHeader("content-security-policy", "frame-ancestors 'none'");
		}
		if (cookies && cookies.length > 0) response.setHeader("set-cookie", cookies);

		if (!webResponse.body || request.method === "HEAD") {
			response.end();
			return;
		}
		Readable.fromWeb(webResponse.body).pipe(response);
	} catch (error) {
		if (response.headersSent) {
			response.destroy(error instanceof Error ? error : undefined);
			return;
		}
		response.statusCode = 500;
		response.setHeader("content-type", "text/plain; charset=utf-8");
		response.end("Internal server error");
		console.error(`Web request failed: ${error instanceof Error ? error.stack || error.message : String(error)}`);
	}
}

function resolveStaticPath(pathname) {
	let decodedPath;
	try {
		decodedPath = decodeURIComponent(pathname);
	} catch {
		return undefined;
	}
	const candidate = resolve(clientRoot, `.${decodedPath}`);
	const relativePath = relative(clientRoot, candidate);
	if (relativePath.startsWith(`..${sep}`) || relativePath === ".." || relativePath.includes(`${sep}..${sep}`)) {
		return undefined;
	}
	if (!existsSync(candidate) || !statSync(candidate).isFile()) return undefined;
	return candidate;
}

function serveStaticFile(request, response, filePath) {
	const stat = statSync(filePath);
	response.statusCode = 200;
	const staticType = contentType(filePath);
	response.setHeader("content-type", staticType);
	if (staticType.startsWith("text/html")) {
		response.setHeader("content-security-policy", "frame-ancestors 'none'");
	}
	response.setHeader("content-length", stat.size);
	if (request.method === "HEAD") {
		response.end();
		return;
	}
	createReadStream(filePath)
		.on("error", (error) => response.destroy(error))
		.pipe(response);
}

function contentType(filePath) {
	const types = {
		".css": "text/css; charset=utf-8",
		".gif": "image/gif",
		".html": "text/html; charset=utf-8",
		".ico": "image/x-icon",
		".jpeg": "image/jpeg",
		".jpg": "image/jpeg",
		".js": "text/javascript; charset=utf-8",
		".json": "application/json; charset=utf-8",
		".png": "image/png",
		".svg": "image/svg+xml",
		".txt": "text/plain; charset=utf-8",
		".webp": "image/webp",
		".woff": "font/woff",
		".woff2": "font/woff2",
	};
	return types[extname(filePath).toLowerCase()] || "application/octet-stream";
}

function parseArgs(args) {
	let host = DEFAULT_HOST;
	let port = DEFAULT_PORT;
	for (let index = 0; index < args.length; index += 1) {
		const arg = args[index];
		if (arg === "--host" || arg === "--port") {
			const value = args[index + 1];
			if (!value || value.startsWith("-")) throw new Error(`${arg} requires a value`);
			index += 1;
			if (arg === "--host") host = parseHost(value);
			else port = parsePort(value);
			continue;
		}
		if (arg.startsWith("--host=")) {
			host = parseHost(arg.slice("--host=".length));
			continue;
		}
		if (arg.startsWith("--port=")) {
			port = parsePort(arg.slice("--port=".length));
			continue;
		}
		if (arg === "--help" || arg === "-h") {
			console.log("Usage: fleet-prime [--host <host>] [--port <port>]");
			process.exit(0);
		}
		throw new Error(`Unknown web launcher option: ${arg}`);
	}
	return { host, port };
}

function parseHost(value) {
	const host = value.trim();
	if (!host) throw new Error("--host requires a non-empty value");
	if (!isLoopbackHostname(host)) {
		throw new Error(`Invalid Fleet Prime host: ${host}. Fleet Prime accepts loopback hosts only.`);
	}
	return host;
}

function isLoopbackHostname(hostname) {
	return hostname === "127.0.0.1" || hostname === "localhost" || hostname === "::1";
}

const LOOPBACK_HOSTNAMES = new Set(["127.0.0.1", "localhost", "::1"]);
const BOUND_ORIGIN_HEADER = "x-fleet-bound-origin";

/** Dependency-free mirror of the protocol helper parseHostAuthority. */
function parseAuthority(authority) {
	let host = String(authority).trim();
	let port = null;
	const bracketEnd = host.indexOf("]");
	if (host.startsWith("[") && bracketEnd !== -1) {
		const suffix = host.slice(bracketEnd + 1);
		if (suffix.startsWith(":")) port = suffix.slice(1);
		host = host.slice(1, bracketEnd);
	} else if (host.includes(":") && host.indexOf(":") === host.lastIndexOf(":")) {
		const colon = host.indexOf(":");
		port = host.slice(colon + 1);
		host = host.slice(0, colon);
	}
	if (port !== null && !/^\d+$/.test(port)) port = null;
	return { hostname: host.toLowerCase(), port };
}

/**
 * Exact-origin gate (request-boundary spec): the Host authority must be a
 * loopback hostname on the bound port, and a present Origin header must match
 * that authority exactly. Mirrors evaluateRequestOrigin in
 * web/protocol/src/schemas/request-policy.ts — this standalone launcher keeps
 * a dependency-free copy of the rule.
 */
function isAllowedRequest(request) {
	const hostHeader = request.headers.host;
	if (!hostHeader || serverAddress === null || typeof serverAddress !== "object") return false;
	const authority = parseAuthority(hostHeader);
	if (!LOOPBACK_HOSTNAMES.has(authority.hostname)) return false;
	if (authority.port === null || Number(authority.port) !== serverAddress.port) return false;

	const origin = request.headers.origin;
	if (origin === undefined || origin === null) return true;
	if (origin === "null" || origin === "") return false;
	let parsed;
	try {
		parsed = new URL(origin);
	} catch {
		return false;
	}
	if (parsed.protocol !== "http:") return false;
	const originHostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
	if (!LOOPBACK_HOSTNAMES.has(originHostname)) return false;
	const originPort = parsed.port || "80";
	return originPort === authority.port && originHostname === authority.hostname;
}

function parsePort(value) {
	if (!/^\d+$/.test(value)) throw new Error(`Invalid web port: ${value}`);
	const port = Number(value);
	if (!Number.isSafeInteger(port) || port < 0 || port > MAX_PORT) {
		throw new Error(`Invalid web port: ${value}. Expected a number between 0 and ${MAX_PORT}.`);
	}
	return port;
}

function formatHost(host) {
	return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

function listen(server, host, port) {
	return new Promise((resolvePromise, reject) => {
		const onError = (error) => {
			server.off("listening", onListening);
			reject(error);
		};
		const onListening = () => {
			server.off("error", onError);
			resolvePromise();
		};
		server.once("error", onError);
		server.once("listening", onListening);
		server.listen({ host, port });
	});
}
