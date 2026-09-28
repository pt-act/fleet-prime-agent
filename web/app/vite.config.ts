import type { IncomingMessage, ServerResponse } from "node:http"
import { resolve } from "node:path"
import { defineConfig, type Plugin } from "vite"
import { tanstackStart } from "@tanstack/react-start/plugin/vite"
import viteReact from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"

const webRoot = resolve(import.meta.dirname)

function headerValue(value: string | string[] | undefined): string | null {
	if (value === undefined) return null
	if (Array.isArray(value)) return value[0] ?? null
	return value
}

// --- dependency-free mirror of the request-boundary origin rule ---
// Canonical implementation: web/protocol/src/schemas/request-policy.ts
// (evaluateRequestOrigin). This config runs under Node's native ESM type
// stripping, which cannot resolve the workspace TS package graph, so the pure
// rule is mirrored here exactly as the standalone launcher mirrors it. The
// audit suite exercises both real launch boundaries, so drift fails tests.

const BOUND_ORIGIN_HEADER = "x-fleet-bound-origin"
const DECLARED_LENGTH_HEADER = "x-fleet-declared-length"
const LOOPBACK_HOSTNAMES = new Set(["127.0.0.1", "localhost", "::1"])

function parseAuthority(authority: string): { hostname: string; port: string | null } {
	let host = authority.trim()
	let port: string | null = null
	const bracketEnd = host.indexOf("]")
	if (host.startsWith("[") && bracketEnd !== -1) {
		const suffix = host.slice(bracketEnd + 1)
		if (suffix.startsWith(":")) port = suffix.slice(1)
		host = host.slice(1, bracketEnd)
	} else if (host.includes(":") && host.indexOf(":") === host.lastIndexOf(":")) {
		const colon = host.indexOf(":")
		port = host.slice(colon + 1)
		host = host.slice(0, colon)
	}
	if (port !== null && !/^\d+$/.test(port)) port = null
	return { hostname: host.toLowerCase(), port }
}

function evaluateRequestOrigin(input: {
	origin: string | null
	host: string | null
	boundPort: number | string
}): boolean {
	const { origin, host, boundPort } = input
	if (!host) return false
	const { hostname, port } = parseAuthority(host)
	if (!LOOPBACK_HOSTNAMES.has(hostname)) return false
	if (port === null || Number(port) !== Number(boundPort)) return false
	if (origin === null || origin === "") return true
	if (origin === "null") return false
	let parsed: URL
	try {
		parsed = new URL(origin)
	} catch {
		return false
	}
	if (parsed.protocol !== "http:") return false
	const originHostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase()
	if (!LOOPBACK_HOSTNAMES.has(originHostname)) return false
	const originPort = parsed.port || "80"
	return originPort === port && originHostname === hostname
}

/**
 * Dev-path request boundary (request-boundary spec): a thin exact-origin
 * pre-gate in front of the TanStack API handlers, the trusted bound-origin
 * header injection, and frame-ancestors 'none' on every HTML response.
 * Grant/protocol/media-type enforcement lives in web/server's policy.
 */
function fleetRequestBoundary(): Plugin {
	let boundOrigin: string | null = null
	return {
		name: "fleet-request-boundary",
		configureServer(server) {
			server.httpServer?.once("listening", () => {
				const address = server.httpServer?.address()
				if (!address || typeof address !== "object") return
				const host = address.address.includes(":") ? `[${address.address}]` : address.address
				boundOrigin = `http://${host}:${address.port}`
			})
			server.middlewares.use((req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void) => {
				// Tag every HTML response (static or SSR) with frame-ancestors 'none'.
				const setHeader = res.setHeader.bind(res)
				res.setHeader = ((name: string, value: string | number | ReadonlyArray<string>) => {
					const result = (setHeader as (n: string, v: string | number | ReadonlyArray<string>) => ServerResponse)(name, value)
					if (name.toLowerCase() === "content-type" && String(value).includes("text/html")) {
						;(setHeader as (n: string, v: string) => ServerResponse)("content-security-policy", "frame-ancestors 'none'")
					}
					return result
				}) as typeof res.setHeader
				const pathname = (req.url ?? "/").split("?")[0]
				if (!pathname.startsWith("/api/")) {
					next()
					return
				}
				if (!boundOrigin) {
					res.statusCode = 503
					res.end("Request boundary not ready")
					return
				}
				const boundPort = Number(new URL(boundOrigin).port)
				const admitted = evaluateRequestOrigin({
					origin: headerValue(req.headers.origin),
					host: headerValue(req.headers.host),
					boundPort,
				})
				if (!admitted) {
					res.statusCode = 403
					res.setHeader("content-type", "application/json")
					res.end(
						JSON.stringify({
							error: {
								code: "ORIGIN_DENIED",
								message: "Same-origin loopback requests only",
								retryable: false,
								requestId: "dev-boundary",
							},
						}),
					)
					return
				}
				// Trusted headers — overwrite any client-supplied values. The
				// declared length preserves the transport-level Content-Length,
				// which fetch-Request construction in the dev pipeline drops.
				req.headers[BOUND_ORIGIN_HEADER] = boundOrigin
				delete req.headers[DECLARED_LENGTH_HEADER]
				const rawLength = req.headers["content-length"]
				if (typeof rawLength === "string" && rawLength.length > 0) {
					req.headers[DECLARED_LENGTH_HEADER] = rawLength
				}
				next()
			})
		},
	}
}

const config = defineConfig({
	envDir: webRoot,
	resolve: {
		tsconfigPaths: true,
	},
	server: {
		port: 3000,
		strictPort: false,
		host: "127.0.0.1",
		fs: {
			allow: [
				webRoot,
				resolve(webRoot, ".."),
				resolve(webRoot, "../../packages"),
				// pnpm store lives at the repo root since the workspace unification.
				resolve(webRoot, "../../node_modules"),
			],
		},
		watch: {
			ignored: ["**/.env", "**/.env.local"],
		},
	},
	ssr: {
		external: [
			"@earendil-works/pi-agent-core",
			"@earendil-works/pi-ai",
			"@earendil-works/pi-tui",
			"prime-agent",
		],
	},
	plugins: [fleetRequestBoundary(), tailwindcss(), tanstackStart(), viteReact()],
})

export default config
