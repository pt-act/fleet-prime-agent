import { REQUEST_POLICY_PROTOCOL_VERSION } from "@prime-agent/web-protocol/request-policy";
import { getLaunchId, mintBootstrapGrant } from "../request-policy";
import { wrapApiHandler } from "../wrap-api-handler";

/**
 * GET /api/bootstrap — mints the 30-minute admission grant for the calling
 * exact-origin browser. Loopback Host and (when present) same-origin fetch
 * metadata are enforced by the request policy before this runs.
 */
export function handleBootstrapGet(request: Request): Promise<Response> {
	return wrapApiHandler(request, async () => {
		const { grant, expiresAt } = mintBootstrapGrant();
		return Response.json(
			{
				protocolVersion: REQUEST_POLICY_PROTOCOL_VERSION,
				launchId: getLaunchId(),
				grant,
				expiresAt,
			},
			{ headers: { "cache-control": "no-store" } },
		);
	});
}
