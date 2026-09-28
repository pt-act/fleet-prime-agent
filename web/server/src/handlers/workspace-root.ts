import { wrapApiHandler } from "../wrap-api-handler";

/** POST /api/workspace/root — the workspace root is fixed; admitted by the request boundary like every API route. */
export function handleWorkspaceRootPost(request: Request): Promise<Response> {
	return wrapApiHandler(request, async () => {
		return Response.json({ message: "The workspace root is fixed when Fleet starts" }, { status: 405 });
	});
}
