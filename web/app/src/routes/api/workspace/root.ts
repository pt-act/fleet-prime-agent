import { handleWorkspaceRootPost, methodNotAllowed } from "@prime-agent/web-server";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/workspace/root")({
	server: {
		handlers: {
			ANY: () => methodNotAllowed(),
			POST: ({ request }) => handleWorkspaceRootPost(request),
		},
	},
});
