import { handleWorkspaceFileGet, methodNotAllowed } from "@prime-agent/web-server";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/workspace/file")({
	server: {
		handlers: {
			ANY: () => methodNotAllowed(),
			GET: ({ request }) => handleWorkspaceFileGet(request),
		},
	},
});
