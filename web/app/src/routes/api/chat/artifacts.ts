import { handleChatOpenUIArtifactPut, methodNotAllowed } from "@prime-agent/web-server";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/chat/artifacts")({
	server: {
		handlers: {
			ANY: () => methodNotAllowed(),
			PUT: ({ request }) => handleChatOpenUIArtifactPut(request),
		},
	},
});
