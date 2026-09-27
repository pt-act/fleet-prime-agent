import { handleChatCommandPost, methodNotAllowed } from "@prime-agent/web-server";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/chat/command")({
	server: {
		handlers: {
			ANY: () => methodNotAllowed(),
			POST: ({ request }) => handleChatCommandPost(request),
		},
	},
});
