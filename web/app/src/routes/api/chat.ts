import { handleChatPost, methodNotAllowed } from "@prime-agent/web-server";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/chat")({
	server: {
		handlers: {
			ANY: () => methodNotAllowed(),
			POST: ({ request }) => handleChatPost(request),
		},
	},
});
