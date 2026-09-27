import { handleChatResumePost, methodNotAllowed } from "@prime-agent/web-server";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/chat/resume")({
	server: {
		handlers: {
			ANY: () => methodNotAllowed(),
			POST: ({ request }) => handleChatResumePost(request),
		},
	},
});
