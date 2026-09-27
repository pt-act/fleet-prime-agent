import { handleChatEventsGet, methodNotAllowed } from "@prime-agent/web-server";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/chat/events")({
	server: {
		handlers: {
			ANY: () => methodNotAllowed(),
			GET: ({ request }) => handleChatEventsGet(request),
		},
	},
});
