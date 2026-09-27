import { handleChatCommandsGet, methodNotAllowed } from "@prime-agent/web-server";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/chat/commands")({
	server: {
		handlers: {
			ANY: () => methodNotAllowed(),
			GET: ({ request }) => handleChatCommandsGet(request),
		},
	},
});
