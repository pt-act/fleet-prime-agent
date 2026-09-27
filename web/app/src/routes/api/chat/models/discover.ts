import { handleChatModelsDiscoverPost, methodNotAllowed } from "@prime-agent/web-server";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/chat/models/discover")({
	server: {
		handlers: {
			ANY: () => methodNotAllowed(),
			POST: ({ request }) => handleChatModelsDiscoverPost(request),
		},
	},
});
