import {
	handleChatSessionDelete,
	handleChatSessionRenamePatch,
	handleChatSessionsGet,
	methodNotAllowed,
} from "@prime-agent/web-server";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/chat/sessions")({
	server: {
		handlers: {
			ANY: () => methodNotAllowed(),
			DELETE: ({ request }) => handleChatSessionDelete(request),
			GET: ({ request }) => handleChatSessionsGet(request),
			PATCH: ({ request }) => handleChatSessionRenamePatch(request),
		},
	},
});
