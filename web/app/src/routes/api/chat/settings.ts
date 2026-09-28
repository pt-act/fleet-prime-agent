import { handleChatSettingsGet, handleChatSettingsPatch, methodNotAllowed } from "@prime-agent/web-server";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/chat/settings")({
	server: {
		handlers: {
			ANY: () => methodNotAllowed(),
			GET: ({ request }) => handleChatSettingsGet(request),
			PATCH: ({ request }) => handleChatSettingsPatch(request),
		},
	},
});
