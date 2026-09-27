import { handleBootstrapGet, methodNotAllowed } from "@prime-agent/web-server";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/bootstrap")({
	server: {
		handlers: {
			ANY: () => methodNotAllowed(),
			GET: ({ request }) => handleBootstrapGet(request),
		},
	},
});
