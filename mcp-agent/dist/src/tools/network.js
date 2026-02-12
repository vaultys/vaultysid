/**
 * Network MCP tool — fetch_url
 *
 * Fetches content from a URL with policy enforcement on the hostname.
 */
import { z } from "zod";
export function registerNetworkTool(server, middleware) {
    server.tool("fetch_url", "Fetch content from a URL. Subject to egress policy.", {
        url: z.string().url().describe("The URL to fetch"),
        method: z.enum(["GET", "POST", "PUT", "DELETE"]).default("GET").describe("HTTP method"),
        body: z.string().optional().describe("Request body (for POST/PUT)"),
    }, async (args) => {
        const result = await middleware.enforce("fetch_url", args, async () => {
            const init = { method: args.method };
            if (args.body && (args.method === "POST" || args.method === "PUT")) {
                init.body = args.body;
                init.headers = { "Content-Type": "application/json" };
            }
            const response = await fetch(args.url, init);
            const text = await response.text();
            return `HTTP ${response.status} ${response.statusText}\n\n${text.slice(0, 10000)}`;
        });
        return { content: result.content, isError: result.decision === "deny" };
    });
}
