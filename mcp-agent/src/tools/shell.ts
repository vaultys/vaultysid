/**
 * Shell MCP tool — run_command
 *
 * Executes shell commands with policy enforcement.
 * Shell metacharacters are blocked by the `no_shell_features` constraint.
 */

import { execSync } from "node:child_process";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { createPolicyMiddleware } from "../policyMiddleware.js";

type Middleware = ReturnType<typeof createPolicyMiddleware>;

export function registerShellTool(
  server: McpServer,
  middleware: Middleware,
  workspaceRoot: string,
) {
  server.tool(
    "run_command",
    "Run a shell command in the workspace directory. Subject to policy constraints.",
    {
      command: z.string().describe("The command to execute (e.g. 'ls -la')"),
      timeout: z.number().describe("Timeout in milliseconds").default(30000),
    },
    async (args) => {
      const result = await middleware.enforce("run_command", args, async () => {
        const output = execSync(args.command, {
          cwd: workspaceRoot,
          timeout: args.timeout,
          encoding: "utf-8",
          maxBuffer: 1024 * 1024, // 1MB
          stdio: ["pipe", "pipe", "pipe"],
        });
        return output;
      });
      return { content: result.content, isError: result.decision === "deny" };
    },
  );
}
