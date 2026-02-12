/**
 * Filesystem MCP tools — read_file, write_file, list_directory
 *
 * All operations are sandboxed to the workspace root via policy evaluation.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { z } from "zod";
export function registerFilesystemTools(server, middleware, workspaceRoot) {
    // ── read_file ──
    server.tool("read_file", "Read a file from the workspace. Returns the file contents.", { path: z.string().describe("Relative or absolute path to the file") }, async (args) => {
        const result = await middleware.enforce("read_file", args, async () => {
            const filePath = path.resolve(workspaceRoot, args.path);
            return fs.readFileSync(filePath, "utf-8");
        });
        return { content: result.content, isError: result.decision === "deny" };
    });
    // ── write_file ──
    server.tool("write_file", "Write content to a file in the workspace.", {
        path: z.string().describe("Relative or absolute path to the file"),
        content: z.string().describe("Content to write to the file"),
    }, async (args) => {
        const result = await middleware.enforce("write_file", args, async () => {
            const filePath = path.resolve(workspaceRoot, args.path);
            const dir = path.dirname(filePath);
            if (!fs.existsSync(dir))
                fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(filePath, args.content, "utf-8");
            return `File written: ${args.path} (${args.content.length} bytes)`;
        });
        return { content: result.content, isError: result.decision === "deny" };
    });
    // ── list_directory ──
    server.tool("list_directory", "List the contents of a directory in the workspace.", { path: z.string().describe("Relative or absolute path to the directory").default(".") }, async (args) => {
        const result = await middleware.enforce("list_directory", args, async () => {
            const dirPath = path.resolve(workspaceRoot, args.path);
            const entries = fs.readdirSync(dirPath, { withFileTypes: true });
            return entries
                .map((e) => `${e.isDirectory() ? "📁" : "📄"} ${e.name}`)
                .join("\n");
        });
        return { content: result.content, isError: result.decision === "deny" };
    });
}
