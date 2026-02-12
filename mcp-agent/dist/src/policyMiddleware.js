/**
 * Policy Middleware — wraps every MCP tool call through ExecutionManager.
 *
 * For each tool invocation the middleware:
 *   1. Maps the MCP tool name + arguments → taxonomy capability strings
 *   2. Creates and signs an ExecutionIntent via the server's IdManager
 *   3. Evaluates the intent against the loaded signed PolicyBundle
 *   4. If allowed, executes the real handler and signs a receipt
 *   5. If denied, returns a denial message and signs a deny receipt
 *
 * All receipts are persisted to ./audit/ as JSON files.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { ExecutionManager } from "@vaultys/id";
/**
 * Default mappings from MCP tool names to taxonomy capabilities.
 *
 * Scopes must match the format used in the policy's scope patterns.
 * For filesystem tools: full resolved paths (e.g. "/workspace/src/file.ts")
 * For process tools: the binary name (e.g. "ls", "npm")
 * For network tools: the hostname (e.g. "api.example.com")
 *
 * The `workspaceRoot` parameter is passed to `extractScope` so that filesystem
 * tools can resolve relative paths to absolute paths matching the policy globs.
 */
export const DEFAULT_TOOL_MAPPINGS = {
    read_file: {
        capability: "fs.read",
        extractScope: (args, workspaceRoot) => {
            const raw = String(args.path ?? args.file ?? "");
            return resolveWorkspacePath(raw, workspaceRoot);
        },
    },
    write_file: {
        capability: "fs.write",
        extractScope: (args, workspaceRoot) => {
            const raw = String(args.path ?? args.file ?? "");
            return resolveWorkspacePath(raw, workspaceRoot);
        },
    },
    list_directory: {
        capability: "fs.list",
        extractScope: (args, workspaceRoot) => {
            const raw = String(args.path ?? args.directory ?? ".");
            return resolveWorkspacePath(raw, workspaceRoot);
        },
    },
    run_command: {
        capability: "proc.exec",
        extractScope: (args) => {
            const cmd = String(args.command ?? "");
            // Extract the binary name (first token)
            return cmd.split(/\s+/)[0] ?? cmd;
        },
    },
    fetch_url: {
        capability: "net.egress.http",
        extractScope: (args) => {
            try {
                return new URL(String(args.url ?? "")).hostname;
            }
            catch {
                return String(args.url ?? "");
            }
        },
    },
};
/**
 * Resolve a tool argument path to an absolute path rooted at workspaceRoot.
 * This ensures capability strings like "fs.read:/workspace/subdir/file.txt"
 * match policy glob patterns like "/workspace/**".
 */
function resolveWorkspacePath(raw, workspaceRoot) {
    if (!raw)
        return workspaceRoot ?? "/workspace";
    if (path.isAbsolute(raw))
        return raw;
    return path.join(workspaceRoot ?? "/workspace", raw);
}
// ── Audit persistence ──
const AUDIT_DIR = path.resolve("audit");
function ensureAuditDir() {
    if (!fs.existsSync(AUDIT_DIR)) {
        fs.mkdirSync(AUDIT_DIR, { recursive: true });
    }
}
function persistReceipt(jobId, receipt, meta) {
    ensureAuditDir();
    const record = {
        job_id: jobId,
        timestamp: new Date().toISOString(),
        ...meta,
        receipt,
    };
    const filePath = path.join(AUDIT_DIR, `${jobId}.json`);
    fs.writeFileSync(filePath, JSON.stringify(record, null, 2));
}
/**
 * Create policy-enforced middleware that wraps MCP tool handlers.
 */
export function createPolicyMiddleware(options) {
    const { serverIdManager, signedPolicy, toolMappings = DEFAULT_TOOL_MAPPINGS, workspaceRoot = process.cwd(), } = options;
    const em = new ExecutionManager(serverIdManager);
    /**
     * Wrap a tool call: evaluate policy, run handler if allowed, sign receipt.
     */
    async function enforce(toolName, args, handler) {
        const mapping = toolMappings[toolName];
        // Build capability strings
        const requestedCaps = [];
        let argv = [];
        if (mapping) {
            const scope = mapping.extractScope(args, workspaceRoot);
            requestedCaps.push(`${mapping.capability}:${scope}`);
            argv = toolName === "run_command"
                ? String(args.command ?? "").split(/\s+/)
                : [toolName, scope];
        }
        else {
            // Unknown tool → treat as a catch-all with the tool name as capability
            requestedCaps.push(`tool.${toolName}`);
            argv = [toolName];
        }
        // Create and sign the intent
        const intent = await em.createIntent({
            tool: toolName,
            argv,
            cwd: workspaceRoot,
            requested_caps: requestedCaps,
        });
        // Evaluate against the policy
        const evaluation = em.evaluateIntent(intent, signedPolicy);
        if (evaluation.decision === "deny") {
            // Sign a deny receipt
            const denyOutcome = {
                started: new Date().toISOString(),
                ended: new Date().toISOString(),
                exit_code: -1,
                stdout_hash: "",
                stderr_hash: "",
            };
            const receipt = await em.signReceipt(intent, signedPolicy, denyOutcome);
            persistReceipt(intent.job_id, receipt, {
                tool: toolName,
                args,
                decision: "deny",
                denied_caps: evaluation.denied_caps,
            });
            const reason = evaluation.denied_caps?.join(", ") ?? "unknown";
            console.error(`[POLICY DENY] ${toolName}: ${reason}`);
            return {
                decision: "deny",
                content: [{ type: "text", text: `⛔ DENIED by policy: ${reason}` }],
                receipt,
                jobId: intent.job_id,
            };
        }
        // Policy allows → execute
        console.error(`[POLICY ALLOW] ${toolName}: ${requestedCaps.join(", ")}`);
        const started = new Date().toISOString();
        let stdout = "";
        let exitCode = 0;
        try {
            stdout = await handler();
        }
        catch (err) {
            stdout = err.message ?? String(err);
            exitCode = 1;
        }
        const ended = new Date().toISOString();
        const outcome = {
            started,
            ended,
            exit_code: exitCode,
            stdout_hash: Buffer.from(stdout).toString("base64").slice(0, 64),
        };
        const receipt = await em.signReceipt(intent, signedPolicy, outcome);
        persistReceipt(intent.job_id, receipt, {
            tool: toolName,
            args,
            decision: "allow",
            allowed_caps: evaluation.allowed_caps,
            constraints: evaluation.constraints,
        });
        return {
            decision: "allow",
            content: [{ type: "text", text: stdout }],
            receipt,
            jobId: intent.job_id,
        };
    }
    return { enforce, em };
}
