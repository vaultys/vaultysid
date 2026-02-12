# @vaultys/mcp-agent

**Policy-enforced MCP server powered by VaultysID** — cryptographic authorization and tamper-evident audit trail for every AI tool call.

Every action your AI agent takes is:
1. **Authorized** against a signed policy bundle
2. **Executed** only if allowed
3. **Receipted** with a cryptographic signature for tamper-evident audit

## Quick Start — 2 minutes to Claude Desktop

### 1. Add to Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "vaultys-agent": {
      "command": "npx",
      "args": ["-y", "@vaultys/mcp-agent"]
    }
  }
}
```

That's it. Restart Claude Desktop — the server auto-generates a default policy on first run.

### 2. (Optional) Set a workspace directory

By default the agent uses your current working directory. To restrict file access to a specific project:

```json
{
  "mcpServers": {
    "vaultys-agent": {
      "command": "npx",
      "args": ["-y", "@vaultys/mcp-agent"],
      "env": {
        "WORKSPACE_ROOT": "/Users/you/projects/my-app"
      }
    }
  }
}
```

### 3. (Optional) Customize the policy

```bash
npx @vaultys/mcp-agent init --workspace /path/to/project --hours 48
```

This creates/updates the signed policy in `~/.vaultys-mcp/`.

## What It Does

```
┌──────────────┐         ┌────────────────────────────────────┐
│  Claude /    │◄──MCP──►│  @vaultys/mcp-agent                │
│  Cursor /    │  stdio  │                                    │
│  any client  │         │  ┌──────────────────────────────┐  │
│              │         │  │ Policy Middleware             │  │
│              │         │  │  map tool → capability        │  │
│              │         │  │  evaluate against policy      │  │
│              │         │  │  sign receipt                 │  │
│              │         │  └──────────────────────────────┘  │
│              │         │                                    │
│              │         │  Tools:                            │
│              │         │    read_file   → fs.read:path      │
│              │         │    write_file  → fs.write:path     │
│              │         │    list_directory → fs.list:path   │
│              │         │    run_command → proc.exec:bin     │
│              │         │    fetch_url   → net.egress:host   │
│              │         │                                    │
│              │         │  Audit: ~/.vaultys-mcp/ + ./audit/ │
└──────────────┘         └────────────────────────────────────┘
```

### Policy Enforcement

Every tool call is mapped to a taxonomy capability and checked against the signed policy:

| Tool             | Capability        | Example Scope             |
| ---------------- | ----------------- | ------------------------- |
| `read_file`      | `fs.read`         | `/workspace/src/index.ts` |
| `write_file`     | `fs.write`        | `/workspace/output.json`  |
| `list_directory` | `fs.list`         | `/workspace/src`          |
| `run_command`    | `proc.exec`       | `ls`, `grep`, `cat`       |
| `fetch_url`      | `net.egress.http` | `api.example.com`         |

Denied calls return an error message to the AI and are logged with a signed denial receipt.

### Default Policy

Auto-generated on first run — allows:
- File read/write/list within `WORKSPACE_ROOT`
- Safe commands: `ls`, `cat`, `echo`, `wc`, `head`, `tail`, `grep`, `find`, `pwd`, `date`, `whoami`
- HTTP requests to any host
- Blocks: `secrets.*`, `pkg.system`, `proc.privilege`

## CLI Commands

```bash
# Start the MCP server (called by Claude Desktop via npx)
npx @vaultys/mcp-agent

# Interactive setup — customize policy, workspace, validity
npx @vaultys/mcp-agent init
npx @vaultys/mcp-agent init --workspace /path --hours 48

# Sign a custom policy
npx @vaultys/mcp-agent grant --policy custom.json --hours 2

# Verify the audit trail
npx @vaultys/mcp-agent audit
npx @vaultys/mcp-agent audit --tamper <job-id>   # demo tampering detection
```

Or using globally installed commands:

```bash
vaultys-mcp-agent          # start server
vaultys-mcp-init           # setup
vaultys-mcp-grant          # sign policy
vaultys-mcp-audit          # verify receipts
```

## MCP Resources

The server exposes these resources that Claude can read:

| Resource URI                | Description                 |
| --------------------------- | --------------------------- |
| `vaultys://policy/current`  | Active signed policy (JSON) |
| `vaultys://identity/server` | Server DID and public key   |
| `vaultys://receipts/list`   | All receipt summaries       |

## Configuration

### Environment Variables

| Variable             | Default           | Description                                 |
| -------------------- | ----------------- | ------------------------------------------- |
| `WORKSPACE_ROOT`     | Current directory | Root directory for file operations          |
| `POLICY_FILE`        | (auto-managed)    | Path to a custom signed policy file         |
| `AUTHORITY_FILE`     | (auto-managed)    | Path to authority identity for verification |
| `VAULTYS_CONFIG_DIR` | `~/.vaultys-mcp`  | Configuration directory                     |

### Config Directory (`~/.vaultys-mcp/`)

| File                      | Purpose                             |
| ------------------------- | ----------------------------------- |
| `server.identity.json`    | Server's VaultysID (auto-generated) |
| `authority.secret.json`   | Authority private key (keep safe!)  |
| `authority.identity.json` | Authority public key                |
| `policy.signed.json`      | Active signed policy                |

### Custom Policy File

Create a JSON policy and sign it:

```json
{
  "version": "1.0",
  "scopes": {
    "fs.read": ["{{WORKSPACE}}/**"],
    "fs.write": ["{{WORKSPACE}}/output/**"],
    "fs.list": ["{{WORKSPACE}}/**"],
    "proc.exec": ["ls", "cat", "grep"],
    "net.egress.http": ["api.mycompany.com"]
  },
  "denied": ["secrets.*", "pkg.system"],
  "constraints": {
    "max_runtime": 60,
    "no_shell_features": true
  }
}
```

`{{WORKSPACE}}` is replaced with the actual workspace path at signing time.

```bash
vaultys-mcp-grant --policy my-policy.json --workspace /my/project --hours 8
```

## Audit Trail

Every tool call produces a signed receipt in `./audit/`:

```json
{
  "job_id": "a1b2c3d4-...",
  "timestamp": "2025-02-12T...",
  "tool": "read_file",
  "decision": "allow",
  "allowed_caps": ["fs.read:/workspace/README.md"],
  "receipt": {
    "intent_hash": "sha256...",
    "policy_hash": "sha256...",
    "exec": { "started": "...", "ended": "...", "exit_code": 0 },
    "broker_signature": "<base64>"
  }
}
```

Verify the entire audit trail:

```bash
vaultys-mcp-audit
```

Tampered receipts are detected — the cryptographic signature becomes invalid.

## Security Model

- **Server identity**: Ed25519 keypair generated on first run, persisted in `~/.vaultys-mcp/`
- **Authority identity**: Separate keypair that signs policies — can be held by a different person/system
- **Policy signing**: Authority signs the policy bundle; server verifies before loading
- **Intent signing**: Server signs each execution intent before policy evaluation
- **Receipt signing**: Server signs each execution outcome for tamper-evident audit
- **Scope matching**: File paths resolved to absolute paths; glob matching against policy patterns
- **Denied capabilities**: Explicit deny list checked before scope matching (deny wins)

## Development

```bash
git clone https://github.com/vaultys/vaultysid
cd mcp-agent
pnpm install

# Run tests (29 E2E tests)
pnpm test

# Start server directly (dev mode, no build needed)
pnpm start

# Sign a policy (dev mode)
pnpm grant-policy

# Build for production
pnpm build
```

## License

MIT
