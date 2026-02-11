import { Buffer } from "buffer/";

// ── Intent ──

export interface IntentParams {
  tool: string;
  argv: string[];
  cwd: string;
  env_allowlist?: string[];
  requested_caps: string[];
  inputs?: Record<string, string>;
}

export interface ExecutionIntent {
  job_id: string;
  timestamp: number;
  nonce: Buffer;
  agent_id: string; // did:vaultys:...
  tool: string;
  argv: string[];
  cwd: string;
  env_allowlist: string[];
  requested_caps: string[];
  inputs: Record<string, string>; // filename → sha256 hash
  signature?: Buffer;
}

// ── Policy ──

export interface PolicyScopes {
  [key: string]: string[];
}

export interface PolicyConstraints {
  max_runtime?: number;
  no_shell_features?: boolean;
  [key: string]: any;
}

export interface PolicyBundle {
  version: string;
  scopes: PolicyScopes;
  denied: string[];
  constraints: PolicyConstraints;
  signature?: Buffer;
}

// ── Execution result ──

export type ExecutionDecision = "allow" | "deny" | "allow-with-constraints";

export interface ExecutionResult {
  decision: ExecutionDecision;
  constraints?: PolicyConstraints;
  denied_caps?: string[];
  allowed_caps?: string[];
}

// ── Execution outcome (returned by sandbox callback) ──

export interface ExecOutcome {
  started: string; // ISO 8601
  ended: string;
  exit_code: number;
  stdout_hash?: string;
  stderr_hash?: string;
  artifacts?: Record<string, string>; // filename → sha256 hash
  sandbox_config_hash?: string;
}

// ── Signed Receipt ──

export interface SignedReceipt {
  intent_hash: string;
  policy_hash: string;
  sandbox_config_hash: string;
  exec: {
    started: string;
    ended: string;
    exit_code: number;
  };
  outputs: {
    stdout_hash?: string;
    stderr_hash?: string;
  };
  artifacts: Record<string, string>;
  broker_signature?: Buffer;
}

// ── Callbacks ──

export type ExecuteCallback = (
  intent: ExecutionIntent,
  result: ExecutionResult,
) => Promise<ExecOutcome>;

// ── Stored Policy (agreed via SRP) ──

export interface StoredPolicy {
  policy: PolicyBundle;
  certificate: Buffer;
  counterpartDid: string;
  agreedAt: number;
}
