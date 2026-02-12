#!/usr/bin/env node
/**
 * End-to-End Test — VaultysID MCP Agent
 *
 * Tests the full lifecycle following the canonical patterns from
 * executionManager.test.ts:
 *
 *   1. Identity creation and persistence (MemoryStorage, IdManager.fromStore)
 *   2. Policy signing and verification (ExecutionManager.signPolicy/verifyPolicy)
 *   3. Intent creation and evaluation (createIntent / evaluateIntent)
 *   4. Capability scope matching (fs, proc, net taxonomy)
 *   5. Receipt signing and verification (signReceipt / verifyReceipt)
 *   6. SRP policy agreement (grantPolicy / acceptPolicy via MemoryChannel)
 *   7. Policy middleware integration
 */

import * as assert from "node:assert";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  IdManager,
  VaultysId,
  MemoryStorage,
  MemoryChannel,
  ExecutionManager,
  Challenger,
} from "@vaultys/id";
import type { PolicyBundle, ExecOutcome } from "@vaultys/id";
import { createPolicyMiddleware } from "../src/policyMiddleware.js";

// ── Helpers ──

const WORKSPACE = "/tmp/vaultys-mcp-test";
const TEST_AUDIT_DIR = path.join(os.tmpdir(), "vaultys-mcp-test-audit");

const createIdManager = async (): Promise<IdManager> => {
  const store = MemoryStorage();
  const idm = await IdManager.fromStore(store);
  idm.setProtocolVersion(1);
  return idm;
};

const samplePolicy: Omit<PolicyBundle, "signature"> = {
  version: "1.0",
  scopes: {
    "fs.read": [`${WORKSPACE}/**`],
    "fs.write": [`${WORKSPACE}/**`],
    "fs.list": [`${WORKSPACE}/**`],
    "proc.exec": ["ls", "cat", "echo", "grep", "find"],
    "net.egress.http": ["*"],
  },
  denied: ["secrets.*", "pkg.system", "proc.privilege"],
  constraints: {
    max_runtime: 300,
    no_shell_features: true,
  },
};

let passed = 0;
let failed = 0;

function test(name: string, fn: () => Promise<void> | void): Promise<void> {
  return Promise.resolve(fn())
    .then(() => {
      passed++;
      console.log(`  ✓ ${name}`);
    })
    .catch((err) => {
      failed++;
      console.log(`  ✗ ${name}`);
      console.log(`    ${err.message}`);
    });
}

// ── Tests ──

async function main() {
  console.log("\n═══ VaultysID MCP Agent — E2E Tests ═══\n");

  // ────────────────────────────────
  console.log("Identity & Storage");
  // ────────────────────────────────

  await test("create machine identity via MemoryStorage + IdManager.fromStore", async () => {
    const store = MemoryStorage();
    const idm = await IdManager.fromStore(store);
    assert.ok(idm.vaultysId.did.startsWith("did:vaultys:"));
    assert.ok(idm.vaultysId.fingerprint);
    assert.ok(idm.vaultysId.id.length > 0);
  });

  await test("persist and restore identity via store.toString / fromString", async () => {
    const store = MemoryStorage();
    const idm = await IdManager.fromStore(store);
    const serialized = store.toString();

    const store2 = MemoryStorage().fromString(serialized);
    const idm2 = await IdManager.fromStore(store2);

    assert.equal(idm2.vaultysId.did, idm.vaultysId.did);
    assert.equal(idm2.vaultysId.fingerprint, idm.vaultysId.fingerprint);
    assert.equal(
      idm2.vaultysId.id.toString("base64"),
      idm.vaultysId.id.toString("base64"),
    );
  });

  await test("export public identity via VaultysId.id and reconstruct with fromId", async () => {
    const idm = await createIdManager();
    const vid = idm.vaultysId;

    // Export as base64
    const idBase64 = Buffer.from(vid.id).toString("base64");

    // Reconstruct public-only VaultysId
    const pub = VaultysId.fromId(Buffer.from(idBase64, "base64"));
    assert.equal(pub.did, vid.did);
    assert.equal(pub.fingerprint, vid.fingerprint);
    assert.deepStrictEqual(pub.didDocument, vid.didDocument);
  });

  // ────────────────────────────────
  console.log("\nPolicy Signing & Verification");
  // ────────────────────────────────

  await test("sign and verify a policy", async () => {
    const authority = await createIdManager();
    const em = new ExecutionManager(authority);
    const signed = await em.signPolicy(samplePolicy);

    assert.ok(signed.signature);
    assert.ok(ExecutionManager.verifyPolicy(signed, authority.vaultysId));
  });

  await test("reject tampered policy", async () => {
    const authority = await createIdManager();
    const em = new ExecutionManager(authority);
    const signed = await em.signPolicy(samplePolicy);

    signed.version = "2.0"; // tamper
    assert.ok(!ExecutionManager.verifyPolicy(signed, authority.vaultysId));
  });

  await test("reject policy signed by wrong authority", async () => {
    const auth1 = await createIdManager();
    const auth2 = await createIdManager();
    const em = new ExecutionManager(auth1);
    const signed = await em.signPolicy(samplePolicy);

    assert.ok(!ExecutionManager.verifyPolicy(signed, auth2.vaultysId));
  });

  // ────────────────────────────────
  console.log("\nIntent Creation & Evaluation");
  // ────────────────────────────────

  let signedPolicy: PolicyBundle;
  let authority: IdManager;
  let broker: IdManager;

  // Setup: sign a policy for evaluation tests
  authority = await createIdManager();
  broker = await createIdManager();
  const authorityEm = new ExecutionManager(authority);
  signedPolicy = await authorityEm.signPolicy(samplePolicy);
  const brokerEm = new ExecutionManager(broker);

  await test("create and verify an intent", async () => {
    const agent = await createIdManager();
    const em = new ExecutionManager(agent);

    const intent = await em.createIntent({
      tool: "read_file",
      argv: ["read_file", `${WORKSPACE}/test.txt`],
      cwd: WORKSPACE,
      requested_caps: [`fs.read:${WORKSPACE}/test.txt`],
    });

    assert.ok(intent.signature);
    assert.ok(intent.job_id);
    assert.ok(intent.nonce);
    assert.equal(intent.agent_id, agent.vaultysId.did);
    assert.ok(ExecutionManager.verifyIntent(intent, agent.vaultysId));
  });

  await test("allow fs.read with workspace-scoped path", async () => {
    const agent = await createIdManager();
    const agentEm = new ExecutionManager(agent);

    const intent = await agentEm.createIntent({
      tool: "read_file",
      argv: ["read_file", `${WORKSPACE}/src/index.ts`],
      cwd: WORKSPACE,
      requested_caps: [`fs.read:${WORKSPACE}/src/index.ts`],
    });

    const result = brokerEm.evaluateIntent(intent, signedPolicy);
    assert.notEqual(result.decision, "deny");
    assert.ok(result.allowed_caps?.includes(`fs.read:${WORKSPACE}/src/index.ts`));
  });

  await test("deny fs.read outside workspace", async () => {
    const agent = await createIdManager();
    const agentEm = new ExecutionManager(agent);

    const intent = await agentEm.createIntent({
      tool: "read_file",
      argv: ["read_file", "/etc/passwd"],
      cwd: WORKSPACE,
      requested_caps: ["fs.read:/etc/passwd"],
    });

    const result = brokerEm.evaluateIntent(intent, signedPolicy);
    assert.equal(result.decision, "deny");
    assert.ok(result.denied_caps?.includes("fs.read:/etc/passwd"));
  });

  await test("allow proc.exec with permitted command", async () => {
    const agent = await createIdManager();
    const agentEm = new ExecutionManager(agent);

    const intent = await agentEm.createIntent({
      tool: "run_command",
      argv: ["ls", "-la"],
      cwd: WORKSPACE,
      requested_caps: ["proc.exec:ls"],
    });

    const result = brokerEm.evaluateIntent(intent, signedPolicy);
    assert.notEqual(result.decision, "deny");
  });

  await test("deny proc.exec with forbidden command", async () => {
    const agent = await createIdManager();
    const agentEm = new ExecutionManager(agent);

    const intent = await agentEm.createIntent({
      tool: "run_command",
      argv: ["rm", "-rf", "/"],
      cwd: WORKSPACE,
      requested_caps: ["proc.exec:rm"],
    });

    const result = brokerEm.evaluateIntent(intent, signedPolicy);
    assert.equal(result.decision, "deny");
  });

  await test("deny shell metacharacters when no_shell_features", async () => {
    const agent = await createIdManager();
    const agentEm = new ExecutionManager(agent);

    const intent = await agentEm.createIntent({
      tool: "run_command",
      argv: ["ls", "&&", "rm", "-rf", "/"],
      cwd: WORKSPACE,
      requested_caps: ["proc.exec:ls"],
    });

    const result = brokerEm.evaluateIntent(intent, signedPolicy);
    assert.equal(result.decision, "deny");
  });

  await test("allow net.egress.http with wildcard scope", async () => {
    const agent = await createIdManager();
    const agentEm = new ExecutionManager(agent);

    const intent = await agentEm.createIntent({
      tool: "fetch_url",
      argv: ["fetch_url", "api.example.com"],
      cwd: WORKSPACE,
      requested_caps: ["net.egress.http:api.example.com"],
    });

    const result = brokerEm.evaluateIntent(intent, signedPolicy);
    assert.notEqual(result.decision, "deny");
  });

  await test("deny secrets.* capabilities", async () => {
    const agent = await createIdManager();
    const agentEm = new ExecutionManager(agent);

    const intent = await agentEm.createIntent({
      tool: "vault",
      argv: ["read", "secret/key"],
      cwd: WORKSPACE,
      requested_caps: ["secrets.read"],
    });

    const result = brokerEm.evaluateIntent(intent, signedPolicy);
    assert.equal(result.decision, "deny");
    assert.ok(result.denied_caps?.includes("secrets.read"));
  });

  await test("return allow-with-constraints when constraints exist", async () => {
    const agent = await createIdManager();
    const agentEm = new ExecutionManager(agent);

    const intent = await agentEm.createIntent({
      tool: "ls",
      argv: ["ls"],
      cwd: WORKSPACE,
      requested_caps: ["proc.exec:ls"],
    });

    const result = brokerEm.evaluateIntent(intent, signedPolicy);
    assert.equal(result.decision, "allow-with-constraints");
    assert.equal(result.constraints?.max_runtime, 300);
  });

  // ────────────────────────────────
  console.log("\nReceipt Signing & Verification");
  // ────────────────────────────────

  await test("sign and verify a receipt", async () => {
    const agent = await createIdManager();
    const agentEm = new ExecutionManager(agent);

    const intent = await agentEm.createIntent({
      tool: "ls",
      argv: ["ls"],
      cwd: WORKSPACE,
      requested_caps: ["proc.exec:ls"],
    });

    const outcome: ExecOutcome = {
      started: new Date().toISOString(),
      ended: new Date().toISOString(),
      exit_code: 0,
      stdout_hash: "sha256:abc123",
      stderr_hash: "",
    };

    const receipt = await brokerEm.signReceipt(intent, signedPolicy, outcome);
    assert.ok(receipt.broker_signature);
    assert.ok(receipt.intent_hash);
    assert.ok(receipt.policy_hash);
    assert.ok(ExecutionManager.verifyReceipt(receipt, broker.vaultysId));
  });

  await test("reject tampered receipt", async () => {
    const agent = await createIdManager();
    const agentEm = new ExecutionManager(agent);

    const intent = await agentEm.createIntent({
      tool: "echo",
      argv: ["echo", "hello"],
      cwd: WORKSPACE,
      requested_caps: ["proc.exec:echo"],
    });

    const receipt = await brokerEm.signReceipt(intent, signedPolicy, {
      started: new Date().toISOString(),
      ended: new Date().toISOString(),
      exit_code: 0,
    });

    receipt.exec.exit_code = 999; // tamper
    assert.ok(!ExecutionManager.verifyReceipt(receipt, broker.vaultysId));
  });

  // ────────────────────────────────
  console.log("\nSRP Policy Agreement");
  // ────────────────────────────────

  await test("grantPolicy / acceptPolicy via MemoryChannel", async () => {
    const producer = await createIdManager();
    const executor = await createIdManager();

    const producerEm = new ExecutionManager(producer);
    const executorEm = new ExecutionManager(executor);

    const channel = MemoryChannel.createBidirectionnal();
    assert.ok(channel.otherend);

    const [counterpart, result] = await Promise.all([
      producerEm.grantPolicy(channel, samplePolicy),
      executorEm.acceptPolicy(channel.otherend!),
    ]);

    assert.equal(counterpart.did, executor.vaultysId.did);
    assert.equal(result.counterpart.did, producer.vaultysId.did);
    assert.deepStrictEqual(result.policy.scopes, samplePolicy.scopes);
    assert.deepStrictEqual(result.policy.denied, samplePolicy.denied);
  });

  await test("stored policy is retrievable by DID", async () => {
    const producer = await createIdManager();
    const executor = await createIdManager();

    const producerEm = new ExecutionManager(producer);
    const executorEm = new ExecutionManager(executor);

    const channel = MemoryChannel.createBidirectionnal();
    await Promise.all([
      producerEm.grantPolicy(channel, samplePolicy),
      executorEm.acceptPolicy(channel.otherend!),
    ]);

    const stored = executorEm.getPolicy(producer.vaultysId.did);
    assert.ok(stored);
    assert.equal(stored!.counterpartDid, producer.vaultysId.did);
    assert.deepStrictEqual(stored!.policy.scopes, samplePolicy.scopes);
  });

  await test("stored policy certificate is verifiable", async () => {
    const producer = await createIdManager();
    const executor = await createIdManager();

    const producerEm = new ExecutionManager(producer);
    const executorEm = new ExecutionManager(executor);

    const channel = MemoryChannel.createBidirectionnal();
    await Promise.all([
      producerEm.grantPolicy(channel, samplePolicy),
      executorEm.acceptPolicy(channel.otherend!),
    ]);

    const stored = executorEm.getPolicy(producer.vaultysId.did)!;
    const valid = await ExecutionManager.verifyStoredPolicy(stored);
    assert.ok(valid);
  });

  await test("executor can reject a policy via onPolicy callback", async () => {
    const producer = await createIdManager();
    const executor = await createIdManager();

    const producerEm = new ExecutionManager(producer);
    const executorEm = new ExecutionManager(executor);

    const channel = MemoryChannel.createBidirectionnal();

    await assert.rejects(
      () =>
        Promise.all([
          producerEm.grantPolicy(channel, samplePolicy),
          executorEm.acceptPolicy(channel.otherend!, async () => false),
        ]),
      /Policy rejected by executor/,
    );
  });

  // ────────────────────────────────
  console.log("\nPolicy Middleware Integration");
  // ────────────────────────────────

  await test("middleware allows fs.read inside workspace", async () => {
    const server = await createIdManager();

    const middleware = createPolicyMiddleware({
      serverIdManager: server,
      signedPolicy,
      workspaceRoot: WORKSPACE,
      auditDir: TEST_AUDIT_DIR,
    });

    const result = await middleware.enforce(
      "read_file",
      { path: "src/index.ts" },
      async () => "file contents",
    );

    assert.equal(result.decision, "allow");
    assert.equal(result.content[0].text, "file contents");
    assert.ok(result.receipt);
  });

  await test("middleware denies read_file outside workspace via absolute path", async () => {
    const server = await createIdManager();

    const middleware = createPolicyMiddleware({
      serverIdManager: server,
      signedPolicy,
      workspaceRoot: WORKSPACE,
      auditDir: TEST_AUDIT_DIR,
    });

    const result = await middleware.enforce(
      "read_file",
      { path: "/etc/passwd" },
      async () => {
        throw new Error("should not execute");
      },
    );

    assert.equal(result.decision, "deny");
    assert.ok(result.content[0].text.includes("DENIED"));
  });

  await test("middleware allows proc.exec with permitted command", async () => {
    const server = await createIdManager();

    const middleware = createPolicyMiddleware({
      serverIdManager: server,
      signedPolicy,
      workspaceRoot: WORKSPACE,
      auditDir: TEST_AUDIT_DIR,
    });

    const result = await middleware.enforce(
      "run_command",
      { command: "ls -la" },
      async () => "total 42\ndrwxr-xr-x ...",
    );

    assert.equal(result.decision, "allow");
    assert.ok(result.receipt);
  });

  await test("middleware denies proc.exec with forbidden command", async () => {
    const server = await createIdManager();

    const middleware = createPolicyMiddleware({
      serverIdManager: server,
      signedPolicy,
      workspaceRoot: WORKSPACE,
      auditDir: TEST_AUDIT_DIR,
    });

    const result = await middleware.enforce(
      "run_command",
      { command: "rm -rf /" },
      async () => {
        throw new Error("should not execute");
      },
    );

    assert.equal(result.decision, "deny");
  });

  await test("middleware denies shell metacharacters", async () => {
    const server = await createIdManager();

    const middleware = createPolicyMiddleware({
      serverIdManager: server,
      signedPolicy,
      workspaceRoot: WORKSPACE,
      auditDir: TEST_AUDIT_DIR,
    });

    const result = await middleware.enforce(
      "run_command",
      { command: "ls && rm -rf /" },
      async () => {
        throw new Error("should not execute");
      },
    );

    assert.equal(result.decision, "deny");
  });

  await test("middleware receipt is cryptographically verifiable", async () => {
    const server = await createIdManager();

    const middleware = createPolicyMiddleware({
      serverIdManager: server,
      signedPolicy,
      workspaceRoot: WORKSPACE,
      auditDir: TEST_AUDIT_DIR,
    });

    const result = await middleware.enforce(
      "read_file",
      { path: "README.md" },
      async () => "# Hello",
    );

    assert.equal(result.decision, "allow");
    assert.ok(result.receipt);
    assert.ok(ExecutionManager.verifyReceipt(result.receipt!, server.vaultysId));
  });

  // ────────────────────────────────
  console.log("\nTime Bounds");
  // ────────────────────────────────

  await test("deny intent when policy has not started yet", async () => {
    const auth = await createIdManager();
    const agent = await createIdManager();
    const authEm = new ExecutionManager(auth);
    const agentEm = new ExecutionManager(agent);

    const futurePolicy = await authEm.signPolicy({
      ...samplePolicy,
      not_before: Date.now() + 60_000,
    });

    const intent = await agentEm.createIntent({
      tool: "ls",
      argv: ["ls"],
      cwd: WORKSPACE,
      requested_caps: ["proc.exec:ls"],
    });

    const result = brokerEm.evaluateIntent(intent, futurePolicy);
    assert.equal(result.decision, "deny");
    assert.ok(result.denied_caps?.includes("policy:not_yet_valid"));
  });

  await test("deny intent when policy has expired", async () => {
    const auth = await createIdManager();
    const agent = await createIdManager();
    const authEm = new ExecutionManager(auth);
    const agentEm = new ExecutionManager(agent);

    const expiredPolicy = await authEm.signPolicy({
      ...samplePolicy,
      not_before: Date.now() - 120_000,
      not_after: Date.now() - 60_000,
    });

    const intent = await agentEm.createIntent({
      tool: "ls",
      argv: ["ls"],
      cwd: WORKSPACE,
      requested_caps: ["proc.exec:ls"],
    });

    const result = brokerEm.evaluateIntent(intent, expiredPolicy);
    assert.equal(result.decision, "deny");
    assert.ok(result.denied_caps?.includes("policy:expired"));
  });

  // ────────────────────────────────
  // Cleanup
  // ────────────────────────────────
  if (fs.existsSync(TEST_AUDIT_DIR)) {
    fs.rmSync(TEST_AUDIT_DIR, { recursive: true });
  }

  // ────────────────────────────────
  // Summary
  // ────────────────────────────────
  console.log("\n═══════════════════════════════════════════");
  console.log(`  Results: ${passed} passed, ${failed} failed`);
  console.log("═══════════════════════════════════════════\n");

  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
