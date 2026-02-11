import assert from "assert";
import { IdManager, VaultysId, MemoryChannel, MemoryStorage, Challenger } from "..";
import { ExecutionManager } from "../src/execution";
import type { PolicyBundle, ExecutionIntent, ExecOutcome, StoredPolicy } from "../src/execution";
import { parseCapability, matchScope, isCapabilityAllowed } from "../src/execution";
import "./shims";

// ── Helpers ──

const createMachineIdManager = async () => {
  const algorithms: ("dilithium_ed25519" | "dilithium" | "ed25519")[] = ["dilithium_ed25519", "dilithium", "ed25519"];
  const id = await VaultysId.generateMachine(algorithms[Math.floor(Math.random() * algorithms.length)]);
  const store = MemoryStorage(() => "");
  const manager = new IdManager(id, store);
  manager.setProtocolVersion(1);
  return manager;
};

const samplePolicy: Omit<PolicyBundle, "signature"> = {
  version: "1.0",
  scopes: {
    "fs.write": ["/workspace/**"],
    "fs.read": ["/workspace/**", "/etc/hosts"],
    "scm.net": ["github.com/org/*"],
    "proc.exec.build": ["npm", "pip", "cargo", "go"],
    "net.egress.http": ["api.company.com"],
  },
  denied: ["secrets.*", "pkg.system", "proc.privilege"],
  constraints: {
    max_runtime: 300,
    no_shell_features: true,
  },
};

// ── Taxonomy Tests ──

describe("ExecutionTaxonomy", () => {
  it("parses capability with scope", () => {
    const cap = parseCapability("fs.write:/workspace/src/**");
    assert.equal(cap.category, "fs");
    assert.equal(cap.action, "write");
    assert.equal(cap.scope, "/workspace/src/**");
  });

  it("parses capability without scope", () => {
    const cap = parseCapability("proc.exec.build");
    assert.equal(cap.category, "proc");
    assert.equal(cap.action, "exec.build");
    assert.equal(cap.scope, undefined);
  });

  it("parses wildcard capability", () => {
    const cap = parseCapability("secrets.*");
    assert.equal(cap.category, "secrets");
    assert.equal(cap.action, "*");
  });

  it("matches glob scopes", () => {
    assert.ok(matchScope("/workspace/**", "/workspace/src/index.ts"));
    assert.ok(matchScope("/workspace/**", "/workspace/deep/nested/file.ts"));
    assert.ok(!matchScope("/workspace/**", "/etc/passwd"));
    assert.ok(matchScope("github.com/org/*", "github.com/org/repo"));
    assert.ok(!matchScope("github.com/org/*", "github.com/other/repo"));
  });

  it("allows valid capabilities", () => {
    assert.ok(isCapabilityAllowed("fs.write:/workspace/src/file.ts", samplePolicy.scopes, samplePolicy.denied));
    assert.ok(isCapabilityAllowed("fs.read:/workspace/README.md", samplePolicy.scopes, samplePolicy.denied));
    assert.ok(isCapabilityAllowed("scm.net:github.com/org/repo", samplePolicy.scopes, samplePolicy.denied));
  });

  it("denies denied capabilities", () => {
    assert.ok(!isCapabilityAllowed("secrets.read", samplePolicy.scopes, samplePolicy.denied));
    assert.ok(!isCapabilityAllowed("secrets.write", samplePolicy.scopes, samplePolicy.denied));
    assert.ok(!isCapabilityAllowed("pkg.system", samplePolicy.scopes, samplePolicy.denied));
    assert.ok(!isCapabilityAllowed("proc.privilege", samplePolicy.scopes, samplePolicy.denied));
  });

  it("denies capabilities not in scopes", () => {
    assert.ok(!isCapabilityAllowed("fs.delete:/workspace/file.ts", samplePolicy.scopes, samplePolicy.denied));
    assert.ok(!isCapabilityAllowed("net.egress.dns:evil.com", samplePolicy.scopes, samplePolicy.denied));
  });

  it("denies out-of-scope paths", () => {
    assert.ok(!isCapabilityAllowed("fs.write:/etc/passwd", samplePolicy.scopes, samplePolicy.denied));
    assert.ok(!isCapabilityAllowed("scm.net:gitlab.com/org/repo", samplePolicy.scopes, samplePolicy.denied));
  });
});

// ── Policy Signing Tests ──

describe("ExecutionManager – Policy", () => {
  it("signs and verifies a policy", async () => {
    const authority = await createMachineIdManager();
    const em = new ExecutionManager(authority);

    const signed = await em.signPolicy(samplePolicy);
    assert.ok(signed.signature);
    assert.ok(ExecutionManager.verifyPolicy(signed, authority.vaultysId));
  });

  it("rejects a tampered policy", async () => {
    const authority = await createMachineIdManager();
    const em = new ExecutionManager(authority);

    const signed = await em.signPolicy(samplePolicy);
    signed.version = "2.0"; // tamper
    assert.ok(!ExecutionManager.verifyPolicy(signed, authority.vaultysId));
  });

  it("rejects a policy signed by a different authority", async () => {
    const authority1 = await createMachineIdManager();
    const authority2 = await createMachineIdManager();
    const em = new ExecutionManager(authority1);

    const signed = await em.signPolicy(samplePolicy);
    assert.ok(!ExecutionManager.verifyPolicy(signed, authority2.vaultysId));
  });
});

// ── Intent Signing Tests ──

describe("ExecutionManager – Intent", () => {
  it("creates and verifies an intent", async () => {
    const agent = await createMachineIdManager();
    const em = new ExecutionManager(agent);

    const intent = await em.createIntent({
      tool: "git",
      argv: ["clone", "https://github.com/org/repo"],
      cwd: "/workspace",
      requested_caps: ["scm.net:github.com/org/repo", "fs.write:/workspace/**"],
    });

    assert.ok(intent.signature);
    assert.ok(intent.job_id);
    assert.ok(intent.nonce);
    assert.equal(intent.agent_id, agent.vaultysId.did);
    assert.ok(ExecutionManager.verifyIntent(intent, agent.vaultysId));
  });

  it("rejects a tampered intent", async () => {
    const agent = await createMachineIdManager();
    const em = new ExecutionManager(agent);

    const intent = await em.createIntent({
      tool: "git",
      argv: ["clone", "https://github.com/org/repo"],
      cwd: "/workspace",
      requested_caps: ["scm.net:github.com/org/repo"],
    });
    //console.log(intent);
    intent.tool = "rm"; // tamper
    assert.ok(!ExecutionManager.verifyIntent(intent, agent.vaultysId));
  });

  it("rejects intent signed by a different agent", async () => {
    const agent1 = await createMachineIdManager();
    const agent2 = await createMachineIdManager();
    const em = new ExecutionManager(agent1);

    const intent = await em.createIntent({
      tool: "git",
      argv: ["clone", "https://github.com/org/repo"],
      cwd: "/workspace",
      requested_caps: ["scm.net:github.com/org/repo"],
    });

    assert.ok(!ExecutionManager.verifyIntent(intent, agent2.vaultysId));
  });
});

// ── Policy Evaluation Tests ──

describe("ExecutionManager – Evaluation", () => {
  let broker: IdManager;
  let em: ExecutionManager;
  let signedPolicy: PolicyBundle;

  before(async () => {
    const authority = await createMachineIdManager();
    broker = await createMachineIdManager();
    em = new ExecutionManager(broker);
    const authorityEm = new ExecutionManager(authority);
    signedPolicy = await authorityEm.signPolicy(samplePolicy);
  });

  it("allows a valid intent", async () => {
    const agentManager = await createMachineIdManager();
    const agentEm = new ExecutionManager(agentManager);

    const intent = await agentEm.createIntent({
      tool: "npm",
      argv: ["install"],
      cwd: "/workspace",
      requested_caps: ["fs.write:/workspace/node_modules/pkg", "proc.exec.build"],
    });

    const result = em.evaluateIntent(intent, signedPolicy);
    assert.notEqual(result.decision, "deny");
  });

  it("denies an intent requesting secrets", async () => {
    const agentManager = await createMachineIdManager();
    const agentEm = new ExecutionManager(agentManager);

    const intent = await agentEm.createIntent({
      tool: "vault",
      argv: ["read", "secret/data"],
      cwd: "/workspace",
      requested_caps: ["secrets.read"],
    });

    const result = em.evaluateIntent(intent, signedPolicy);
    assert.equal(result.decision, "deny");
    assert.ok(result.denied_caps?.includes("secrets.read"));
  });

  it("denies an intent with shell metacharacters when no_shell_features is set", async () => {
    const agentManager = await createMachineIdManager();
    const agentEm = new ExecutionManager(agentManager);

    const intent = await agentEm.createIntent({
      tool: "npm",
      argv: ["run", "build", "&&", "rm", "-rf", "/"],
      cwd: "/workspace",
      requested_caps: ["proc.exec.build"],
    });

    const result = em.evaluateIntent(intent, signedPolicy);
    assert.equal(result.decision, "deny");
  });

  it("returns allow-with-constraints when constraints exist", async () => {
    const agentManager = await createMachineIdManager();
    const agentEm = new ExecutionManager(agentManager);

    const intent = await agentEm.createIntent({
      tool: "npm",
      argv: ["install"],
      cwd: "/workspace",
      requested_caps: ["proc.exec.build"],
    });

    const result = em.evaluateIntent(intent, signedPolicy);
    assert.equal(result.decision, "allow-with-constraints");
    assert.equal(result.constraints?.max_runtime, 300);
  });
});

// ── Receipt Tests ──

describe("ExecutionManager – Receipt", () => {
  it("signs and verifies a receipt", async () => {
    const broker = await createMachineIdManager();
    const brokerEm = new ExecutionManager(broker);

    const agent = await createMachineIdManager();
    const agentEm = new ExecutionManager(agent);
    const authority = await createMachineIdManager();
    const authorityEm = new ExecutionManager(authority);

    const policy = await authorityEm.signPolicy(samplePolicy);
    const intent = await agentEm.createIntent({
      tool: "npm",
      argv: ["install"],
      cwd: "/workspace",
      requested_caps: ["proc.exec.build"],
    });

    const outcome: ExecOutcome = {
      started: new Date().toISOString(),
      ended: new Date().toISOString(),
      exit_code: 0,
      stdout_hash: "abc123",
      stderr_hash: "",
    };

    const receipt = await brokerEm.signReceipt(intent, policy, outcome);
    assert.ok(receipt.broker_signature);
    assert.ok(receipt.intent_hash);
    assert.ok(receipt.policy_hash);
    assert.ok(ExecutionManager.verifyReceipt(receipt, broker.vaultysId));
  });

  it("rejects a tampered receipt", async () => {
    const broker = await createMachineIdManager();
    const brokerEm = new ExecutionManager(broker);
    const agent = await createMachineIdManager();
    const agentEm = new ExecutionManager(agent);
    const authority = await createMachineIdManager();
    const authorityEm = new ExecutionManager(authority);

    const policy = await authorityEm.signPolicy(samplePolicy);
    const intent = await agentEm.createIntent({
      tool: "npm",
      argv: ["install"],
      cwd: "/workspace",
      requested_caps: ["proc.exec.build"],
    });

    const receipt = await brokerEm.signReceipt(intent, policy, {
      started: new Date().toISOString(),
      ended: new Date().toISOString(),
      exit_code: 0,
    });

    receipt.exec.exit_code = 1; // tamper
    assert.ok(!ExecutionManager.verifyReceipt(receipt, broker.vaultysId));
  });
});

// ── Full SRP Round-Trip ──

describe("ExecutionManager – SRP Round-Trip", () => {
  it("agent requests execution, broker accepts and returns receipt", async () => {
    const agent = await createMachineIdManager();
    const broker = await createMachineIdManager();
    const authority = await createMachineIdManager();

    const agentEm = new ExecutionManager(agent);
    const brokerEm = new ExecutionManager(broker);
    const authorityEm = new ExecutionManager(authority);

    const policy = await authorityEm.signPolicy(samplePolicy);
    const intent = await agentEm.createIntent({
      tool: "npm",
      argv: ["install"],
      cwd: "/workspace",
      requested_caps: ["proc.exec.build", "fs.write:/workspace/node_modules/pkg"],
    });

    const channel = MemoryChannel.createBidirectionnal();

    const mockExecutor = async (receivedIntent: ExecutionIntent) => {
      return {
        started: new Date().toISOString(),
        ended: new Date().toISOString(),
        exit_code: 0,
        stdout_hash: "sha256:stdout_hash",
        stderr_hash: "sha256:stderr_hash",
      } as ExecOutcome;
    };

    const [receipt, brokerReceipt] = await Promise.all([
      agentEm.requestExecution(channel.otherend!, intent, policy),
      brokerEm.acceptExecution(channel, authority.vaultysId, mockExecutor),
    ]);

    // Both sides should agree on the receipt
    assert.ok(receipt);
    assert.ok(brokerReceipt);
    assert.equal(receipt!.intent_hash, brokerReceipt.intent_hash);
    assert.equal(receipt!.policy_hash, brokerReceipt.policy_hash);
    assert.equal(receipt!.exec.exit_code, 0);

    // Receipt should be verifiable
    assert.ok(ExecutionManager.verifyReceipt(brokerReceipt, broker.vaultysId));

    // Receipt should be stored
    const stored = brokerEm.getReceipt(intent.job_id);
    assert.ok(stored);

    const list = brokerEm.listReceipts();
    assert.equal(list.length, 1);
  });

  it("broker rejects intent with denied capabilities", async () => {
    const agent = await createMachineIdManager();
    const broker = await createMachineIdManager();
    const authority = await createMachineIdManager();

    const agentEm = new ExecutionManager(agent);
    const brokerEm = new ExecutionManager(broker);
    const authorityEm = new ExecutionManager(authority);

    const policy = await authorityEm.signPolicy(samplePolicy);
    const intent = await agentEm.createIntent({
      tool: "vault",
      argv: ["read", "secret/key"],
      cwd: "/workspace",
      requested_caps: ["secrets.read"],
    });

    const channel = MemoryChannel.createBidirectionnal();

    const mockExecutor = async () => {
      throw new Error("Should not be called");
    };

    await assert.rejects(
      () =>
        Promise.all([
          agentEm.requestExecution(channel.otherend!, intent, policy),
          brokerEm.acceptExecution(channel, authority.vaultysId, mockExecutor),
        ]),
      /denied by policy/,
    );
  });

  it("broker rejects intent with bad policy signature", async () => {
    const agent = await createMachineIdManager();
    const broker = await createMachineIdManager();
    const authority = await createMachineIdManager();
    const fakeAuthority = await createMachineIdManager();

    const agentEm = new ExecutionManager(agent);
    const brokerEm = new ExecutionManager(broker);
    const fakeAuthorityEm = new ExecutionManager(fakeAuthority);

    // Policy signed by fake authority, but broker expects real authority
    const policy = await fakeAuthorityEm.signPolicy(samplePolicy);
    const intent = await agentEm.createIntent({
      tool: "npm",
      argv: ["install"],
      cwd: "/workspace",
      requested_caps: ["proc.exec.build"],
    });

    const channel = MemoryChannel.createBidirectionnal();

    const mockExecutor = async () => {
      throw new Error("Should not be called");
    };

    await assert.rejects(
      () =>
        Promise.all([
          agentEm.requestExecution(channel.otherend!, intent, policy),
          brokerEm.acceptExecution(channel, authority.vaultysId, mockExecutor),
        ]),
      /Policy signature verification failed/,
    );
  });
});

// ── SRP Policy Agreement ──

describe("ExecutionManager – SRP Policy Agreement", () => {
  it("producer grants policy to executor via SRP, both sides store it", async () => {
    const producer = await createMachineIdManager();
    const executor = await createMachineIdManager();

    const producerEm = new ExecutionManager(producer);
    const executorEm = new ExecutionManager(executor);

    const channel = MemoryChannel.createBidirectionnal();

    const [counterpart, result] = await Promise.all([
      producerEm.grantPolicy(channel, samplePolicy),
      executorEm.acceptPolicy(channel.otherend!),
    ]);

    // Producer sees the executor
    assert.equal(counterpart.did, executor.vaultysId.did);

    // Executor sees the producer and the policy
    assert.equal(result.counterpart.did, producer.vaultysId.did);
    assert.equal(result.policy.version, samplePolicy.version);
    assert.deepStrictEqual(result.policy.scopes, samplePolicy.scopes);
    assert.deepStrictEqual(result.policy.denied, samplePolicy.denied);
    assert.deepStrictEqual(result.policy.constraints, samplePolicy.constraints);
  });

  it("stores policies in the 'policies' substore, retrievable by DID", async () => {
    const producer = await createMachineIdManager();
    const executor = await createMachineIdManager();

    const producerEm = new ExecutionManager(producer);
    const executorEm = new ExecutionManager(executor);

    const channel = MemoryChannel.createBidirectionnal();

    await Promise.all([
      producerEm.grantPolicy(channel, samplePolicy),
      executorEm.acceptPolicy(channel.otherend!),
    ]);

    // Producer side: stored under executor's DID
    const producerStored = producerEm.getPolicy(executor.vaultysId.did);
    assert.ok(producerStored);
    assert.equal(producerStored!.counterpartDid, executor.vaultysId.did);
    assert.deepStrictEqual(producerStored!.policy.scopes, samplePolicy.scopes);
    assert.ok(producerStored!.certificate);
    assert.ok(producerStored!.agreedAt > 0);

    // Executor side: stored under producer's DID
    const executorStored = executorEm.getPolicy(producer.vaultysId.did);
    assert.ok(executorStored);
    assert.equal(executorStored!.counterpartDid, producer.vaultysId.did);
    assert.deepStrictEqual(executorStored!.policy.denied, samplePolicy.denied);
  });

  it("listPolicies returns all stored policies", async () => {
    const producer1 = await createMachineIdManager();
    const producer2 = await createMachineIdManager();
    const executor = await createMachineIdManager();

    const producer1Em = new ExecutionManager(producer1);
    const producer2Em = new ExecutionManager(producer2);
    const executorEm = new ExecutionManager(executor);

    // Agree with producer1
    const ch1 = MemoryChannel.createBidirectionnal();
    await Promise.all([
      producer1Em.grantPolicy(ch1, samplePolicy),
      executorEm.acceptPolicy(ch1.otherend!),
    ]);

    // Agree with producer2 (different policy)
    const restrictedPolicy = {
      ...samplePolicy,
      version: "2.0",
      denied: ["secrets.*", "pkg.system", "proc.privilege", "net.egress.http"],
    };
    const ch2 = MemoryChannel.createBidirectionnal();
    await Promise.all([
      producer2Em.grantPolicy(ch2, restrictedPolicy),
      executorEm.acceptPolicy(ch2.otherend!),
    ]);

    const policies = executorEm.listPolicies();
    assert.equal(policies.length, 2);
    const dids = policies.map((p) => p.counterpartDid).sort();
    const expected = [producer1.vaultysId.did, producer2.vaultysId.did].sort();
    assert.deepStrictEqual(dids, expected);
  });

  it("verifyStoredPolicy confirms the SRP certificate is valid", async () => {
    const producer = await createMachineIdManager();
    const executor = await createMachineIdManager();

    const producerEm = new ExecutionManager(producer);
    const executorEm = new ExecutionManager(executor);

    const channel = MemoryChannel.createBidirectionnal();

    await Promise.all([
      producerEm.grantPolicy(channel, samplePolicy),
      executorEm.acceptPolicy(channel.otherend!),
    ]);

    const stored = executorEm.getPolicy(producer.vaultysId.did)!;
    assert.ok(stored);

    // Certificate should verify (both signatures valid)
    const valid = await ExecutionManager.verifyStoredPolicy(stored);
    assert.ok(valid);

    // Tamper with the certificate → should fail
    const tampered = { ...stored, certificate: Buffer.from([0, 1, 2, 3]) };
    let failed = false;
    try {
      const result = await ExecutionManager.verifyStoredPolicy(tampered);
      failed = !result;
    } catch {
      failed = true;
    }
    assert.ok(failed, "Tampered certificate should not verify");
  });

  it("executor can reject a policy via onPolicy callback", async () => {
    const producer = await createMachineIdManager();
    const executor = await createMachineIdManager();

    const producerEm = new ExecutionManager(producer);
    const executorEm = new ExecutionManager(executor);

    const channel = MemoryChannel.createBidirectionnal();

    await assert.rejects(
      () =>
        Promise.all([
          producerEm.grantPolicy(channel, samplePolicy),
          executorEm.acceptPolicy(
            channel.otherend!,
            async (policy) => {
              // Reject if secrets are not denied
              return false;
            },
          ),
        ]),
      /Policy rejected by executor/,
    );

    // Nothing should be stored on the executor side
    const stored = executorEm.getPolicy(producer.vaultysId.did);
    assert.equal(stored, null);
  });

  it("executor can filter the producer identity via accept callback", async () => {
    const producer = await createMachineIdManager();
    const executor = await createMachineIdManager();

    const producerEm = new ExecutionManager(producer);
    const executorEm = new ExecutionManager(executor);

    const channel = MemoryChannel.createBidirectionnal();

    await assert.rejects(
      () =>
        Promise.all([
          producerEm.grantPolicy(channel, samplePolicy),
          executorEm.acceptPolicy(
            channel.otherend!,
            undefined,
            async () => false, // reject the producer identity
          ),
        ]),
      /refused/i,
    );
  });

  it("policy content is cryptographically bound to SRP metadata", async () => {
    const producer = await createMachineIdManager();
    const executor = await createMachineIdManager();

    const producerEm = new ExecutionManager(producer);
    const executorEm = new ExecutionManager(executor);

    const channel = MemoryChannel.createBidirectionnal();

    const [, result] = await Promise.all([
      producerEm.grantPolicy(channel, samplePolicy),
      executorEm.acceptPolicy(channel.otherend!),
    ]);

    // The stored certificate is a valid SRP certificate
    const cert = Challenger.deserializeCertificate(
      executorEm.getPolicy(producer.vaultysId.did)!.certificate,
    );
    assert.equal(cert.protocol, "execution");
    assert.equal(cert.service, "policy");

    // The metadata contains the policy hash
    assert.ok(cert.metadata?.pk1?.policy_hash);
    assert.ok(cert.metadata?.pk1?.policy);
  });
});
