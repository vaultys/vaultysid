import { encode, decode } from "@msgpack/msgpack";
import { hash, randomBytes } from "../crypto";
import { Buffer } from "buffer/";
import IdManager from "../IdManager";
import VaultysId from "../VaultysId";
import Challenger from "../Challenger";
import { Channel } from "../MemoryChannel";
import { isCapabilityAllowed } from "./ExecutionTaxonomy";
import type {
  ExecutionIntent,
  IntentParams,
  PolicyBundle,
  SignedReceipt,
  ExecutionResult,
  ExecOutcome,
  ExecuteCallback,
  StoredPolicy,
} from "./types";

// ── Helpers ──

function generateJobId(): string {
  const bytes = randomBytes(16);
  const hex = bytes.toString("hex");
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20, 32)].join("-");
}

function serializePolicy(policy: PolicyBundle): Buffer {
  const { signature, ...rest } = policy;
  return Buffer.from(encode(rest));
}

function serializeIntent(intent: ExecutionIntent): Buffer {
  const { signature, ...rest } = intent;
  return Buffer.from(encode(rest));
}

function hashPayload(payload: Buffer): string {
  return hash("sha256", payload).toString("hex");
}

// ── ExecutionManager ──

export default class ExecutionManager {
  idManager: IdManager;

  constructor(idManager: IdManager) {
    this.idManager = idManager;
  }

  // ═══════════════════════════════════════════
  //  Policy Methods (Authority side)
  // ═══════════════════════════════════════════

  /**
   * Sign a policy bundle with the current identity (authority).
   * Returns a new PolicyBundle object that includes the `signature` field.
   */
  async signPolicy(policy: Omit<PolicyBundle, "signature">): Promise<PolicyBundle> {
    const serialized = serializePolicy(policy as PolicyBundle);
    const signature = await this.idManager.vaultysId.signChallenge(serialized);
    return { ...policy, signature };
  }

  /**
   * Verify that a policy bundle was signed by the given authority.
   */
  static verifyPolicy(policy: PolicyBundle, authorityId: VaultysId): boolean {
    if (!policy.signature) return false;
    const serialized = serializePolicy(policy);
    return authorityId.verifyChallenge(serialized, policy.signature, true);
  }

  // ═══════════════════════════════════════════
  //  SRP Policy Agreement
  // ═══════════════════════════════════════════

  /**
   * **Producer side** – propose a policy to the executor via SRP.
   *
   * The policy is serialized into the SRP metadata (pk1 side) so that
   * both parties' signatures cover the policy content. On success the
   * resulting certificate + policy are stored in the "policies" substore,
   * keyed by the executor's DID.
   *
   * @param channel  Communication channel to the executor
   * @param policy   The policy to propose (unsigned — SRP provides the signatures)
   * @param accept   Optional guard to approve/reject the executor
   * @returns The counterpart VaultysId on success
   */
  async grantPolicy(
    channel: Channel,
    policy: Omit<PolicyBundle, "signature">,
    accept?: (contact: VaultysId) => Promise<boolean>,
  ): Promise<VaultysId> {
    const policyJson = JSON.stringify(policy);
    const policyHash = hashPayload(Buffer.from(policyJson, "utf-8"));

    const metadata: Record<string, string> = {
      policy: policyJson,
      policy_hash: policyHash,
    };

    const challenger = await this.idManager.startSRP(channel, "execution", "policy", metadata, accept);

    if (!challenger.isComplete()) {
      throw new Error("Policy SRP handshake failed");
    }

    const counterpart = challenger.getContactId();
    const certificate = challenger.getCertificate();

    // Store the agreed policy
    const stored: StoredPolicy = {
      policy: policy as PolicyBundle,
      certificate,
      counterpartDid: counterpart.did,
      agreedAt: Date.now(),
    };
    this.idManager.store.substore("policies").set(counterpart.did, stored);
    this.idManager.store.save();

    return counterpart;
  }

  /**
   * **Executor side** – accept a policy proposed via SRP.
   *
   * Reads the policy from the SRP metadata (pk1 side), verifies the hash,
   * and on successful completion stores the certificate + policy in the
   * "policies" substore keyed by the producer's DID.
   *
   * @param channel  Communication channel to the producer
   * @param onPolicy Optional callback to inspect/approve the policy before agreeing
   * @param accept   Optional guard to approve/reject the producer identity
   * @returns Object containing the counterpart VaultysId and the agreed policy
   */
  async acceptPolicy(
    channel: Channel,
    onPolicy?: (policy: PolicyBundle, producerId: VaultysId) => Promise<boolean>,
    accept?: (contact: VaultysId) => Promise<boolean>,
  ): Promise<{ counterpart: VaultysId; policy: PolicyBundle }> {
    const challenger = await this.idManager.acceptSRP(channel, "execution", "policy", {}, accept);

    if (!challenger.isComplete()) {
      throw new Error("Policy SRP handshake failed");
    }

    // Extract policy from SRP metadata (pk1 = producer side)
    const metadata = challenger.getContext().metadata;
    const policyJson = metadata?.pk1?.policy;
    const policyHash = metadata?.pk1?.policy_hash;

    if (!policyJson || !policyHash) {
      throw new Error("No policy found in SRP metadata");
    }

    // Verify hash
    const computedHash = hashPayload(Buffer.from(policyJson, "utf-8"));
    if (computedHash !== policyHash) {
      throw new Error("Policy hash mismatch in SRP metadata");
    }

    const policy = JSON.parse(policyJson) as PolicyBundle;
    const counterpart = challenger.getContactId();

    // Let the executor approve the policy content
    if (onPolicy && !(await onPolicy(policy, counterpart))) {
      throw new Error("Policy rejected by executor");
    }

    const certificate = challenger.getCertificate();

    // Store the agreed policy
    const stored: StoredPolicy = {
      policy,
      certificate,
      counterpartDid: counterpart.did,
      agreedAt: Date.now(),
    };
    this.idManager.store.substore("policies").set(counterpart.did, stored);
    this.idManager.store.save();

    return { counterpart, policy };
  }

  // ═══════════════════════════════════════════
  //  Policy Storage Helpers
  // ═══════════════════════════════════════════

  /**
   * Retrieve the agreed policy for a given counterpart DID.
   */
  getPolicy(did: string): StoredPolicy | null {
    return this.idManager.store.substore("policies").get(did) ?? null;
  }

  /**
   * List all agreed policies.
   */
  listPolicies(): StoredPolicy[] {
    const store = this.idManager.store.substore("policies");
    return store.list().map((did) => store.get(did));
  }

  /**
   * Verify that a stored policy's SRP certificate is still valid.
   * This re-checks both parties' signatures on the mutual-auth certificate.
   */
  static async verifyStoredPolicy(stored: StoredPolicy): Promise<boolean> {
    if (!stored.certificate) return false;
    return Challenger.verifyCertificate(Buffer.from(stored.certificate));
  }

  // ═══════════════════════════════════════════
  //  Intent Methods (Agent side)
  // ═══════════════════════════════════════════

  /**
   * Build and sign an execution intent.
   * The intent records the agent's DID, a unique job ID, timestamp, nonce,
   * and the requested operation with its capabilities.
   */
  async createIntent(params: IntentParams): Promise<ExecutionIntent> {
    const intent: ExecutionIntent = {
      job_id: generateJobId(),
      timestamp: Date.now(),
      nonce: randomBytes(16),
      agent_id: this.idManager.vaultysId.did,
      tool: params.tool,
      argv: params.argv,
      cwd: params.cwd,
      env_allowlist: params.env_allowlist ?? [],
      requested_caps: params.requested_caps,
      inputs: params.inputs ?? {},
    };
    const serialized = serializeIntent(intent);
    intent.signature = await this.idManager.vaultysId.signChallenge(serialized);
    return intent;
  }

  /**
   * Verify that an execution intent was signed by the given agent.
   */
  static verifyIntent(intent: ExecutionIntent, agentId: VaultysId): boolean {
    if (!intent.signature) return false;
    const serialized = serializeIntent(intent);
    return agentId.verifyChallenge(serialized, intent.signature, true);
  }

  // ═══════════════════════════════════════════
  //  Policy Evaluation (Broker side)
  // ═══════════════════════════════════════════

  /**
   * Evaluate a signed intent against a policy bundle.
   * Returns allow / deny / allow-with-constraints.
   */
  evaluateIntent(intent: ExecutionIntent, policy: PolicyBundle): ExecutionResult {
    const denied_caps: string[] = [];
    const allowed_caps: string[] = [];

    for (const cap of intent.requested_caps) {
      if (isCapabilityAllowed(cap, policy.scopes, policy.denied)) {
        allowed_caps.push(cap);
      } else {
        denied_caps.push(cap);
      }
    }

    if (denied_caps.length > 0) {
      return { decision: "deny", denied_caps, allowed_caps };
    }

    // Enforce constraints
    const constraints = policy.constraints ?? {};

    if (constraints.no_shell_features) {
      const shellChars = /[|;&`$(){}[\]<>!]/;
      for (const arg of intent.argv) {
        if (shellChars.test(arg)) {
          return {
            decision: "deny",
            denied_caps: ["constraint:no_shell_features"],
            allowed_caps,
            constraints,
          };
        }
      }
    }

    if (Object.keys(constraints).length > 0) {
      return { decision: "allow-with-constraints", allowed_caps, constraints };
    }

    return { decision: "allow", allowed_caps };
  }

  // ═══════════════════════════════════════════
  //  Receipt Methods (Broker side)
  // ═══════════════════════════════════════════

  /**
   * Build and sign an execution receipt.
   */
  async signReceipt(intent: ExecutionIntent, policy: PolicyBundle, outcome: ExecOutcome): Promise<SignedReceipt> {
    const receipt: SignedReceipt = {
      intent_hash: hashPayload(serializeIntent(intent)),
      policy_hash: hashPayload(serializePolicy(policy)),
      sandbox_config_hash: outcome.sandbox_config_hash ?? "",
      exec: {
        started: outcome.started,
        ended: outcome.ended,
        exit_code: outcome.exit_code,
      },
      outputs: {
        stdout_hash: outcome.stdout_hash,
        stderr_hash: outcome.stderr_hash,
      },
      artifacts: outcome.artifacts ?? {},
    };
    const { broker_signature: _, ...unsigned } = receipt;
    const serialized = Buffer.from(encode(unsigned));
    receipt.broker_signature = await this.idManager.vaultysId.signChallenge(serialized);
    return receipt;
  }

  /**
   * Verify that a receipt was signed by the given broker.
   */
  static verifyReceipt(receipt: SignedReceipt, brokerId: VaultysId): boolean {
    if (!receipt.broker_signature) return false;
    const { broker_signature, ...rest } = receipt;
    const serialized = Buffer.from(encode(rest));
    return brokerId.verifyChallenge(serialized, broker_signature, true);
  }

  // ═══════════════════════════════════════════
  //  SRP Integration (Agent ↔ Broker)
  // ═══════════════════════════════════════════

  /**
   * **Agent side** – request execution of an intent.
   *
   * 1. Perform SRP handshake with the broker (agent acts as responder).
   * 2. Send the signed intent + policy over the channel.
   * 3. Receive and return the broker's signed receipt.
   *
   * The policy hash is included in the SRP metadata so it is
   * cryptographically bound to the mutual-auth certificate.
   */
  async requestExecution(
    channel: Channel,
    intent: ExecutionIntent,
    policy: PolicyBundle,
    accept?: (contact: VaultysId) => Promise<boolean>,
  ): Promise<SignedReceipt | null> {
    const policyHash = hashPayload(serializePolicy(policy));
    const intentHash = hashPayload(serializeIntent(intent));

    const challenger = await this.idManager.acceptSRP(channel, "execution", "intent", { policy_hash: policyHash, intent_hash: intentHash }, accept);

    if (challenger.isComplete()) {
      const payload = Buffer.from(encode({ intent, policy }));
      channel.send(payload);

      const response = await channel.receive();
      if (response.length <= 1) return null;

      const receipt = decode(response) as SignedReceipt;
      return receipt;
    }

    return null;
  }

  /**
   * **Broker side** – accept and process execution requests.
   *
   * 1. Perform SRP handshake with the agent (broker acts as initiator).
   * 2. Receive intent + policy from the agent.
   * 3. Verify both signatures (agent on intent, authority on policy).
   * 4. Evaluate the intent against the policy.
   * 5. Delegate actual execution to the `onExecute` callback.
   * 6. Sign and return a receipt.
   *
   * @param authorityId  The VaultysId of the authority who signed the policy.
   * @param onExecute    Pluggable sandbox callback.
   * @param accept       Optional filter invoked during SRP to accept/reject the agent.
   */
  async acceptExecution(
    channel: Channel,
    authorityId: VaultysId,
    onExecute: ExecuteCallback,
    accept?: (contact: VaultysId) => Promise<boolean>,
  ): Promise<SignedReceipt> {
    const challenger = await this.idManager.startSRP(channel, "execution", "intent", {}, accept);

    if (!challenger.isComplete()) {
      channel.send(Buffer.from([0]));
      throw new Error("SRP handshake failed");
    }

    // Receive intent + policy from agent
    const message = await channel.receive();
    if (message.length <= 1) {
      channel.send(Buffer.from([0]));
      throw new Error("Empty execution request");
    }

    const { intent, policy } = decode(message) as {
      intent: ExecutionIntent;
      policy: PolicyBundle;
    };

    // Verify agent identity matches the SRP peer
    const agentId = challenger.getContactId();
    if (!ExecutionManager.verifyIntent(intent, agentId)) {
      channel.send(Buffer.from([0]));
      throw new Error("Intent signature verification failed");
    }

    // Verify policy was signed by the authority
    if (!ExecutionManager.verifyPolicy(policy, authorityId)) {
      channel.send(Buffer.from([0]));
      throw new Error("Policy signature verification failed");
    }

    // Verify metadata binding (policy hash committed during SRP)
    const expectedPolicyHash = hashPayload(serializePolicy(policy));
    const metadata = challenger.getContext().metadata;
    if (metadata?.pk2?.policy_hash && metadata.pk2.policy_hash !== expectedPolicyHash) {
      channel.send(Buffer.from([0]));
      throw new Error("Policy hash mismatch with SRP metadata");
    }

    // Evaluate intent against policy
    const evaluation = this.evaluateIntent(intent, policy);
    if (evaluation.decision === "deny") {
      channel.send(Buffer.from([0]));
      throw new Error(`Intent denied by policy: ${evaluation.denied_caps?.join(", ")}`);
    }

    // Execute via pluggable callback
    const outcome = await onExecute(intent, evaluation);

    // Sign receipt
    const receipt = await this.signReceipt(intent, policy, outcome);

    // Persist receipt
    this.idManager.store.substore("receipts").set(intent.job_id, receipt);
    this.idManager.store.save();

    // Return receipt to agent
    channel.send(Buffer.from(encode(receipt)));
    return receipt;
  }

  // ═══════════════════════════════════════════
  //  Receipt storage helpers
  // ═══════════════════════════════════════════

  listReceipts(): SignedReceipt[] {
    const store = this.idManager.store.substore("receipts");
    return store.list().map((id) => store.get(id));
  }

  getReceipt(jobId: string): SignedReceipt | null {
    return this.idManager.store.substore("receipts").get(jobId) ?? null;
  }
}
