import assert from "assert";
import "./shims";
import VaultysId from "../src/VaultysId";
import { randomBytes } from "../src/crypto";
import { Buffer } from "buffer/";
import { HybridManager } from "../src/KeyManager";
import { getDilithiumKeyInfo } from "../src/pqCrypto";

describe("PQC", () => {
  it("serder a VaultytsID secret - software", async () => {
    const vaultysId = await VaultysId.generatePerson("dilithium_ed25519");
    if (!vaultysId) assert.fail("VaultysId creation failed");
    assert.equal(vaultysId.id.length, 2670);
    assert.equal(vaultysId.id.toString("hex").length, 5340);
    assert.equal(vaultysId.id.toString("base64").length, 3560);
    assert.equal(vaultysId.keyManager.signer.publicKey.length, 2624);
    const id2 = VaultysId.fromSecret(vaultysId.getSecret());

    assert.equal(vaultysId.keyManager instanceof HybridManager, true);
    assert.equal(id2.keyManager instanceof HybridManager, true);

    assert.equal(vaultysId.id.toString("base64"), id2.id.toString("base64"));
  });

  it("serder a VaultytsID - software", async () => {
    const vaultysId = await VaultysId.generateOrganization("dilithium_ed25519");
    if (!vaultysId) assert.fail("VaultysId creation failed");
    assert.equal(vaultysId.keyManager.signer.publicKey.length, 2624);
    assert.equal(vaultysId.id.length, 2670);
    const id2 = VaultysId.fromId(vaultysId.id);

    assert.equal(vaultysId.id.toString("hex"), id2.id.toString("hex"));
    assert.equal(vaultysId.keyManager instanceof HybridManager, true);
    assert.equal(id2.keyManager instanceof HybridManager, true);
  });

  it("sign/verify with VaultytsID - software", async () => {
    const vaultysId = await VaultysId.generateMachine("dilithium_ed25519");
    if (!vaultysId) assert.fail("VaultysId creation failed");
    const challenge = randomBytes(32);
    const signature = await vaultysId.signChallenge(challenge);
    assert.equal(vaultysId.verifyChallenge(challenge, signature, false), true);
  });

  it("sign and verify a message", async () => {
    const signer = await HybridManager.generate();
    const id = signer.id;
    const verifier = HybridManager.fromId(id);
    const message = Buffer.from("this is a message to be verified man", "utf-8");
    const signature = await signer.sign(message);
    if (!signature) assert.fail();
    assert.notEqual(signature, null);
    assert.ok(verifier.verify(message, signature));
  });
});
