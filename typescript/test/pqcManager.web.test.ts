import assert from "assert";
import "./shims";
import VaultysId from "../src/VaultysId";
import { randomBytes } from "../src/crypto";
import { Buffer } from "buffer/";
import { DilithiumManager } from "../src/KeyManager";
import { getDilithiumKeyInfo } from "../src/pqCrypto";

describe("PQC", () => {
  it("serder a VaultytsID secret - software", async () => {
    const vaultysId = await VaultysId.generatePerson("dilithium");
    if (!vaultysId) assert.fail("VaultysId creation failed");
    assert.equal(vaultysId.id.length, 2638);
    assert.equal(vaultysId.id.toString("hex").length, 5276);
    assert.equal(vaultysId.id.toString("base64").length, 3520);
    assert.equal(vaultysId.keyManager.signer.publicKey.length, getDilithiumKeyInfo().publicKeySize);
    const id2 = VaultysId.fromSecret(vaultysId.getSecret());

    assert.equal(vaultysId.id.toString("hex"), id2.id.toString("hex"));
    assert.equal(vaultysId.keyManager instanceof DilithiumManager, true);
    assert.equal(id2.keyManager instanceof DilithiumManager, true);
  });

  it("serder a VaultytsID - software", async () => {
    const vaultysId = await VaultysId.generateOrganization("dilithium");
    if (!vaultysId) assert.fail("VaultysId creation failed");
    assert.equal(vaultysId.keyManager.signer.publicKey.length, 2592);
    assert.equal(vaultysId.id.length, 2638);
    const id2 = VaultysId.fromId(vaultysId.id);

    assert.equal(vaultysId.id.toString("hex"), id2.id.toString("hex"));
    assert.equal(vaultysId.keyManager instanceof DilithiumManager, true);
    assert.equal(id2.keyManager instanceof DilithiumManager, true);
  });

  it("sign/verify with VaultytsID - software", async () => {
    const vaultysId = await VaultysId.generateMachine("dilithium");
    if (!vaultysId) assert.fail("VaultysId creation failed");
    const challenge = randomBytes(32);
    const signature = await vaultysId.signChallenge(challenge);
    assert.equal(vaultysId.verifyChallenge(challenge, signature, false), true);
  });

  it("sign and verify a message", async () => {
    const signer = await DilithiumManager.generate();
    const id = signer.id;
    const verifier = DilithiumManager.fromId(id);
    const message = Buffer.from("this is a message to be verified man", "utf-8");
    const signature = await signer.sign(message);
    if (!signature) assert.fail();
    assert.notEqual(signature, null);
    assert.ok(verifier.verify(message, signature));
  });
});
