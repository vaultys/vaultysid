import assert from "assert";
import "./shims";
import VaultysId from "../src/VaultysId";
import { randomBytes } from "../src/crypto";
import { Buffer } from "buffer/";
import { PQManager } from "../src/KeyManager";

describe("PQC", () => {
  it("serder a VaultytsID secret - software", async () => {
    const vaultysId = await VaultysId.generatePerson(true);
    if (!vaultysId) assert.fail("VaultysId creation failed");
    assert.equal(vaultysId.id.length, 1998);
    assert.equal(vaultysId.id.toString("hex").length, 3996);
    assert.equal(vaultysId.id.toString("base64").length, 2664);
    assert.equal(vaultysId.keyManager.signer.publicKey.length, 1952);
    const id2 = VaultysId.fromSecret(vaultysId.getSecret());

    assert.equal(vaultysId.id.toString("hex"), id2.id.toString("hex"));
    assert.equal(vaultysId.keyManager instanceof PQManager, true);
    assert.equal(id2.keyManager instanceof PQManager, true);
  });

  it("serder a VaultytsID - software", async () => {
    const vaultysId = await VaultysId.generateOrganization(true);
    if (!vaultysId) assert.fail("VaultysId creation failed");
    assert.equal(vaultysId.keyManager.signer.publicKey.length, 1952);
    assert.equal(vaultysId.id.length, 1998);
    const id2 = VaultysId.fromId(vaultysId.id);

    assert.equal(vaultysId.id.toString("hex"), id2.id.toString("hex"));
    assert.equal(vaultysId.keyManager instanceof PQManager, true);
    assert.equal(id2.keyManager instanceof PQManager, true);
  });

  it("sign/verify with VaultytsID - software", async () => {
    const vaultysId = await VaultysId.generateMachine(true);
    if (!vaultysId) assert.fail("VaultysId creation failed");
    const challenge = randomBytes(32);
    const signature = await vaultysId.signChallenge(challenge);
    assert.equal(vaultysId.verifyChallenge(challenge, signature, false), true);
  });

  it("sign and verify a message", async () => {
    const signer = await PQManager.generate();
    const id = signer.id;
    const verifier = PQManager.fromId(id);
    const message = Buffer.from("this is a message to be verified man", "utf-8");
    const signature = await signer.sign(message);
    if (!signature) assert.fail();
    assert.notEqual(signature, null);
    assert.ok(verifier.verify(message, signature));
  });
});
