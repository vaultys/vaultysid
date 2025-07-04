import assert from "assert";
import "./shims";
import VaultysId from "../src/VaultysId";
import { randomBytes } from "../src/crypto";
import { Fido2Manager } from "../src/KeyManager";

describe("PQC", () => {
  it("serder a VaultytsID secret - webauthn", async () => {
    const vaultysId = await VaultysId.createPQC();
    if (!vaultysId) assert.fail("VaultysId creation failed");
    assert.equal(vaultysId.id.length, 2012);
    assert.equal(vaultysId.id.toString("hex").length, 4024);
    assert.equal(vaultysId.id.toString("base64").length, 2684);
    assert.equal(vaultysId.keyManager.signer.publicKey.length, 1952);
    assert.equal((vaultysId.keyManager as Fido2Manager).ckey.length, 1966);
    const id2 = VaultysId.fromSecret(vaultysId.getSecret());

    assert.equal(vaultysId.id.toString("hex"), id2.id.toString("hex"));
    assert.equal(vaultysId.keyManager instanceof Fido2Manager, true);
    assert.equal(id2.keyManager instanceof Fido2Manager, true);
  });

  it("serder a VaultytsID - webauthn", async () => {
    const vaultysId = await VaultysId.createPQC();
    if (!vaultysId) assert.fail("VaultysId creation failed");
    assert.equal(vaultysId.keyManager.signer.publicKey.length, 1952);
    assert.equal((vaultysId.keyManager as Fido2Manager).ckey.length, 1966);
    assert.equal(vaultysId.id.length, 2012);
    const id2 = VaultysId.fromId(vaultysId.id);
    assert.equal((id2.keyManager as Fido2Manager).ckey.length, 1966);

    assert.equal(vaultysId.id.toString("hex"), id2.id.toString("hex"));
    assert.equal(vaultysId.keyManager instanceof Fido2Manager, true);
    assert.equal(id2.keyManager instanceof Fido2Manager, true);
  });

  it("sign/verify with VaultytsID - webauthn", async () => {
    const vaultysId = await VaultysId.createPQC();
    const challenge = randomBytes(32);
    if (!vaultysId) assert.fail("VaultysId creation failed");
    const signature = await vaultysId.signChallenge(challenge);
    //console.log(signature);
    assert.equal(vaultysId.verifyChallenge(challenge, signature, false), true);
  });
});
