import assert from "assert";
import "./shims";
import VaultysId from "../src/VaultysId";
import { randomBytes } from "../src/crypto";

describe("PQC", () => {
  it("serder a VaultytsID (PQC)", async () => {
    const vaultysId = await VaultysId.createPQC();
    assert.notEqual(vaultysId, null);
    //console.log(vaultysId);
    assert.equal(vaultysId?.keyManager.signer.publicKey.length, 1312);
    const id2 = VaultysId.fromSecret(vaultysId?.getSecret());

    assert.equal(vaultysId?.id.toString("hex"), id2.id.toString("hex"));
  });

  it("sign/verify with VaultytsID (PQC)", async () => {
    const vaultysId = await VaultysId.createPQC();
    const challenge = randomBytes(32);
    const signature = await vaultysId!.signChallenge(challenge);
    //console.log(signature);
    assert.equal(vaultysId?.verifyChallenge(challenge, signature, false), true);
  });
});
