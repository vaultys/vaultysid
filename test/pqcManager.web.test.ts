import assert from "assert";
import "./shims";
import VaultysId from "../src/VaultysId";
import { randomBytes } from "../src/crypto";

describe("PQC", () => {
  it("serder a VaultytsID secret - software", async () => {
    const vaultysId = await VaultysId.generatePerson(true);
    if (!vaultysId) assert.fail("VaultysId creation failed");
    assert.equal(vaultysId.id.length, 1394);
    assert.equal(vaultysId.id.toString("hex").length, 2788);
    assert.equal(vaultysId.id.toString("base64").length, 1860);
    assert.equal(vaultysId.keyManager.signer.publicKey.length, 1312);
    const id2 = VaultysId.fromSecret(vaultysId.getSecret());

    assert.equal(vaultysId.id.toString("hex"), id2.id.toString("hex"));
  });

  it("serder a VaultytsID - software", async () => {
    const vaultysId = await VaultysId.generateOrganization(true);
    if (!vaultysId) assert.fail("VaultysId creation failed");
    assert.equal(vaultysId.keyManager.signer.publicKey.length, 1312);
    assert.equal(vaultysId.id.length, 1394);
    const id2 = VaultysId.fromId(vaultysId.id);

    assert.equal(vaultysId.id.toString("hex"), id2.id.toString("hex"));
  });

  it("sign/verify with VaultytsID - software", async () => {
    const vaultysId = await VaultysId.generateMachine(true);
    if (!vaultysId) assert.fail("VaultysId creation failed");
    const challenge = randomBytes(32);
    const signature = await vaultysId.signChallenge(challenge);
    assert.equal(vaultysId.verifyChallenge(challenge, signature, false), true);
  });
});
