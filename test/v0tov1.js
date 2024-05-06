
import Challenger from "../src/Challenger";
import SoftCredentials from "../src/SoftCredentials";
import VaultysId from "../src/VaultysId";
import assert from "assert";

// nodejs polyfill
global.navigator = {
  credentials: SoftCredentials,
};
global.atob = (str) => Buffer.from(str, "base64").toString("latin1");
global.btoa = (str) => Buffer.from(str, "latin1").toString("base64");

global.CredentialUserInteractionRequest = () => global.CredentialUserInteractionRequested++


const testCertificate = (rogueCert) => {
  try {
    const result = Challenger.deserializeCertificate(rogueCert);
    return result;
  } catch (error) {
    return {
      state: -2
    }
  }
}

describe("Symetric Proof of Relationship - SRG", () => {
  it("Perform Protocol with KeyManager", async () => {
    const vaultysId1 = await VaultysId.generateMachine();
    const challenger1 = new Challenger(vaultysId1.toVersion(0));
    const vaultysId2 = await VaultysId.generateOrganization();
    const challenger2 = new Challenger(vaultysId2.toVersion(0));
    assert.equal(challenger1.isComplete(), false);
    assert.equal(challenger1.hasFailed(), false);
    challenger1.createChallenge("p2p", "auth");
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    assert.ok(challenger1.isComplete());
    assert.ok(!challenger2.isComplete());
    await challenger2.update(challenger1.getCertificate());
    // SYMETRIC PROOF
    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
    assert.equal(challenger1.toString(), challenger2.toString());
  });

  it("Perform Protocol with Fido2Manager", async () => {
    const attestation1 = await navigator.credentials.create(
      SoftCredentials.createRequest(-7),
    );
    const vaultysId1 = await VaultysId.fido2FromAttestation(attestation1);
    const challenger1 = new Challenger(vaultysId1.toVersion(0));

    const attestation2 = await navigator.credentials.create(
      SoftCredentials.createRequest(-8),
    );
    const vaultysId2 = await VaultysId.fido2FromAttestation(attestation2);
    const challenger2 = new Challenger(vaultysId2.toVersion(0));

    assert.equal(challenger1.isComplete(), false);
    assert.equal(challenger1.hasFailed(), false);
    challenger1.createChallenge("p2p", "auth");
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    assert.ok(challenger1.isComplete());
    assert.ok(!challenger2.isComplete());
    await challenger2.update(challenger1.getCertificate());
    // SYMETRIC PROOF
    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
    console.log(vaultysId1.version)
    assert.equal(vaultysId1.version, 0);
    assert.equal(vaultysId2.version, 0);
    assert.equal(challenger1.toString(), challenger2.toString());
  });

  it("Fail for mismatch versioning", async () => {
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    const vaultysId1 = await VaultysId.fido2FromAttestation(attestation1);
    const challenger1 = new Challenger(vaultysId1.toVersion(0));
    const vaultysId2 = await VaultysId.generatePerson();
    const challenger2 = new Challenger(vaultysId2);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth");
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    await assert.rejects(challenger2.update(challenger1.getCertificate()), {
      name: "Error",
      message: "The challenge is in an expected state. Received state = '-2', expected state = '2'"
    });
  });
});
