import assert from "assert";
import Challenger from "../src/Challenger.js";
import SoftCredentials from "../src/SoftCredentials.js";
import VaultysId from "../src/VaultysId.js";

describe("Symetric Proof of Relationship - SRG", () => {
  it("Perform Protocol with KeyManager", async () => {
    const vaultysId1 = await VaultysId.generateMachine();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await VaultysId.generateOrganization();
    const challenger2 = new Challenger(vaultysId2);
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
    const challenger1 = new Challenger(vaultysId1);

    const attestation2 = await navigator.credentials.create(
      SoftCredentials.createRequest(-8),
    );
    const vaultysId2 = await VaultysId.fido2FromAttestation(attestation2);
    const challenger2 = new Challenger(vaultysId2);

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

  it("Fail for liveliness at first round", async () => {
    const attestation1 = await navigator.credentials.create(
      SoftCredentials.createRequest(-7),
    );
    const vaultysId1 = await VaultysId.fido2FromAttestation(attestation1);
    const challenger1 = new Challenger(vaultysId1, 50);
    const vaultysId2 = await VaultysId.generatePerson();
    const challenger2 = new Challenger(vaultysId2, 50);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth");
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.rejects(challenger2.update(challenger1.getCertificate()));
    // challenger2.update(challenger1.getCertificate())
  });

  it("Fail for liveliness at second round", async () => {
    const attestation1 = await navigator.credentials.create(
      SoftCredentials.createRequest(-8),
    );
    const vaultysId1 = await VaultysId.fido2FromAttestation(attestation1);
    const challenger1 = new Challenger(vaultysId1, 50);
    const vaultysId2 = await VaultysId.generateMachine();
    const challenger2 = new Challenger(vaultysId2, 50);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth");
    await challenger2.update(challenger1.getCertificate());
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.rejects(challenger1.update(challenger2.getCertificate()));
  });

  it("Pass for liveliness at third round", async () => {
    const attestation1 = await navigator.credentials.create(
      SoftCredentials.createRequest(-8),
    );
    const vaultysId1 = await VaultysId.fido2FromAttestation(attestation1);
    const challenger1 = new Challenger(vaultysId1, 50);
    const vaultysId2 = await VaultysId.generateOrganization();
    const challenger2 = new Challenger(vaultysId2, 50);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth");
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    await new Promise((resolve) => setTimeout(resolve, 100));
    await challenger2.update(challenger1.getCertificate());

    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
    assert.equal(challenger1.toString(), challenger2.toString());
  });

  it("Pass with time deviation of 5s in the future", async () => {
    const attestation1 = await navigator.credentials.create(
      SoftCredentials.createRequest(-7),
    );
    const vaultysId1 = await VaultysId.fido2FromAttestation(attestation1);
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await VaultysId.generatePerson();
    const challenger2 = new Challenger(vaultysId2);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth");
    challenger1.challenge.timestamp = challenger1.challenge.timestamp + 5000;
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    await new Promise((resolve) => setTimeout(resolve, 100));
    await challenger2.update(challenger1.getCertificate());

    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
    assert.equal(challenger1.toString(), challenger2.toString());
  });

  it("Fail with time deviation of 15s in the future", async () => {
    const attestation1 = await navigator.credentials.create(
      SoftCredentials.createRequest(-8),
    );
    const vaultysId1 = await VaultysId.fido2FromAttestation(attestation1);
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await VaultysId.generateOrganization();
    const challenger2 = new Challenger(vaultysId2);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth");
    challenger1.challenge.timestamp = challenger1.challenge.timestamp + 15000;
    assert.rejects(challenger2.update(challenger1.getCertificate()));
  });
});
