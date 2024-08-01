import Challenger from "../src/Challenger";
import IdManager from "../src/IdManager";
import { MemoryChannel } from "../src/MemoryChannel";
import { MemoryStorage } from "../src/MemoryStorage";
import SoftCredentials from "../src/SoftCredentials";
import VaultysId from "../src/VaultysId";
import assert from "assert";
import "./utils";

const generateWot = async (max = 10) => {
  const result = [];
  for (let i = 0; i < max; i++) {
    const vaultysId = await VaultysId.generatePerson();
    const s = MemoryStorage(() => "");
    const jeanjacques = new IdManager(vaultysId, s);
    result.push(jeanjacques);
  }
  return result;
};

const testCertificate = (rogueCert: Buffer) => {
  try {
    const result = Challenger.deserializeCertificate(rogueCert);
    return result;
  } catch (error) {
    return {
      state: -2,
    };
  }
};

describe("VaultysId Migration", () => {
  it("create VaultysId  with version 1 by default", async () => {
    const bob = await VaultysId.generateMachine();
    assert.equal(bob.version, 1);
  });
  it("Migrate VaultysId to Version 0", async () => {
    const bob = await VaultysId.generatePerson();
    bob.toVersion(0);
    assert.equal(bob.version, 0);
  });

  it("Migrate IdManager to Version 0", async () => {
    const vaultysId = await VaultysId.generatePerson();
    const s = MemoryStorage(() => "");
    const bob = new IdManager(vaultysId, s);
    const wot = await generateWot();

    await Promise.all(
      wot.map(async (jeanjacques) => {
        const channel = MemoryChannel.createBidirectionnal();
        if (!channel.otherend) assert.fail();
        const contacts = await Promise.all([jeanjacques.askContact(channel), bob.acceptContact(channel.otherend)]);
      }),
    );

    bob.migrate(0);
    wot.forEach((jeanjacques) => {
      jeanjacques.migrate(0);
      //console.log(jeanjacques);
      assert.notEqual(bob.getContact(jeanjacques.vaultysId.did), null);
    });

    assert.equal(bob.store.substore("wot").list().length, wot.length);
    assert.equal(bob.store.substore("contacts").list().length, wot.length);
    assert.equal(bob.vaultysId.version, 0);

    bob.migrate(1);
    wot.forEach((jeanjacques) => {
      jeanjacques.migrate(1);
      //console.log(jeanjacques);
      assert.notEqual(bob.getContact(jeanjacques.vaultysId.did), null);
    });
    assert.equal(bob.store.substore("wot").list().length, wot.length);
    assert.equal(bob.store.substore("contacts").list().length, wot.length);
    assert.equal(bob.vaultysId.version, 1);
  });
});

describe("Symetric Proof of Relationship - SRG - V0", () => {
  it("Perform Protocol with KeyManager", async () => {
    const vaultysId1 = await VaultysId.generateMachine();
    const challenger1 = new Challenger(vaultysId1.toVersion(0));
    const vaultysId2 = await VaultysId.generateOrganization();
    const challenger2 = new Challenger(vaultysId2.toVersion(0));
    assert.equal(challenger1.isComplete(), false);
    assert.equal(challenger1.hasFailed(), false);
    challenger1.createChallenge("p2p", "auth", 0);
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
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-ignore
    const vaultysId1 = (await VaultysId.fido2FromAttestation(attestation1)).toVersion(0);
    const challenger1 = new Challenger(vaultysId1);

    const attestation2 = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    // @ts-ignore
    const vaultysId2 = (await VaultysId.fido2FromAttestation(attestation2)).toVersion(0);
    const challenger2 = new Challenger(vaultysId2);

    assert.equal(challenger1.isComplete(), false);
    assert.equal(challenger1.hasFailed(), false);
    challenger1.createChallenge("p2p", "auth", 0);
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    assert.ok(challenger1.isComplete());
    assert.ok(!challenger2.isComplete());
    await challenger2.update(challenger1.getCertificate());
    // SYMETRIC PROOF
    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
    assert.equal(vaultysId1.version, 0);
    assert.equal(vaultysId2.version, 0);
    assert.equal(challenger1.toString(), challenger2.toString());
  });

  it("Fail for different vaultysId versions", async () => {
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-ignore
    const vaultysId1 = await VaultysId.fido2FromAttestation(attestation1);
    const challenger1 = new Challenger(vaultysId1.toVersion(0));
    const vaultysId2 = await VaultysId.generatePerson();
    const challenger2 = new Challenger(vaultysId2);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth", 0);
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());

    try {
      await challenger2.update(challenger1.getCertificate());
    } catch (err: any) {
      assert(err?.message === "The challenge is in an expected state. Received state = '-2', expected state = '2'");
      return;
    }
    assert.fail("The protocol should have failed");
  });
});

describe("Symetric Proof of Relationship - SRG - V1", () => {
  it("Perform Protocol with KeyManager", async () => {
    const vaultysId1 = await VaultysId.generateMachine();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await VaultysId.generateOrganization();
    const challenger2 = new Challenger(vaultysId2);
    assert.equal(challenger1.isComplete(), false);
    assert.equal(challenger1.hasFailed(), false);
    challenger1.createChallenge("p2p", "auth", 1);
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
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-ignore
    const vaultysId1 = await VaultysId.fido2FromAttestation(attestation1);
    const challenger1 = new Challenger(vaultysId1);

    const attestation2 = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    // @ts-ignore
    const vaultysId2 = await VaultysId.fido2FromAttestation(attestation2);
    const challenger2 = new Challenger(vaultysId2);

    assert.equal(challenger1.isComplete(), false);
    assert.equal(challenger1.hasFailed(), false);
    challenger1.createChallenge("p2p", "auth", 1);
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    assert.ok(challenger1.isComplete());
    assert.ok(!challenger2.isComplete());
    await challenger2.update(challenger1.getCertificate());
    // SYMETRIC PROOF
    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
    assert.equal(vaultysId1.version, 1);
    assert.equal(vaultysId2.version, 1);
    assert.equal(challenger1.toString(), challenger2.toString());
  });

  it("Succeed for different vaultysId versions", async () => {
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-ignore
    const vaultysId1 = await VaultysId.fido2FromAttestation(attestation1);
    const challenger1 = new Challenger(vaultysId1.toVersion(0));
    const vaultysId2 = await VaultysId.generatePerson();
    const challenger2 = new Challenger(vaultysId2);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth", 1);
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    await challenger2.update(challenger1.getCertificate());
  });
});
