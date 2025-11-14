import { Buffer } from "buffer/";
import { VaultysId, Challenger, IdManager, MemoryChannel, MemoryStorage } from "../";
import assert from "assert";
import "./shims";
import { createRandomVaultysId } from "./utils";

const generateWot = async (max = 4) => {
  const result: IdManager[] = [];
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
    const bob = await createRandomVaultysId();
    assert.equal(bob.version, 1);
  });
  it("Migrate VaultysId to Version 0", async () => {
    const bob = await createRandomVaultysId();
    bob.toVersion(0);
    assert.equal(bob.version, 0);
  });

  it("Migrate IdManager to Version 0", async () => {
    const vaultysId = await createRandomVaultysId();
    const s = MemoryStorage(() => "");
    const bob = new IdManager(vaultysId, s);
    const wot = await generateWot();

    for (let i = 0; i < wot.length; i++) {
      const jeanjacques = wot[i];
      const channel = MemoryChannel.createBidirectionnal();
      if (!channel.otherend) assert.fail();
      await Promise.all([jeanjacques.askContact(channel), bob.acceptContact(channel.otherend)]);
    }

    bob.migrate(0);
    wot.forEach((jeanjacques) => {
      jeanjacques.migrate(0);
      // console.log(jeanjacques);
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
  }).timeout(5000);
});

describe("Symetric Proof of Relationship - SRG - V0", () => {
  it("Perform Protocol with KeyManager", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
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

  it("Succeed for different vaultysId versions", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2.toVersion(0));
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth", 0);
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    assert.equal(challenger1.toString(), challenger2.toString());
  });
});

describe("Symetric Proof of Relationship - SRG - V1", () => {
  it("Perform Protocol with KeyManager", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
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

  it("Succeed for different vaultysId versions", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1.toVersion(0));
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth", 1);
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    await challenger2.update(challenger1.getCertificate());
  });
});
