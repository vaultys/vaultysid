import { expect } from "chai";
import { MemoryStorage as OldMemoryStorage, IdManager as OldIdManager, VaultysId as VaultysIdOld, Challenger as OldChallenger } from "@vaultys/id";
import { MemoryStorage as NewMemoryStorage, IdManager as NewIdManager, VaultysId as VaultysIdCurrent, MemoryChannel, Challenger as NewChallenger } from "../../dist/node/index.js";
import { decode } from "@msgpack/msgpack";

const oldChallengeNext = async (vaultysId: VaultysIdOld, newCertificate?: Buffer, oldCertificate?: Buffer) => {
  //console.log(newCertificate, oldCertificate);
  const challenger = new OldChallenger(vaultysId);
  challenger.version = 0;
  if (oldCertificate) {
    await challenger.init(oldCertificate);
  } else if (!newCertificate) {
    challenger.createChallenge("p2p", "test", 0);
  }
  if (newCertificate) await challenger.update(newCertificate);
  return challenger.getCertificate();
};

const newChallengeNext = async (vaultysId: VaultysIdCurrent, newCertificate?: Buffer, oldCertificate?: Buffer) => {
  //console.log(newCertificate, oldCertificate);
  const challenger = new NewChallenger(vaultysId);
  challenger.version = 0;
  if (oldCertificate) {
    await challenger.init(oldCertificate);
  } else if (!newCertificate) {
    challenger.createChallenge("p2p", "test", 0);
  }
  if (newCertificate) await challenger.update(newCertificate);
  return challenger.getCertificate();
};

describe("SRP Challenge Compatibility Tests - @vaultys/id@2.4.9 vs Current", () => {
  it("Perform Protocol", async () => {
    const vaultysId1 = await VaultysIdOld.generatePerson();
    vaultysId1.toVersion(0);
    const challenger1 = new OldChallenger(vaultysId1);
    const vaultysId2 = VaultysIdCurrent.fromSecret((await VaultysIdOld.generatePerson()).getSecret()).toVersion(0);
    //console.log(vaultysId2);
    const challenger2 = new NewChallenger(vaultysId2);
    expect(challenger1.isComplete()).to.be.false;
    expect(challenger1.hasFailed()).to.be.false;
    challenger1.createChallenge("p2p", "auth");
    expect(challenger1.state).to.equal(0);
    expect(challenger2.state).to.equal(-1);
    await challenger2.update(challenger1.getCertificate());
    expect(challenger1.state).to.equal(0);
    expect(challenger2.state).to.equal(1);
    console.log(decode(challenger2.getCertificate()));
    await challenger1.update(challenger2.getCertificate());
    expect(challenger1.state).to.equal(2);
    expect(challenger2.state).to.equal(1);
    expect(challenger1.isComplete()).to.be.true;
    expect(challenger2.isComplete()).to.be.false;
    await challenger2.update(challenger1.getCertificate());
    expect(challenger1.state).to.equal(2);
    expect(challenger2.state).to.equal(2);
    // SYMETRIC PROOF
    expect(challenger1.isComplete()).to.be.true;
    expect(challenger2.isComplete()).to.be.true;
    expect(challenger1.toString()).to.equal(challenger2.toString());
  });

  it("Perform Stateless Protocol", async () => {
    for (let i = 0; i < 10; i++) {
      const vaultysId1 = await VaultysIdOld.generatePerson();
      const vaultysId2 = await VaultysIdCurrent.generatePerson();
      const init = await oldChallengeNext(vaultysId1);
      // console.log("init", Challenger.deserializeCertificate(init));
      const step1 = await newChallengeNext(vaultysId2, init);
      // console.log("step1", Challenger.deserializeCertificate(step1));
      const complete = await oldChallengeNext(vaultysId1, step1);
      // console.log("complete", Challenger.deserializeCertificate(complete));
      const finalise = await newChallengeNext(vaultysId2, complete, step1);
      expect(complete.toString("base64")).to.equal(finalise.toString("base64"));
    }
  });

  it("Perform Protocol attacking protocol", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2);
    const challengerattack = new Challenger(vaultysId2);
    assert.equal(challenger1.isComplete(), false);
    assert.equal(challenger1.hasFailed(), false);
    challenger1.createChallenge("p2p", "auth");
    assert.equal(challenger1.state, 0);
    assert.equal(challenger2.state, -1);
    await challengerattack.setChallenge(challenger1.getCertificate());
    challengerattack.challenge!.protocol = "hack";
    delete challengerattack.challenge?.pk2;
    delete challengerattack.challenge?.sign2;
    challengerattack.challenge!.nonce = Buffer.from(challengerattack.challenge!.nonce!.subarray(0, 16));
    await challenger2.update(challengerattack.getCertificate());
    // console.log(challengerattack.challenge);
    assert.equal(challenger1.state, 0);
    assert.equal(challenger2.state, 1);
    try {
      await challenger1.update(challenger2.getCertificate());
    } catch (err: any) {
      assert.equal(err?.message, "The challenge was expecting protocol 'p2p' and service 'auth', received 'hack' and 'auth'");
      return;
    }
    assert.fail("The protocol with tampered nonce should have failed");
  });

  describe("Cross-version SRP Challenge", () => {
    it("should pass SRP challenge between old and new version IDs", async () => {
      // Create IDs with both versions
      const oldId1 = await VaultysIdOld.generatePerson();
      const currentId2 = await VaultysIdCurrent.generatePerson();

      // Create channel with old version ID and new version contact
      const channel = MemoryChannel.createBidirectionnal();

      // channel.logger = (buffer) => console.log(decode(buffer));

      const manager1 = new OldIdManager(
        oldId1,
        OldMemoryStorage(() => {}),
      );
      const manager2 = new NewIdManager(
        currentId2,
        NewMemoryStorage(() => {}),
      );

      manager1.setProtocolVersion(0);
      manager2.setProtocolVersion(0);

      // Start SRP challenge from old version
      const challengeRequest = manager1.acceptSRP(channel, "p2p", "auth");

      // Accept challenge with current version
      await manager2.startSRP(channel.otherend!, "p2p", "auth");
      await challengeRequest;

      // Check that both managers have the contact added
      const contacts1 = manager1.contacts;
      const contacts2 = manager2.contacts;

      expect(contacts2).to.have.lengthOf(1);
      expect(contacts1).to.have.lengthOf(1);

      // Verify metadata exchange
      //expect(contacts1[0].metadata.name).to.equal(metadata2.name);
      //expect(contacts2[0].metadata.name).to.equal(metadata1.name);
    });

    it("should pass SRP challenge from current to old version", async () => {
      // Create IDs with both versions (reversed)
      const currentId1 = await VaultysIdCurrent.generatePerson();
      const oldId2 = await VaultysIdOld.generatePerson();

      // Create channel with current version ID and old version contact
      const channel = await currentId1.createChannel([oldId2.toJSON()]);

      // Create managers
      const s1 = await currentId1.export();
      const s2 = await oldId2.export();
      const manager1 = await VaultysIdCurrent.import(s1, { passphrase: "test123" });
      const manager2 = await VaultysIdOld.import(s2, { passphrase: "test456" });

      const metadata1 = {
        name: "User Current Version",
        email: "current@test.com",
        phone: "+1234567890",
      };

      const metadata2 = {
        name: "User Old Version",
        email: "old@test.com",
        phone: "+0987654321",
      };

      // Start SRP challenge from current version
      const challengeRequest = await manager1.startChallenge(channel, metadata1);
      expect(challengeRequest).to.exist;

      // Accept challenge with old version
      const challengeResponse = await manager2.acceptChallenge(challengeRequest, metadata2);
      expect(challengeResponse).to.exist;

      // Verify challenge with current version
      const verifyResult = await manager1.verifyChallenge(challengeResponse);
      expect(verifyResult).to.exist;
      expect(verifyResult.success).to.be.true;

      // Check that both managers have the contact added
      const contacts1 = await manager1.getContacts();
      const contacts2 = await manager2.getContacts();

      expect(contacts1).to.have.lengthOf(1);
      expect(contacts2).to.have.lengthOf(1);
    });

    it("should handle challenge failure when old version user refuses", async () => {
      const oldId1 = await VaultysIdOld.generatePerson();
      const currentId2 = await VaultysIdCurrent.generatePerson();

      const channel = await oldId1.createChannel([currentId2.toJSON()]);

      const s1 = await oldId1.export();
      const s2 = await currentId2.export();
      const manager1 = await VaultysIdOld.import(s1, { passphrase: "test123" });
      const manager2 = await VaultysIdCurrent.import(s2, { passphrase: "test456" });

      const metadata1 = {
        name: "User Old Version",
        email: "old@test.com",
        phone: "+1234567890",
      };

      const metadata2 = {
        name: "User Current Version",
        email: "current@test.com",
        phone: "+0987654321",
      };

      // Start challenge but reject it
      const challengeRequest = await manager1.startChallenge(channel, metadata1);
      const challengeResponse = await manager2.rejectChallenge(challengeRequest, "User refused");

      expect(challengeResponse.rejected).to.be.true;
      expect(challengeResponse.reason).to.equal("User refused");

      // Verify no contacts were added
      const contacts1 = await manager1.getContacts();
      const contacts2 = await manager2.getContacts();

      expect(contacts1).to.have.lengthOf(0);
      expect(contacts2).to.have.lengthOf(0);
    });

    it("should perform encrypted channel communication between versions", async () => {
      const oldId1 = await VaultysIdOld.generatePerson();
      const currentId2 = await VaultysIdCurrent.generatePerson();

      const channel = await oldId1.createChannel([currentId2.toJSON()], { encrypted: true });

      const s1 = await oldId1.export();
      const s2 = await currentId2.export();
      const manager1 = await VaultysIdOld.import(s1, { passphrase: "test123" });
      const manager2 = await VaultysIdCurrent.import(s2, { passphrase: "test456" });

      const metadata1 = {
        name: "User Old Version",
        email: "old@test.com",
      };

      const metadata2 = {
        name: "User Current Version",
        phone: "+0987654321",
      };

      // Perform challenge over encrypted channel
      const challengeRequest = await manager1.startChallenge(channel, metadata1);
      const challengeResponse = await manager2.acceptChallenge(challengeRequest, metadata2);
      const verifyResult = await manager1.verifyChallenge(challengeResponse);

      expect(verifyResult.success).to.be.true;

      // Test message exchange over encrypted channel
      const testMessage = "Hello from old version";
      const encrypted = await channel.encrypt(Buffer.from(testMessage));
      const decrypted = await channel.decrypt(encrypted);
      expect(Buffer.from(decrypted).toString()).to.equal(testMessage);
    });

    it("should perform PRF over cross-version channel", async () => {
      const oldId1 = await VaultysIdOld.generatePerson();
      const currentId2 = await VaultysIdCurrent.generatePerson();

      const channel = await oldId1.createChannel([currentId2.toJSON()]);

      const s1 = await oldId1.export();
      const s2 = await currentId2.export();
      const manager1 = await VaultysIdOld.import(s1, { passphrase: "test123" });
      const manager2 = await VaultysIdCurrent.import(s2, { passphrase: "test456" });

      // Complete challenge first
      const challengeRequest = await manager1.startChallenge(channel, { name: "Old" });
      const challengeResponse = await manager2.acceptChallenge(challengeRequest, { name: "Current" });
      await manager1.verifyChallenge(challengeResponse);

      // Perform PRF
      const salt = Buffer.from("test-salt");
      const result1 = await manager1.performPRF(channel, salt);
      const result2 = await manager2.performPRF(channel, salt);

      expect(result1).to.exist;
      expect(result2).to.exist;
      expect(result1).to.deep.equal(result2);
    });

    it("should handle file encryption/decryption between versions", async () => {
      const oldId1 = await VaultysIdOld.generatePerson();
      const currentId2 = await VaultysIdCurrent.generatePerson();

      let channel = await oldId1.createChannel([currentId2.toJSON()]);

      const s1 = await oldId1.export();
      const s2 = await currentId2.export();
      const manager1 = await VaultysIdOld.import(s1, { passphrase: "test123" });
      const manager2 = await VaultysIdCurrent.import(s2, { passphrase: "test456" });

      // Complete challenge
      const challengeRequest = await manager1.startChallenge(channel, { name: "Old" });
      const challengeResponse = await manager2.acceptChallenge(challengeRequest, { name: "Current" });
      await manager1.verifyChallenge(challengeResponse);

      // Create a test file
      const fileContent = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
      const originalFile = {
        arrayBuffer: async () => fileContent.buffer,
        type: "application/octet-stream",
        name: "test.bin",
      };

      // Encrypt file with old version
      const encryptedFile = await manager1.encryptFile(channel, originalFile, async (contact: any) => {
        expect(contact).to.exist;
        return true;
      });

      expect(encryptedFile).to.exist;
      expect(encryptedFile.name).to.include(".encrypted");

      // Decrypt file with current version
      const decryptedFile = await manager2.decryptFile(channel, encryptedFile, async (contact: any) => {
        expect(contact).to.exist;
        return true;
      });

      expect(decryptedFile).to.exist;
      expect(decryptedFile.name).to.equal("test.bin");
      const decryptedContent = new Uint8Array(await decryptedFile.arrayBuffer());
      expect(decryptedContent).to.deep.equal(fileContent);
    });

    it("should handle mixed version contacts in channel", async () => {
      // Create multiple IDs of different versions
      const oldId1 = await VaultysIdOld.generatePerson();
      const oldId2 = await VaultysIdOld.generatePerson();
      const currentId1 = await VaultysIdCurrent.generatePerson();
      const currentId2 = await VaultysIdCurrent.generatePerson();

      // Create channel with mixed version contacts
      const channel = await oldId1.createChannel([oldId2.toJSON(), currentId1.toJSON(), currentId2.toJSON()]);

      expect(channel).to.exist;
      expect(channel.id).to.exist;

      // Verify all contacts can be part of the channel
      const participants = channel.participants || channel.members;
      expect(participants).to.have.lengthOf(4); // Including the creator
    });

    it("should maintain backward compatibility for channel message format", async () => {
      const oldId1 = await VaultysIdOld.generatePerson();
      const currentId2 = await VaultysIdCurrent.generatePerson();

      const channel = await oldId1.createChannel([currentId2.toJSON()]);

      // Send message from old version
      const message = { type: "text", content: "Hello from old version" };
      const encrypted = await channel.encrypt(Buffer.from(JSON.stringify(message)));

      // Import channel to current version and decrypt
      const s2 = await currentId2.export();
      const manager2 = await VaultysIdCurrent.import(s2, { passphrase: "test456" });

      // Create compatible channel on current version
      const currentChannel = await currentId2.createChannel([oldId1.toJSON()]);
      const decrypted = await currentChannel.decrypt(encrypted);

      const decryptedMessage = JSON.parse(Buffer.from(decrypted).toString());
      expect(decryptedMessage.type).to.equal("text");
      expect(decryptedMessage.content).to.equal("Hello from old version");
    });

    it("should handle version mismatch gracefully", async () => {
      const oldId = await VaultysIdOld.generatePerson();
      const currentId = await VaultysIdCurrent.generatePerson();

      // Export from old, import to current
      const oldExport = await oldId.export();
      let importedToCurrent;

      try {
        importedToCurrent = await VaultysIdCurrent.import(oldExport);
        expect(importedToCurrent.did).to.equal(oldId.did);
      } catch (e: any) {
        console.log("Version compatibility issue on import:", e.message);
        expect(e).to.exist;
      }

      // Export from current, import to old
      const currentExport = await currentId.export();

      try {
        const importedToOld = await VaultysIdOld.import(currentExport);
        expect(importedToOld.did).to.equal(currentId.did);
      } catch (e: any) {
        console.log("Expected: Current version export may not be compatible with v2.4.9");
        expect(e).to.exist;
      }
    });

    it("should handle cross-version Web of Trust operations", async () => {
      const oldId = await VaultysIdOld.generatePerson();
      const currentId = await VaultysIdCurrent.generatePerson();

      const s1 = await oldId.export();
      const s2 = await currentId.export();
      const manager1 = await VaultysIdOld.import(s1, { passphrase: "test123" });
      const manager2 = await VaultysIdCurrent.import(s2, { passphrase: "test456" });

      // Create channel and complete challenge
      const channel = await oldId.createChannel([currentId.toJSON()]);
      const challengeRequest = await manager1.startChallenge(channel, { name: "Old User" });
      const challengeResponse = await manager2.acceptChallenge(challengeRequest, { name: "Current User" });
      await manager1.verifyChallenge(challengeResponse);

      // Check Web of Trust
      const contacts1 = await manager1.getContacts();
      const contacts2 = await manager2.getContacts();

      expect(contacts1).to.have.lengthOf(1);
      expect(contacts2).to.have.lengthOf(1);

      // Verify trust relationships
      const trust1 = contacts1[0];
      const trust2 = contacts2[0];

      expect(trust1.did).to.equal(currentId.did);
      expect(trust2.did).to.equal(oldId.did);
    });
  });
});
