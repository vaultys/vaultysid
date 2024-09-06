import assert from "assert";
import { createHash, randomBytes } from "crypto";
import IdManager from "../src/IdManager";
import VaultysId from "../src/VaultysId";
import { MemoryChannel } from "../src/MemoryChannel";
import { MemoryStorage } from "../src/MemoryStorage";
import { createReadStream, createWriteStream, readFileSync, rmSync } from "fs";
import SoftCredentials from "../src/SoftCredentials";
import "./utils";

const hashFile = (name: string) => {
  const fileBuffer = readFileSync(name);
  const hashSum = createHash("sha256");
  hashSum.update(fileBuffer);
  return hashSum.digest("hex");
};

const generateWebauthn = async (prf = true) => {
  const attestation = await SoftCredentials.create(SoftCredentials.createRequest(-7, prf));
  return VaultysId.fido2FromAttestation(attestation);
};

describe("IdManager", () => {
  it("serder a vaultys secret", async () => {
    const ids = await Promise.all([VaultysId.generateMachine(), VaultysId.generateOrganization(), VaultysId.generatePerson(), generateWebauthn()]);
    for (const id1 of ids) {
      const secret = id1.getSecret();
      const id2 = VaultysId.fromSecret(secret);
      assert.equal(id2.fingerprint, id1.fingerprint);
      assert.equal(id2.id.toString("base64"), id1.id.toString("base64"));
      assert.deepStrictEqual(id2.didDocument, id1.didDocument);
      const hmac1 = await id1.hmac("test message");
      const hmac2 = await id2.hmac("test message");
      assert.notEqual(hmac1, undefined);
      assert.equal(hmac1?.toString("base64"), hmac2?.toString("base64"));
    }
  });

  it("serder a vaultys secret in base64", async () => {
    const ids = await Promise.all([VaultysId.generateMachine(), VaultysId.generateOrganization(), VaultysId.generatePerson(), generateWebauthn()]);
    for (const id1 of ids) {
      const secret = id1.getSecret("base64");
      const id2 = VaultysId.fromSecret(secret, "base64");
      assert.equal(id2.fingerprint, id1.fingerprint);
      assert.equal(id2.id.toString("base64"), id1.id.toString("base64"));
      assert.deepStrictEqual(id2.didDocument, id1.didDocument);
      const hmac1 = await id1.hmac("test message");
      const hmac2 = await id2.hmac("test message");
      assert.notEqual(hmac1, undefined);
      assert.equal(hmac1?.toString("base64"), hmac2?.toString("base64"));
    }
  });

  it("serder to public Idmanager", async () => {
    const ids = await Promise.all([VaultysId.generateMachine(), VaultysId.generateOrganization(), VaultysId.generatePerson(), generateWebauthn()]);
    for (const id1 of ids) {
      const id2 = VaultysId.fromId(id1.id);
      assert.equal(id2.fingerprint, id1.fingerprint);
      assert.equal(id2.id.toString("base64"), id1.id.toString("base64"));
      assert.deepStrictEqual(id2.didDocument, id1.didDocument);

      const hmac1 = await id1.hmac("test message");
      const hmac2 = await id2.hmac("test message");
      assert.notEqual(hmac1, undefined);
      assert.equal(hmac2, undefined);
    }
  });

  it("serder to public Idmanager stringified", async () => {
    const ids = await Promise.all([VaultysId.generateMachine(), VaultysId.generateOrganization(), VaultysId.generatePerson(), generateWebauthn()]);
    for (const id1 of ids) {
      const id = JSON.stringify(id1.id);
      const id2 = VaultysId.fromId(JSON.parse(id));
      assert.equal(id2.fingerprint, id1.fingerprint);
      assert.equal(id2.id.toString("base64"), id1.id.toString("base64"));
      assert.deepStrictEqual(id2.didDocument, id1.didDocument);
    }
  });

  it("serder to public Idmanager as hex string", async () => {
    const ids = await Promise.all([VaultysId.generateMachine(), VaultysId.generateOrganization(), VaultysId.generatePerson(), generateWebauthn()]);
    for (const id1 of ids) {
      const id2 = VaultysId.fromId(id1.id.toString("hex"));
      assert.equal(id2.fingerprint, id1.fingerprint);
    }
  });

  it("serder to public Idmanager as base64 string", async () => {
    const ids = await Promise.all([VaultysId.generateMachine(), VaultysId.generateOrganization(), VaultysId.generatePerson(), generateWebauthn()]);
    for (const id1 of ids) {
      const id2 = VaultysId.fromId(id1.id.toString("base64"), undefined, "base64");
      assert.equal(id2.fingerprint, id1.fingerprint);
      assert.equal(id2.id.toString("base64"), id1.id.toString("base64"));
      assert.deepStrictEqual(id2.didDocument, id1.didDocument);
    }
  });

  it("sign unspecified data and log it in the store", async () => {
    const ids = await Promise.all([VaultysId.generateMachine(), VaultysId.generateOrganization(), VaultysId.generatePerson(), generateWebauthn()]);
    for (const id1 of ids) {
      const s = MemoryStorage(() => "");
      const manager = new IdManager(id1, s);
      const signature = await manager.signChallenge(manager.vaultysId.id);
      if (signature == null) assert.fail();
      const signatures = manager.getSignatures();
      assert.equal(signatures.length, 1);
      assert.equal(signatures[0].payload.challenge.toString("hex"), manager.vaultysId.id.toString("hex"));
      assert.equal(signatures[0].payload.signature.toString("hex"), signature.toString("hex"));
      assert.equal(signatures[0].type, "UNKNOWN");
    }
  });

  it("sign random document hash and log it in the store", async () => {
    const ids = await Promise.all([VaultysId.generateMachine(), VaultysId.generateOrganization(), VaultysId.generatePerson(), generateWebauthn()]);
    for (const id1 of ids) {
      const s = MemoryStorage(() => "");
      const fileHashMock = randomBytes(32);
      const manager = new IdManager(id1, s);
      const payload = await manager.signFile(fileHashMock);
      const signatures = manager.getSignatures();
      assert.equal(signatures.length, 1);
      const challenge = new URL(signatures[0].challenge);
      assert.equal(challenge.searchParams.get("hash"), fileHashMock.toString("hex"));
      assert.ok(manager.verifyFile(signatures[0].payload.challenge.toString("hex"), signatures[0].payload.signature));
      if (payload.signature == null) assert.fail();
      assert.equal(signatures[0].payload.signature.toString("hex"), payload.signature.toString("hex"));
      //console.log(signatures[0]);
      assert.equal(signatures[0].type, "DOCUMENT");
    }
  });

  // it("sign login and log it in the store", async () => {
  //   const s = MemoryStorage(() => "");
  //   const loginMock = 'vaultys://login?host=https://sso.vaultys.net/interaction/1UfGEF9HDQiIreFPS3wlI&nonce=9c0c7621a790c6e697032093aeca614d183319d663aa5cc1a085e052c7f904d5&timestamp=1665498137687&challenge=dummy'
  //   const manager = new IdManager(await VaultysId.generatePerson(), s);
  //   const payload = await manager.signLogin(loginMock);
  //   const signatures = manager.getSignatures();
  //   assert.equal(signatures.length, 1);
  //   const challenge = new URL(signatures[0].challenge)
  //   assert.equal(challenge.searchParams.get('hash'), fileHashMock.toString("hex"));
  //   assert.ok(manager.verifyFile(signatures[0].payload.challenge.toString("hex"), signatures[0].payload.signature));
  //   assert.equal(signatures[0].payload.signature.toString("hex"), payload.signature.toString("hex"));
  //   //console.log(signatures[0]);
  //   assert.equal(signatures[0].type, 'LOGIN');
  // });
});

describe("SRG challenge with IdManager", () => {
  it("pass a challenge", async () => {
    const ids = await Promise.all([VaultysId.generateMachine(), VaultysId.generateOrganization(), VaultysId.generatePerson(), generateWebauthn()]);
    for (const id1 of ids) {
      const channel = MemoryChannel.createBidirectionnal();
      if (!channel.otherend) assert.fail();
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);
      const manager2 = new IdManager(await VaultysId.generateMachine(), s2);
      const metadata1 = {
        name: "a",
        email: "b",
        phone: "c",
      };
      const metadata2 = {
        name: "d",
        email: "e",
        phone: "f",
      };

      const contacts = await Promise.all([manager1.askContact(channel, metadata1), manager2.acceptContact(channel.otherend, metadata2)]);

      assert.equal(contacts[0].did, manager2.vaultysId.did);
      assert.equal(contacts[1].did, manager1.vaultysId.did);

      // console.log(s2.substore("contacts"))

      // assert.deepStrictEqual(s2.substore("contacts").get(manager1.vaultysId.did).metadata, metadata1);
      // assert.deepStrictEqual(s1.substore("contacts").get(manager2.vaultysId.did).metadata, metadata2);

      assert.equal(s1.substore("wot").list().length, 1);
      assert.equal(s2.substore("wot").list().length, 1);
      if (manager1.vaultysId.type === 0) {
        assert.equal(manager2.apps.length, 1);
        assert.equal(manager2.getApp(manager1.vaultysId.did)?.fingerprint, manager1.vaultysId.fingerprint);
        assert.ok(await manager1.verifyRelationshipCertificate(manager2.vaultysId.did));
        assert.ok(await manager2.verifyRelationshipCertificate(manager1.vaultysId.did));
      } else {
        assert.equal(manager2.contacts.length, 1);
        assert.equal(manager2.getContact(manager1.vaultysId.did)?.fingerprint, manager1.vaultysId.fingerprint);
        manager2.setContactMetadata(manager1.vaultysId.did, "name", "salut");
        manager2.setContactMetadata(manager1.vaultysId.did, "group", "pro");
        assert.equal(manager2.getContactMetadata(manager1.vaultysId.did, "name"), "salut");
        assert.equal(manager2.getContactMetadata(manager1.vaultysId.did, "group"), "pro");
        assert.ok(await manager1.verifyRelationshipCertificate(manager2.vaultysId.did));
        assert.ok(await manager2.verifyRelationshipCertificate(manager1.vaultysId.did));
      }
    }
  });

  it("pass a challenge over encrypted Channel", async () => {
    const ids = await Promise.all([VaultysId.generateMachine(), VaultysId.generateOrganization(), VaultysId.generatePerson(), generateWebauthn()]);
    for (const id1 of ids) {
      const channel = MemoryChannel.createBidirectionnal();
      if (!channel.otherend) assert.fail();
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);
      const manager2 = new IdManager(await VaultysId.generateOrganization(), s2);
      const metadata1 = {
        name: "a",
        email: "b",
      };
      const metadata2 = {
        name: "d",
        phone: "f",
      };

      const contacts = await Promise.all([manager1.askContact(channel, metadata1), manager2.acceptContact(channel.otherend, metadata2)]);

      assert.equal(contacts[0].did, manager2.vaultysId.did);
      assert.equal(contacts[1].did, manager1.vaultysId.did);

      // assert.deepStrictEqual(s2.substore("contacts").get(manager1.vaultysId.did).metadata, metadata1);
      // assert.deepStrictEqual(s1.substore("contacts").get(manager2.vaultysId.did).metadata, metadata2);

      assert.equal(s1.substore("wot").list().length, 1);
      assert.equal(s2.substore("wot").list().length, 1);

      manager1.setContactMetadata(manager2.vaultysId.did, "name", "salut");
      manager1.setContactMetadata(manager2.vaultysId.did, "group", "pro");
      // assert.deepStrictEqual(
      //   manager1.getCertifiedMetadata(manager2.vaultysId.did),
      //   metadata2
      // );
      // assert.deepStrictEqual(
      //   manager1.getAllMetadata(manager2.vaultysId.did),
      //   {
      //     group: 'pro',
      //     name: 'salut',
      //     phone: 'f'
      //   }
      // );

      assert.ok(await manager1.verifyRelationshipCertificate(manager2.vaultysId.did));
      assert.ok(await manager2.verifyRelationshipCertificate(manager1.vaultysId.did));
    }
  });

  it("Transfer data over encrypted Channel", async () => {
    const ids = await Promise.all([VaultysId.generateMachine(), VaultysId.generateOrganization(), VaultysId.generatePerson(), generateWebauthn()]);
    for (const id1 of ids) {
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      // channel.setLogger((data) => console.log("<"));
      // channel.otherend?.setLogger((data) => console.log(">"));
      if (!channel.otherend) assert.fail();
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);
      const manager2 = new IdManager(await VaultysId.generateOrganization(), s2);

      const input = createReadStream("./test/assets/testfile.png", {
        highWaterMark: 1 * 1024,
      });
      const output = createWriteStream("./test/assets/streamed_file_encrypted.png");
      const promise = manager2.download(channel, output);
      await manager1.upload(channel.otherend, input);
      await promise;
      const hash1 = hashFile("./test/assets/testfile.png");
      const hash2 = hashFile("./test/assets/streamed_file_encrypted.png");
      assert.equal(hash1, hash2);
      rmSync("./test/assets/streamed_file_encrypted.png");
    }
  });

  it("perform PRF over Channel", async () => {
    const ids = await Promise.all([VaultysId.generateMachine(), VaultysId.generateOrganization(), VaultysId.generatePerson(), generateWebauthn()]);
    for (const id1 of ids) {
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      if (!channel.otherend) assert.fail();
      // channel.setLogger((data) => console.log(data.toString("utf-8")));
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);
      const manager2 = new IdManager(await VaultysId.generateOrganization(), s2);

      const promise = manager2.requestPRF(channel.otherend, "nostr");
      manager1.acceptPRF(channel);
      const result = await promise;
      assert.deepEqual(result, await manager1.vaultysId.hmac("prf/nostr/end"));
    }
  });

  it("perform migration from version 0 to 1", async () => {
    const ids = [];
    for (let i = 0; i < 2; i++) {
      const vids1 = await Promise.all([VaultysId.generateMachine(), VaultysId.generateOrganization(), VaultysId.generatePerson(), generateWebauthn(), generateWebauthn(false)]);
      for (const vid of vids1) {
        const s1 = MemoryStorage(() => "");
        const id1 = new IdManager(vid, s1);
        for (let j = 0; j < 2; j++) {
          const vids2 = await Promise.all([VaultysId.generateMachine(), VaultysId.generateOrganization(), VaultysId.generatePerson(), generateWebauthn(), generateWebauthn(false)]);
          for (const vid2 of vids2) {
            const s2 = MemoryStorage(() => "");
            const id2 = new IdManager(vid2, s2);
            id1.saveContact(id2.vaultysId);
            id1.setContactMetadata(id2.vaultysId.did, "test", id2.vaultysId.did);
          }
        }
        ids.push(id1);
      }
    }

    for (const id of ids) {
      id.migrate(0);
      assert.equal(id.contacts.length, 8);
      assert.equal(id.apps.length, 2);
      id.migrate(1);
      assert.equal(id.contacts.length, 8);
      assert.equal(id.apps.length, 2);
    }
  });
});
