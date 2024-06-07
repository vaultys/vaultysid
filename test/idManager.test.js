import assert from "assert";
import { randomBytes } from "crypto";
import IdManager from "../src/IdManager";
import VaultysId from "../src/VaultysId";
import { MemoryChannel } from "../src/MemoryChannel";
import { MemoryStorage }  from "../src/MemoryStorage";

describe("IdManager", () => {
  it("serder a vaultys secret", async () => {
    const id1 = await VaultysId.generateMachine();
    const secret = id1.getSecret();
    const id2 = VaultysId.fromSecret(secret);
    assert.equal(id2.fingerprint, id1.fingerprint);
    assert.equal(id2.id.toString("base64"), id1.id.toString("base64"));
    assert.deepStrictEqual(id2.didDocument, id1.didDocument);
  });

  it("serder a vaultys secret in base64", async () => {
    const id1 = await VaultysId.generateMachine();
    const secret = id1.getSecret("base64");
    const id2 = VaultysId.fromSecret(secret, "base64");
    assert.equal(id2.fingerprint, id1.fingerprint);
    assert.equal(id2.id.toString("base64"), id1.id.toString("base64"));
    assert.deepStrictEqual(id2.didDocument, id1.didDocument);
  });

  it("serder to public Idmanager", async () => {
    const id1 = await VaultysId.generateMachine();
    const id2 = VaultysId.fromId(id1.id);
    assert.equal(id2.fingerprint, id1.fingerprint);
    assert.equal(id2.id.toString("base64"), id1.id.toString("base64"));
    assert.deepStrictEqual(id2.didDocument, id1.didDocument);
  });

  it("serder to public Idmanager stringified", async () => {
    const id1 = await VaultysId.generateMachine();
    const id = JSON.stringify(id1.id);
    const id2 = VaultysId.fromId(JSON.parse(id));
    assert.equal(id2.fingerprint, id1.fingerprint);
    assert.equal(id2.id.toString("base64"), id1.id.toString("base64"));
    assert.deepStrictEqual(id2.didDocument, id1.didDocument);
  });

  it("serder to public Idmanager as hex string", async () => {
    const id1 = await VaultysId.generateMachine();
    const id2 = VaultysId.fromId(id1.id.toString('hex'));
    assert.equal(id2.fingerprint, id1.fingerprint);
  });

  it("serder to public Idmanager as base64 string", async () => {
    const id1 = await VaultysId.generateMachine();
    const id2 = VaultysId.fromId(id1.id.toString('base64'), null, "base64");
    assert.equal(id2.fingerprint, id1.fingerprint);
    assert.equal(id2.id.toString("base64"), id1.id.toString("base64"));
    assert.deepStrictEqual(id2.didDocument, id1.didDocument);
  });

  it("sign unspecified data and log it in the store", async () => {
    const s = MemoryStorage(() => "");
    const manager = new IdManager(await VaultysId.generatePerson(), s);
    const signature = await manager.signChallenge(manager.vaultysId.id);
    const signatures = manager.getSignatures();
    assert.equal(signatures.length, 1);
    assert.equal(signatures[0].payload.challenge.toString("hex"), manager.vaultysId.id.toString("hex"));
    assert.equal(signatures[0].payload.signature.toString("hex"), signature.toString("hex"));
    assert.equal(signatures[0].type, 'UNKNOWN');
  });

  it("sign random document hash and log it in the store", async () => {
    const s = MemoryStorage(() => "");
    const fileHashMock = randomBytes(32);
    const manager = new IdManager(await VaultysId.generatePerson(), s);
    const payload = await manager.signFile(fileHashMock);
    const signatures = manager.getSignatures();
    assert.equal(signatures.length, 1);
    const challenge = new URL(signatures[0].challenge)
    assert.equal(challenge.searchParams.get('hash'), fileHashMock.toString("hex"));
    assert.ok(manager.verifyFile(signatures[0].payload.challenge.toString("hex"), signatures[0].payload.signature));
    assert.equal(signatures[0].payload.signature.toString("hex"), payload.signature.toString("hex"));
    //console.log(signatures[0]);
    assert.equal(signatures[0].type, 'DOCUMENT');
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
    const channel = MemoryChannel.createBidirectionnal();
    const s1 = MemoryStorage(() => "");
    const s2 = MemoryStorage(() => "");
    const manager1 = new IdManager(await VaultysId.generatePerson(), s1);
    const manager2 = new IdManager(await VaultysId.generateMachine(), s2);
    const metadata1 = {
      name: "a",
      email: "b",
      phone: "c"
    };
    const metadata2 = {
      name: "d",
      email: "e",
      phone: "f"
    };

    const contacts = await Promise.all([
      manager1.askContact(channel, metadata1),
      manager2.acceptContact(channel.otherend, metadata2),
    ]);

    assert.equal(contacts[0].did, manager2.vaultysId.did);
    assert.equal(contacts[1].did, manager1.vaultysId.did);

    // console.log(s2.substore("contacts"))
    
    // assert.deepStrictEqual(s2.substore("contacts").get(manager1.vaultysId.did).metadata, metadata1);
    // assert.deepStrictEqual(s1.substore("contacts").get(manager2.vaultysId.did).metadata, metadata2);

    assert.equal(Object.values(s1.substore("wot")._raw).length, 1);
    assert.equal(Object.values(s2.substore("wot")._raw).length, 1);
    
    assert.equal(manager2.contacts.length, 1);
    assert.equal(manager2.getContact( manager1.vaultysId.did).fingerprint, manager1.vaultysId.fingerprint);
    
    manager2.setContactMetadata(manager1.vaultysId.did, "name", "salut");
    manager2.setContactMetadata(manager1.vaultysId.did, "group", "pro");
    assert.equal(manager2.getContactMetadata(manager1.vaultysId.did, "name"), "salut");
    assert.equal(manager2.getContactMetadata(manager1.vaultysId.did, "group"), "pro");

    assert.ok(await manager1.verifyRelationshipCertificate(manager2.vaultysId.did));
    assert.ok(await manager2.verifyRelationshipCertificate(manager1.vaultysId.did));

  });

  it("pass a challenge over encrypted Channel", async () => {
    const channel = MemoryChannel.createBidirectionnal();

    const s1 = MemoryStorage(() => "");
    const s2 = MemoryStorage(() => "");
    const manager1 = new IdManager(await VaultysId.generatePerson(), s1);
    const manager2 = new IdManager(await VaultysId.generateOrganization(), s2);
    const metadata1 = {
      name: "a",
      email: "b"
    };
    const metadata2 = {
      name: "d",
      phone: "f"
    };

    const contacts = await Promise.all([
      manager1.askContact(channel, metadata1),
      manager2.acceptContact(channel.otherend, metadata2),
    ]);

    assert.equal(contacts[0].did, manager2.vaultysId.did);
    assert.equal(contacts[1].did, manager1.vaultysId.did);

    // assert.deepStrictEqual(s2.substore("contacts").get(manager1.vaultysId.did).metadata, metadata1);
    // assert.deepStrictEqual(s1.substore("contacts").get(manager2.vaultysId.did).metadata, metadata2);

    assert.equal(Object.values(s1.substore("wot")._raw).length, 1);
    assert.equal(Object.values(s2.substore("wot")._raw).length, 1);

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

    assert.ok(
      await manager1.verifyRelationshipCertificate(manager2.vaultysId.did),
    );
    assert.ok(
      await manager2.verifyRelationshipCertificate(manager1.vaultysId.did),
    );
  });

  it("perform migration from version 0 to 1",  async () => {
    const ids = [];
    for(let i = 0; i <10; i++) {
      const s1 = MemoryStorage(() => "");
      const id1 = new IdManager(await VaultysId.generatePerson(), s1);
      for(let j = 0; j <10; j++) {
        const s2 = MemoryStorage(() => "");
        const id2 = new IdManager(await VaultysId.generatePerson(), s2);
        id1.saveContact(id2.vaultysId);
        id1.setContactMetadata(id2.vaultysId.did, "test", id2.vaultysId.did);
      }
      ids.push(id1)
    }

    for(const id of ids) {
      id.migrate(0);
      assert.equal(id.contacts.length, 10);
      id.migrate(1);
      assert.equal(id.contacts.length, 10);
    }
   
  });

});
