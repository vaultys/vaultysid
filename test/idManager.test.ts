import assert from "assert";
import { Buffer } from "..";
import { FileSignature } from "../src/IdManager";
import { IdManager, Challenger, KeyManager, VaultysId, MemoryChannel, MemoryStorage, File } from "..";
import "./shims";
import { hash, randomBytes } from "../src/crypto";
import { allVaultysIdType, createApp, createContact, createRandomVaultysId } from "./utils";
import wot_v0 from "./assets/wot_v0.json";
import wot_v1 from "./assets/wot_v1.json";
import clear_backup from "./assets/backup.bin.json";
import encrypted_backup from "./assets/backup.encrypted.bin.json";
import { migrateIdManager } from "../src/utils/migration";
import { Ed25519Manager } from "../src/KeyManager";
import { deserialize, MessagePackStorage, storagify } from "../src/MemoryStorage";

const passphrase = "deal develop devote mail agree try tide expand indicate poverty chuckle target";

describe("IdManager", () => {
  it("serder a vaultys secret", async () => {
    for (const id1 of await allVaultysIdType()) {
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
    for (const id1 of await allVaultysIdType()) {
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
    for (const id1 of await allVaultysIdType()) {
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
    for (const id1 of await allVaultysIdType()) {
      const id = JSON.stringify(id1.id);
      const id2 = VaultysId.fromId(JSON.parse(id));
      assert.equal(id2.fingerprint, id1.fingerprint);
      assert.equal(id2.id.toString("base64"), id1.id.toString("base64"));
      assert.deepStrictEqual(id2.didDocument, id1.didDocument);
    }
  });

  it("serder to public Idmanager as hex string", async () => {
    for (const id1 of await allVaultysIdType()) {
      const id2 = VaultysId.fromId(id1.id.toString("hex"));
      assert.equal(id2.fingerprint, id1.fingerprint);
    }
  });

  it("serder to public Idmanager as base64 string", async () => {
    for (const id1 of await allVaultysIdType()) {
      const id2 = VaultysId.fromId(id1.id.toString("base64"), undefined, "base64");
      assert.equal(id2.fingerprint, id1.fingerprint);
      assert.equal(id2.id.toString("base64"), id1.id.toString("base64"));
      assert.deepStrictEqual(id2.didDocument, id1.didDocument);
    }
  });

  it("sign unspecified data and log it in the store", async () => {
    for (const id1 of await allVaultysIdType()) {
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
    for (const id1 of await allVaultysIdType()) {
      const s = MemoryStorage(() => "");
      const file = { arrayBuffer: Buffer.from(randomBytes(1024)), type: "random" } as File;
      const h = hash("sha256", file.arrayBuffer);
      const manager = new IdManager(id1, s);
      const payload = await manager.signFile(file);
      const signatures = manager.getSignatures();
      assert.equal(signatures.length, 1);
      const challenge = new URL(signatures[0].challenge);
      assert.equal(challenge.searchParams.get("hash"), h.toString("hex"));
      assert.ok(manager.verifyFile(file, signatures[0].payload as FileSignature, id1));
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

describe("WoT", () => {
  it("write Web of Trust", async () => {
    const id = await VaultysId.generateMachine();
    const s2 = MemoryStorage(() => "");
    const manager2 = new IdManager(id, s2);
    for (let i = 0; i < 5; i++) {
      const id1 = await createContact();
      const channel = MemoryChannel.createBidirectionnal();
      if (!channel.otherend) assert.fail();
      const s1 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);

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
    }
    for (let i = 0; i < 5; i++) {
      const id1 = await createApp();
      const channel = MemoryChannel.createBidirectionnal();
      if (!channel.otherend) assert.fail();
      const s1 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);

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
    }
    // require("fs").writeFileSync(__dirname + "/assets/wot.json", s2.toString());
  });

  it("read Web of Trust v0", async () => {
    // const data2 = readFileSync(__dirname + "/assets/wot_v0.json");
    //console.log(data);
    const store = storagify(
      deserialize(JSON.stringify(wot_v0)),
      () => "",
      () => "",
    );
    assert.equal(store.listSubstores().length, 3);
    const contacts = ["did:vaultys:0222cf6797fb5d997d9ca9bf650af26e986b8b18", "did:vaultys:04f9f57c532d525407c4f07c46d5868794dfdb44", "did:vaultys:04fbd2781a354e8d3636c7884ca6d87775fadc6a", "did:vaultys:02a3da6fb68019dfd77d8825a254d0e26f13074e", "did:vaultys:031ce55a84f388767ee8861b1f52c1faef7047e7"];
    const apps = ["did:vaultys:003813d0639f103023909498b8101424a01ea458", "did:vaultys:007eeed55c703c23db23a3f965a5ca2c26f5c428", "did:vaultys:0062a0efff32c131617115df4525a234e58e5710", "did:vaultys:0033eb847e64d56b6e604eb42fe744d4eec02644", "did:vaultys:001c53a28e606a1c3250b4065df370dc300b26fe"];
    assert.deepEqual(store.substore("contacts").list(), contacts);
    assert.deepEqual(store.substore("registrations").list(), apps);
    assert.deepEqual(store.substore("wot").list(), ["1750418334298", "1750418334312", "1750418334325", "1750418334341", "1750418334353", "1750418334370", "1750418334385", "1750418334401", "1750418334418", "1750418334433"]);
    const idManager = await IdManager.fromStore(store);
    // migration
    migrateIdManager(idManager);
    //await new Promise((r) => setTimeout(r, 300));
    const newContats = ["did:vaultys:04f9f57c532d525407c4f07c46d5868794dfdb44", "did:vaultys:04fbd2781a354e8d3636c7884ca6d87775fadc6a", "did:vaultys:031ce55a84f388767ee8861b1f52c1faef7047e7", "did:vaultys:028814f629126dba851cc6639b2960d1bbc941e6", "did:vaultys:020fdb7bba1ff3db860ec560acf0518487aa7aea"];
    const newApps = ["did:vaultys:004790c0e7651084ec26918899b9d0e0b1d5e7a2", "did:vaultys:004ed3d4278aefb5d140b73e15d23e2d6c081529", "did:vaultys:000ae5fcf15c3c5527c96ff2769f0b6b29417941", "did:vaultys:00bc190099ed87fe837bd23f802b96b93c64cf64", "did:vaultys:000bdbee85201b86f4dc89578a03fe81e23148de"];
    assert.deepEqual(store.substore("contacts").list(), newContats);
    assert.deepEqual(store.substore("registrations").list(), newApps);
    assert.deepEqual(store.substore("wot").list(), ["1750418334298", "1750418334312", "1750418334325", "1750418334341", "1750418334353", "1750418334370", "1750418334385", "1750418334401", "1750418334418", "1750418334433"]);

    //assert.equal(idManager.vaultysId.did, "did:vaultys:00f2b4cab97b9bb95f375e17d3f58966da52202f");
    assert.equal(idManager.vaultysId.did, "did:vaultys:00a6effd86d237d99117c68dcf0b843e3c2f9e4c");
    const keyManager = await Ed25519Manager.createFromEntropy(store.get("entropy"));
    assert.equal(keyManager.id.toString("hex"), "83a17601a178c42002593d5fcd0e42b33f57c96a5cdc1daa1ac0b63952085d75ee8e485dc42c20e9a165c4203ca1b470b4505842a9b6446273759a6ae4b3a019bc9b48d563e0398cb2cbec7e");
    const vid = new VaultysId(keyManager, undefined, 0);
    assert.equal(vid.did, idManager.vaultysId.did);
    for (const certid of store.substore("wot").list()) {
      const cert = store.substore("wot").get(certid);
      //console.log(Challenger.deserializeCertificate(cert));
      assert.equal(await Challenger.verifyCertificate(cert), true);
    }
    for (const appid of store.substore("registrations").list()) {
      const app = store.substore("registrations").get(appid);
      assert.equal(appid, app.site);
      assert.equal(appid, VaultysId.fromId(app.serverId, undefined, "base64").did);
      assert.equal(await Challenger.verifyCertificate(app!.certificate!), true);
    }
    assert.equal(idManager.contacts.length, 5);
    for (const contact of newContats) {
      const c = idManager.getContact(contact);
      assert.equal(contact, c!.did);
      assert.equal(await Challenger.verifyCertificate(c!.certificate!), true);
    }
    assert.equal(idManager.apps.length, 5);
    for (const app of newApps) {
      const c = idManager.getApp(app);
      assert.equal(app, c!.did);
      assert.equal(await Challenger.verifyCertificate(c!.certificate!), true);
    }

    assert.equal(await idManager.verifyWebOfTrust(), true);
  });

  it("read Web of Trust v1", async () => {
    // const data2 = readFileSync(__dirname + "/assets/wot_v0.json");
    //console.log(data);
    const store = storagify(
      deserialize(JSON.stringify(wot_v1)),
      () => "",
      () => "",
    );
    assert.equal(store.listSubstores().length, 3);
    const contacts = ["did:vaultys:039868dabdfa5b2b93a42837adb56264f503827f", "did:vaultys:044d24c906f5a585e065271793792f93cc2a588e", "did:vaultys:02ba1810d8f453da15469643b305fca91667458d", "did:vaultys:03a9aef25b7aeb6d3fbe244d5628fa2d3c204212", "did:vaultys:01d6a4fbc7ad3c3959e16bd8e6b13d359fa716dd"];
    const apps = ["did:vaultys:00c63e39b800ba52d10e2186ef273302088c9f6d", "did:vaultys:00be5e25cf45b386da62947c98ab56fa72f93398", "did:vaultys:00d7f1829ba0717753699cd444cbe5b13e2b593f", "did:vaultys:007014a482f672c8b462955a69b38faeaf750789", "did:vaultys:0021bebd098c332957cbe9fd088597b4dd5a07d7"];
    assert.deepEqual(store.substore("contacts").list(), contacts);
    assert.deepEqual(store.substore("registrations").list(), apps);
    assert.deepEqual(store.substore("wot").list(), ["1750441335308", "1750441335318", "1750441335326", "1750441335334", "1750441335341", "1750441335349", "1750441335357", "1750441335364", "1750441335372", "1750441335379"]);
    const idManager = await IdManager.fromStore(store);
    assert.equal(idManager.vaultysId.did, "did:vaultys:001feb17d2d85718dee401fc2e776f21142ebaf1");
    const keyManager = await Ed25519Manager.createFromEntropy(store.get("entropy"));
    assert.equal(keyManager.id.toString("hex"), "83a17601a178c42038242fb2cd2352a584af35515efbb7757d7997943750541bef4db8f4a57c78eea165c4207f44f58019be61744095611788153748ca7f9f5cba68ce4cc1391b8fc4f3d45b");
    const vid = new VaultysId(keyManager, undefined, 0);
    assert.equal(vid.did, idManager.vaultysId.did);
    for (const certid of store.substore("wot").list()) {
      const cert = store.substore("wot").get(certid);
      //console.log(Challenger.deserializeCertificate(cert));
      assert.equal(await Challenger.verifyCertificate(cert), true);
    }
    for (const appid of store.substore("registrations").list()) {
      const app = store.substore("registrations").get(appid);
      assert.equal(appid, app.site);
      assert.equal(appid, VaultysId.fromId(app.serverId, undefined, "base64").did);
      assert.equal(await Challenger.verifyCertificate(app!.certificate!), true);
    }
    assert.equal(idManager.contacts.length, 5);
    for (const contact of contacts) {
      const c = idManager.getContact(contact);
      assert.equal(contact, c!.did);
      assert.equal(await Challenger.verifyCertificate(c!.certificate!), true);
    }
    assert.equal(idManager.apps.length, 5);
    for (const app of apps) {
      const c = idManager.getApp(app);
      assert.equal(app, c!.did);
      assert.equal(await Challenger.verifyCertificate(c!.certificate!), true);
    }

    assert.equal(await idManager.verifyWebOfTrust(), true);
  });

  it("create backup v1", async () => {
    // const data2 = readFileSync(__dirname + "/assets/wot_v0.json");
    //console.log(data);
    const store = storagify(
      deserialize(JSON.stringify(wot_v1)),
      () => "",
      () => "",
    );
    const idManager = await IdManager.fromStore(store);

    const backup = await idManager.exportBackup();
    // require("fs").writeFileSync(__dirname + "/assets/backup.bin.json", JSON.stringify({ backup: Buffer.from(backup).toString("base64") }));
    const id2 = await IdManager.importBackup(backup);

    assert.equal(await id2?.verifyWebOfTrust(), true);
    // console.log(id2?.store.toString());
    assert.equal(id2?.store.toString(), idManager.store.toString());
  });

  it("read backup v1", async () => {
    const id2 = await IdManager.importBackup(Buffer.from(clear_backup.backup, "base64"));
    assert.equal(await id2?.verifyWebOfTrust(), true);
  });

  it("create encrypted backup v1", async () => {
    // const data2 = readFileSync(__dirname + "/assets/wot_v0.json");
    //console.log(data);
    const store = storagify(
      deserialize(JSON.stringify(wot_v1)),
      () => "",
      () => "",
    );
    const idManager = await IdManager.fromStore(store);

    const backup = await idManager.exportBackup(passphrase);
    // require("fs").writeFileSync(__dirname + "/assets/backup.encrypted.bin.json", JSON.stringify({ backup: Buffer.from(backup).toString("base64") }));

    const id2 = await IdManager.importBackup(backup, passphrase);

    assert.equal(await id2?.verifyWebOfTrust(), true);
    assert.equal(id2?.store.toString(), idManager.store.toString());
  }).timeout(20000);

  it("read encrypted backup v1", async () => {
    const id2 = await IdManager.importBackup(Buffer.from(encrypted_backup.backup, "base64"), passphrase);
    assert.equal(await id2?.verifyWebOfTrust(), true);
  }).timeout(10000);
});

describe("SRG v0 challenge with IdManager", () => {
  it("pass a challenge", async () => {
    for (const id1 of await allVaultysIdType()) {
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
        const app1 = manager2.getApp(manager1.vaultysId.did);
        assert.equal(app1?.fingerprint, manager1.vaultysId.fingerprint);
        assert.equal(app1?.keyManager.authType, manager1.vaultysId.keyManager.authType);
        assert.equal(app1?.keyManager.encType, manager1.vaultysId.keyManager.encType);
        assert.ok(await manager1.verifyRelationshipCertificate(manager2.vaultysId.did));
        assert.ok(await manager2.verifyRelationshipCertificate(manager1.vaultysId.did));
      } else {
        assert.equal(manager2.contacts.length, 1);
        const contact1 = manager2.getContact(manager1.vaultysId.did);
        assert.equal(contact1?.fingerprint, manager1.vaultysId.fingerprint);
        assert.equal(contact1?.keyManager.authType, manager1.vaultysId.keyManager.authType);
        assert.equal(contact1?.keyManager.encType, manager1.vaultysId.keyManager.encType);
        manager2.setContactMetadata(manager1.vaultysId.did, "name", "salut");
        manager2.setContactMetadata(manager1.vaultysId.did, "group", "pro");
        assert.equal(manager2.getContactMetadata(manager1.vaultysId.did, "name"), "salut");
        assert.equal(manager2.getContactMetadata(manager1.vaultysId.did, "group"), "pro");
        assert.ok(await manager1.verifyRelationshipCertificate(manager2.vaultysId.did));
        assert.ok(await manager2.verifyRelationshipCertificate(manager1.vaultysId.did));
      }
    }
  });

  it("fail a challenge if user1 refuse", async () => {
    for (const id1 of await allVaultysIdType()) {
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

      try {
        await Promise.all([manager1.askContact(channel, metadata1, () => Promise.resolve(false)), manager2.acceptContact(channel.otherend, metadata2)]);
      } catch (e) {
        assert.equal((e as { message: string }).message, "Error: Contact refused");
      }
    }
  });

  it("fail a challenge if user2 refuse", async () => {
    for (const id1 of await allVaultysIdType()) {
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

      try {
        await Promise.all([manager1.askContact(channel, metadata1), manager2.acceptContact(channel.otherend, metadata2, () => Promise.resolve(false))]);
      } catch (e) {
        assert.equal((e as { message: string }).message, "Error: Contact refused");
      }
    }
  });

  it("pass a challenge over encrypted Channel", async () => {
    for (const id1 of await allVaultysIdType()) {
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

  // it("pass a challenge over encrypted Channel using MessagePackStorage", async () => {
  //   for (const id1 of await allVaultysIdType()) {
  //     const channel = MemoryChannel.createBidirectionnal();
  //     if (!channel.otherend) assert.fail();
  //     const s1 = MessagePackStorage();
  //     const s2 = MessagePackStorage();
  //     const manager1 = new IdManager(id1, s1);
  //     const manager2 = new IdManager(await VaultysId.generateOrganization(), s2);
  //     const metadata1 = {
  //       name: "a",
  //       email: "b",
  //     };
  //     const metadata2 = {
  //       name: "d",
  //       phone: "f",
  //     };

  //     const contacts = await Promise.all([manager1.askContact(channel, metadata1), manager2.acceptContact(channel.otherend, metadata2)]);

  //     assert.equal(contacts[0].did, manager2.vaultysId.did);
  //     assert.equal(contacts[1].did, manager1.vaultysId.did);

  //     // assert.deepStrictEqual(s2.substore("contacts").get(manager1.vaultysId.did).metadata, metadata1);
  //     // assert.deepStrictEqual(s1.substore("contacts").get(manager2.vaultysId.did).metadata, metadata2);

  //     assert.equal(s1.substore("wot").list().length, 1);
  //     assert.equal(s2.substore("wot").list().length, 1);

  //     manager1.setContactMetadata(manager2.vaultysId.did, "name", "salut");
  //     manager1.setContactMetadata(manager2.vaultysId.did, "group", "pro");
  //     // assert.deepStrictEqual(
  //     //   manager1.getCertifiedMetadata(manager2.vaultysId.did),
  //     //   metadata2
  //     // );
  //     // assert.deepStrictEqual(
  //     //   manager1.getAllMetadata(manager2.vaultysId.did),
  //     //   {
  //     //     group: 'pro',
  //     //     name: 'salut',
  //     //     phone: 'f'
  //     //   }
  //     // );

  //     assert.ok(await manager1.verifyRelationshipCertificate(manager2.vaultysId.did));
  //     assert.ok(await manager2.verifyRelationshipCertificate(manager1.vaultysId.did));
  //   }
  // });

  it("perform PRF over Channel", async () => {
    for (let i = 0; i < 5; i++) {
      const id1 = await createRandomVaultysId();
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      if (!channel.otherend) assert.fail();
      // channel.setLogger((data) => console.log(data.toString("utf-8")));
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);
      const manager2 = new IdManager(await VaultysId.generateOrganization(), s2);

      manager1.acceptPRF(channel);
      const result = await manager2.requestPRF(channel.otherend, "nostr");
      assert.deepEqual(result, await manager1.vaultysId.hmac("prf|nostr|prf"));
    }
  });

  it("perform decrypt over Channel", async () => {
    for (let i = 0; i < 5; i++) {
      const id1 = await createRandomVaultysId();
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      if (!channel.otherend) assert.fail();
      // channel.setLogger((data) => console.log(data.toString("utf-8")));
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);
      const manager2 = new IdManager(await VaultysId.generateOrganization(), s2);

      const message = "test decrypt on demand";

      const toDecrypt = await VaultysId.encrypt(message, [manager1.vaultysId.id]);

      manager1.acceptDecrypt(channel);

      //console.log(toDecrypt);
      const result = await manager2.requestDecrypt(channel.otherend, Buffer.from(toDecrypt, "utf-8"));

      assert.deepEqual(result?.toString("utf-8"), message);
    }
  });

  describe("IdManager File Encryption/Decryption", () => {
    it("should encrypt and decrypt a file between two IdManagers", async () => {
      let channel = MemoryChannel.createEncryptedBidirectionnal();

      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(await createRandomVaultysId(), s1);
      const manager2 = new IdManager(await createRandomVaultysId(), s2);

      // Create a sample file
      const fileContent = randomBytes(1024);
      const originalFile = {
        arrayBuffer: Buffer.from(fileContent),
        type: "application/octet-stream",
        name: "test.bin",
      };

      // Set up the decryption handler on manager2
      manager2.acceptDecryptFile(channel.otherend!);

      // Request encryption from manager1 to manager2
      const encryptedFile = await manager1.requestEncryptFile(channel, originalFile);

      assert.ok(encryptedFile, "Encryption failed");
      assert.equal(encryptedFile.type, originalFile.type, "File type should be preserved");
      assert.equal(encryptedFile.name, originalFile.name, "File name should be preserved");
      assert.ok(encryptedFile.arrayBuffer, "Encrypted data should be present");
      assert.notDeepEqual(encryptedFile.arrayBuffer, originalFile.arrayBuffer, "Encrypted data should be different from original");

      // Now decrypt the file
      channel = MemoryChannel.createEncryptedBidirectionnal();
      manager2.acceptDecryptFile(channel.otherend!);

      const decryptedFile = await manager1.requestDecryptFile(channel, encryptedFile);
      assert.ok(decryptedFile, "Decryption failed");
      assert.equal(decryptedFile.type, originalFile.type, "File type should be preserved after decryption");
      assert.equal(decryptedFile.name, originalFile.name, "File name should be preserved after decryption");
      assert.deepEqual(decryptedFile.arrayBuffer, originalFile.arrayBuffer, "Decrypted file should match the original");
    });

    it("should work with different file types and sizes", async () => {
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      if (!channel.otherend) assert.fail("Channel creation failed");
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(await createRandomVaultysId(), s1);
      const manager2 = new IdManager(await createRandomVaultysId(), s2);

      // Test with different file types and sizes
      const testCases = [
        { size: 10, type: "text/plain", name: "small.txt" },
        { size: 1024, type: "application/pdf", name: "medium.pdf" },
        { size: 4096, type: "image/jpeg", name: "large.jpg" },
      ];

      for (const testCase of testCases) {
        const fileContent = randomBytes(testCase.size);
        const originalFile = {
          arrayBuffer: Buffer.from(fileContent),
          type: testCase.type,
          name: testCase.name,
        };

        manager2.acceptEncryptFile(channel.otherend);

        const encryptedFile = await manager1.requestEncryptFile(channel, originalFile);
        assert.ok(encryptedFile, `Encryption failed for ${testCase.name}`);

        manager2.acceptDecryptFile(channel.otherend);

        const decryptedFile = await manager1.requestDecryptFile(channel, encryptedFile);
        assert.ok(decryptedFile, `Decryption failed for ${testCase.name}`);
        assert.equal(decryptedFile.type, originalFile.type, `File type should be preserved for ${testCase.name}`);
        assert.equal(decryptedFile.name, originalFile.name, `File name should be preserved for ${testCase.name}`);
        assert.deepEqual(decryptedFile.arrayBuffer, originalFile.arrayBuffer, `Decrypted content should match original for ${testCase.name}`);
      }
    });

    it("should handle acceptDecryptFile with custom acceptance function", async () => {
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      if (!channel.otherend) assert.fail("Channel creation failed");

      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(await createRandomVaultysId(), s1);
      const manager2 = new IdManager(await createRandomVaultysId(), s2);

      // First establish contact between the managers
      const contactChannel = MemoryChannel.createBidirectionnal();
      if (!contactChannel.otherend) assert.fail("Contact channel creation failed");

      await Promise.all([manager1.askContact(contactChannel), manager2.acceptContact(contactChannel.otherend)]);

      // Create a sample file
      const originalFile = {
        arrayBuffer: Buffer.from(randomBytes(512)),
        type: "text/plain",
        name: "test.txt",
      };

      // Test with accepting function that returns true
      let acceptCalled = false;
      manager2.acceptDecryptFile(channel.otherend, async (contact) => {
        acceptCalled = true;
        assert.equal(contact.toVersion(1).fingerprint, manager1.vaultysId.fingerprint);
        return true;
      });

      const encryptedFile = await manager1.requestEncryptFile(channel, originalFile);

      assert.ok(encryptedFile, "Encryption should succeed when accept returns true");
      assert.ok(acceptCalled, "Accept function should be called");

      // Test with accepting function that returns false

      acceptCalled = false;
      manager2.acceptDecryptFile(channel.otherend, async () => {
        acceptCalled = true;
        return false;
      });

      const failedResult = await manager1.requestEncryptFile(channel, originalFile);
      assert.ok(acceptCalled, "Accept function should be called even when rejecting");
      assert.equal(failedResult, null, "Encryption should fail when accept returns false");
    });

    it("should handle acceptEncryptFile with custom acceptance function", async () => {
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      if (!channel.otherend) assert.fail("Channel creation failed");

      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(await createRandomVaultysId(), s1);
      const manager2 = new IdManager(await createRandomVaultysId(), s2);

      // First establish contact between the managers
      const contactChannel = MemoryChannel.createBidirectionnal();
      if (!contactChannel.otherend) assert.fail("Contact channel creation failed");

      await Promise.all([manager1.askContact(contactChannel), manager2.acceptContact(contactChannel.otherend)]);

      // Create an encrypted file
      let acceptCalled = false;
      manager2.acceptEncryptFile(channel.otherend, async (contact) => {
        acceptCalled = true;
        assert.equal(contact.toVersion(1).fingerprint, manager1.vaultysId.fingerprint);
        return true;
      });

      // Create a sample file and encrypt it
      const originalFile = {
        arrayBuffer: Buffer.from(randomBytes(256)),
        type: "application/json",
        name: "data.json",
      };

      const encryptedFile = await manager1.requestEncryptFile(channel, originalFile);
      assert.ok(encryptedFile, "Encryption should succeed when accept returns true");
      assert.ok(acceptCalled, "Accept function should be called");

      // Verify we can decrypt it back
      manager2.acceptDecryptFile(channel.otherend);

      const decryptedFile = await manager1.requestDecryptFile(channel, encryptedFile);
      assert.ok(decryptedFile, "Decryption should succeed");
      assert.deepEqual(decryptedFile.arrayBuffer, originalFile.arrayBuffer, "Decrypted content should match original");
    });

    it("should verify that acceptEncryptFile and acceptDecryptFile are the same function", async () => {
      const manager = new IdManager(
        await createRandomVaultysId(),
        MemoryStorage(() => ""),
      );
      assert.strictEqual(manager.acceptEncryptFile, manager.acceptDecryptFile, "acceptEncryptFile should be an alias of acceptDecryptFile");
    });
  });

  it("perform migration from version 0 to 1", async () => {
    const ids: IdManager[] = [];
    for (let i = 0; i < 2; i++) {
      for (let i = 0; i < 4; i++) {
        const vid = await createRandomVaultysId();
        const s1 = MemoryStorage(() => "");
        const id1 = new IdManager(vid, s1);
        for (let j = 0; j < 2; j++) {
          for (let i = 0; i < 4; i++) {
            const vid2 = await createRandomVaultysId();
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
      assert.equal(id.contacts.length + id.apps.length, 8);
      id.migrate(1);
      assert.equal(id.contacts.length + id.apps.length, 8);
    }
  }).timeout(20000);
});

describe("SRG v1 challenge with IdManager", () => {
  it("pass a challenge", async () => {
    for (let i = 0; i < 5; i++) {
      const id1 = await createRandomVaultysId();
      const channel = MemoryChannel.createBidirectionnal();
      if (!channel.otherend) assert.fail();
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);
      manager1.setProtocolVersion(1);
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

      const challengers = await Promise.all([manager1.startSRP(channel, "p2p", "auth", metadata1), manager2.acceptSRP(channel.otherend, "p2p", "auth", metadata2)]);

      //console.log(challengers);
      // assert.equal(contacts[0].did, manager2.vaultysId.did);
      // assert.equal(contacts[1].did, manager1.vaultysId.did);

      ///console.log(s2, s1);

      // assert.deepStrictEqual(s2.substore("contacts").get(manager1.vaultysId.did).metadata, metadata1);
      // assert.deepStrictEqual(s1.substore("contacts").get(manager2.vaultysId.did).metadata, metadata2);

      // assert.equal(s1.substore("wot").list().length, 1);
      // assert.equal(s2.substore("wot").list().length, 1);
      // console.log(Challenger.deserializeCertificate(s2.substore("wot").get(s2.substore("wot").list()[0])));
      // if (manager1.vaultysId.type === 0) {
      //   assert.equal(manager2.apps.length, 1);
      //   assert.equal(manager2.getApp(manager1.vaultysId.did)?.fingerprint, manager1.vaultysId.fingerprint);
      //   assert.ok(await manager1.verifyRelationshipCertificate(manager2.vaultysId.did));
      //   assert.ok(await manager2.verifyRelationshipCertificate(manager1.vaultysId.did));
      // } else {
      //   assert.equal(manager2.contacts.length, 1);
      //   assert.equal(manager2.getContact(manager1.vaultysId.did)?.fingerprint, manager1.vaultysId.fingerprint);
      //   manager2.setContactMetadata(manager1.vaultysId.did, "name", "salut");
      //   manager2.setContactMetadata(manager1.vaultysId.did, "group", "pro");
      //   assert.equal(manager2.getContactMetadata(manager1.vaultysId.did, "name"), "salut");
      //   assert.equal(manager2.getContactMetadata(manager1.vaultysId.did, "group"), "pro");
      //   assert.ok(await manager1.verifyRelationshipCertificate(manager2.vaultysId.did));
      //   assert.ok(await manager2.verifyRelationshipCertificate(manager1.vaultysId.did));
      // }
    }
  });

  it("fail a challenge if user1 refuse", async () => {
    for (let i = 0; i < 5; i++) {
      const id1 = await createRandomVaultysId();
      const channel = MemoryChannel.createBidirectionnal();
      if (!channel.otherend) assert.fail();
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);
      manager1.setProtocolVersion(1);
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

      try {
        await Promise.all([manager1.askContact(channel, metadata1, () => Promise.resolve(false)), manager2.acceptContact(channel.otherend, metadata2)]);
      } catch (e) {
        assert.equal((e as { message: string }).message, "Error: Contact refused");
      }
    }
  });

  it("fail a challenge if user2 refuse", async () => {
    for (let i = 0; i < 5; i++) {
      const id1 = await createRandomVaultysId();
      const channel = MemoryChannel.createBidirectionnal();
      if (!channel.otherend) assert.fail();
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);
      manager1.setProtocolVersion(1);
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

      try {
        await Promise.all([manager1.askContact(channel, metadata1), manager2.acceptContact(channel.otherend, metadata2, () => Promise.resolve(false))]);
      } catch (e) {
        assert.equal((e as { message: string }).message, "Error: Contact refused");
      }
    }
  });

  it("pass a challenge over encrypted Channel", async () => {
    for (let i = 0; i < 5; i++) {
      const id1 = await createRandomVaultysId();
      const channel = MemoryChannel.createBidirectionnal();
      if (!channel.otherend) assert.fail();
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);
      manager1.setProtocolVersion(1);
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

  it("perform PRF over Channel", async () => {
    for (let i = 0; i < 5; i++) {
      const id1 = await createRandomVaultysId();
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      if (!channel.otherend) assert.fail();
      // channel.setLogger((data) => console.log(data.toString("utf-8")));
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);
      manager1.setProtocolVersion(1);
      const manager2 = new IdManager(await VaultysId.generateOrganization(), s2);

      manager1.acceptPRF(channel);
      const result = await manager2.requestPRF(channel.otherend, "nostr");
      assert.deepEqual(result, await manager1.vaultysId.hmac("prf|nostr|prf"));
    }
  });

  it("perform decrypt over Channel", async () => {
    for (let i = 0; i < 5; i++) {
      const id1 = await createRandomVaultysId();
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      if (!channel.otherend) assert.fail();
      // channel.setLogger((data) => console.log(data.toString("utf-8")));
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);
      manager1.setProtocolVersion(1);
      const manager2 = new IdManager(await VaultysId.generateOrganization(), s2);

      const message = "test decrypt on demand";

      const toDecrypt = await VaultysId.encrypt(message, [manager1.vaultysId.id]);

      manager1.acceptDecrypt(channel);

      //console.log(toDecrypt);
      const result = await manager2.requestDecrypt(channel.otherend, Buffer.from(toDecrypt, "utf-8"));

      assert.deepEqual(result?.toString("utf-8"), message);
    }
  });

  describe("IdManager File Encryption/Decryption", () => {
    it("should encrypt and decrypt a file between two IdManagers", async () => {
      let channel = MemoryChannel.createEncryptedBidirectionnal();

      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(await createRandomVaultysId(), s1);
      manager1.setProtocolVersion(1);
      const manager2 = new IdManager(await createRandomVaultysId(), s2);

      // Create a sample file
      const fileContent = randomBytes(1024);
      const originalFile = {
        arrayBuffer: Buffer.from(fileContent),
        type: "application/octet-stream",
        name: "test.bin",
      };

      // Set up the decryption handler on manager2
      manager2.acceptDecryptFile(channel.otherend!);

      // Request encryption from manager1 to manager2
      const encryptedFile = await manager1.requestEncryptFile(channel, originalFile);

      assert.ok(encryptedFile, "Encryption failed");
      assert.equal(encryptedFile.type, originalFile.type, "File type should be preserved");
      assert.equal(encryptedFile.name, originalFile.name, "File name should be preserved");
      assert.ok(encryptedFile.arrayBuffer, "Encrypted data should be present");
      assert.notDeepEqual(encryptedFile.arrayBuffer, originalFile.arrayBuffer, "Encrypted data should be different from original");

      // Now decrypt the file
      channel = MemoryChannel.createEncryptedBidirectionnal();
      manager2.acceptDecryptFile(channel.otherend!);

      const decryptedFile = await manager1.requestDecryptFile(channel, encryptedFile);
      assert.ok(decryptedFile, "Decryption failed");
      assert.equal(decryptedFile.type, originalFile.type, "File type should be preserved after decryption");
      assert.equal(decryptedFile.name, originalFile.name, "File name should be preserved after decryption");
      assert.deepEqual(decryptedFile.arrayBuffer, originalFile.arrayBuffer, "Decrypted file should match the original");
    });

    it("should work with different file types and sizes", async () => {
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      if (!channel.otherend) assert.fail("Channel creation failed");
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(await createRandomVaultysId(), s1);
      manager1.setProtocolVersion(1);
      const manager2 = new IdManager(await createRandomVaultysId(), s2);

      // Test with different file types and sizes
      const testCases = [
        { size: 10, type: "text/plain", name: "small.txt" },
        { size: 1024, type: "application/pdf", name: "medium.pdf" },
        { size: 4096, type: "image/jpeg", name: "large.jpg" },
      ];

      for (const testCase of testCases) {
        const fileContent = randomBytes(testCase.size);
        const originalFile = {
          arrayBuffer: Buffer.from(fileContent),
          type: testCase.type,
          name: testCase.name,
        };

        manager2.acceptEncryptFile(channel.otherend);

        const encryptedFile = await manager1.requestEncryptFile(channel, originalFile);
        assert.ok(encryptedFile, `Encryption failed for ${testCase.name}`);

        manager2.acceptDecryptFile(channel.otherend);

        const decryptedFile = await manager1.requestDecryptFile(channel, encryptedFile);
        assert.ok(decryptedFile, `Decryption failed for ${testCase.name}`);
        assert.equal(decryptedFile.type, originalFile.type, `File type should be preserved for ${testCase.name}`);
        assert.equal(decryptedFile.name, originalFile.name, `File name should be preserved for ${testCase.name}`);
        assert.deepEqual(decryptedFile.arrayBuffer, originalFile.arrayBuffer, `Decrypted content should match original for ${testCase.name}`);
      }
    });

    it("should handle acceptDecryptFile with custom acceptance function", async () => {
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      if (!channel.otherend) assert.fail("Channel creation failed");

      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(await createRandomVaultysId(), s1);
      manager1.setProtocolVersion(1);
      const manager2 = new IdManager(await createRandomVaultysId(), s2);

      // First establish contact between the managers
      const contactChannel = MemoryChannel.createBidirectionnal();
      if (!contactChannel.otherend) assert.fail("Contact channel creation failed");

      await Promise.all([manager1.askContact(contactChannel), manager2.acceptContact(contactChannel.otherend)]);

      // Create a sample file
      const originalFile = {
        arrayBuffer: Buffer.from(randomBytes(512)),
        type: "text/plain",
        name: "test.txt",
      };

      // Test with accepting function that returns true
      let acceptCalled = false;
      manager2.acceptDecryptFile(channel.otherend, async (contact) => {
        acceptCalled = true;
        assert.equal(contact.toVersion(1).fingerprint, manager1.vaultysId.fingerprint);
        return true;
      });

      const encryptedFile = await manager1.requestEncryptFile(channel, originalFile);

      assert.ok(encryptedFile, "Encryption should succeed when accept returns true");
      assert.ok(acceptCalled, "Accept function should be called");

      // Test with accepting function that returns false

      acceptCalled = false;
      manager2.acceptDecryptFile(channel.otherend, async () => {
        acceptCalled = true;
        return false;
      });

      const failedResult = await manager1.requestEncryptFile(channel, originalFile);
      assert.ok(acceptCalled, "Accept function should be called even when rejecting");
      assert.equal(failedResult, null, "Encryption should fail when accept returns false");
    });

    it("should handle acceptEncryptFile with custom acceptance function", async () => {
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      if (!channel.otherend) assert.fail("Channel creation failed");

      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(await createRandomVaultysId(), s1);
      manager1.setProtocolVersion(1);
      const manager2 = new IdManager(await createRandomVaultysId(), s2);

      // First establish contact between the managers
      const contactChannel = MemoryChannel.createBidirectionnal();
      if (!contactChannel.otherend) assert.fail("Contact channel creation failed");

      await Promise.all([manager1.askContact(contactChannel), manager2.acceptContact(contactChannel.otherend)]);

      // Create an encrypted file
      let acceptCalled = false;
      manager2.acceptEncryptFile(channel.otherend, async (contact) => {
        acceptCalled = true;
        assert.equal(contact.toVersion(1).fingerprint, manager1.vaultysId.fingerprint);
        return true;
      });

      // Create a sample file and encrypt it
      const originalFile = {
        arrayBuffer: Buffer.from(randomBytes(256)),
        type: "application/json",
        name: "data.json",
      };

      const encryptedFile = await manager1.requestEncryptFile(channel, originalFile);
      assert.ok(encryptedFile, "Encryption should succeed when accept returns true");
      assert.ok(acceptCalled, "Accept function should be called");

      // Verify we can decrypt it back
      manager2.acceptDecryptFile(channel.otherend);

      const decryptedFile = await manager1.requestDecryptFile(channel, encryptedFile);
      assert.ok(decryptedFile, "Decryption should succeed");
      assert.deepEqual(decryptedFile.arrayBuffer, originalFile.arrayBuffer, "Decrypted content should match original");
    });

    it("should verify that acceptEncryptFile and acceptDecryptFile are the same function", async () => {
      const manager = new IdManager(
        await createRandomVaultysId(),
        MemoryStorage(() => ""),
      );
      manager.setProtocolVersion(1);
      assert.strictEqual(manager.acceptEncryptFile, manager.acceptDecryptFile, "acceptEncryptFile should be an alias of acceptDecryptFile");
    });
  });
});
