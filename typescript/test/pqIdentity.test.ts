import assert from "assert";
import { Buffer } from "buffer/";
import { encode } from "@msgpack/msgpack";
import { IdManager, MemoryChannel, MemoryStorage, VaultysId } from "..";
import "./shims";
import { hmac, randomBytes } from "../src/crypto";
import CypherManager from "../src/KeyManager/CypherManager";
import DilithiumManager from "../src/KeyManager/DilithiumManager";
import { DHIES_V3_MIN_LENGTH, DHIES_V3_TAG, dhiesV2Encrypt, dhiesV3Decrypt, dhiesV3Encrypt } from "../src/KeyManager/dhies";
import { decodeRecord } from "../src/KeyManager/validation";
import { deriveMlKemKeyPair, derivePrfKey, mlKemDecapsulate, MLKEM768_PK_LENGTH } from "../src/pqCrypto";
import { VaultysIdV2 } from "./lib-versions";

// rfc/PQ-ENCRYPTION.md: post-quantum identity types, ML-KEM key, PRF key, DHIES v3

const withType = (id: Buffer, type: number) => Buffer.concat([Buffer.from([type]), id.subarray(1)]);
const kmOf = (id: VaultysId) => id.keyManager as CypherManager & { seed: Buffer };

const classical = () => Promise.all([VaultysId.generatePerson(), VaultysId.generatePerson("dilithium"), VaultysId.generatePerson("dilithium_ed25519")]);
const postQuantum = () => Promise.all([VaultysId.generatePerson("dilithium", true), VaultysId.generatePerson("dilithium_ed25519", true)]);

describe("Post-quantum identities", () => {
  describe("types and roles", () => {
    it("uses 0x10 | role and keeps role checks", async () => {
      const machine = await VaultysId.generateMachine("dilithium", true);
      const person = await VaultysId.generatePerson("dilithium_ed25519", true);
      const organization = await VaultysId.generateOrganization("dilithium", true);
      assert.deepStrictEqual([machine.type, person.type, organization.type], [0x10, 0x11, 0x12]);
      assert.ok(machine.isMachine() && !machine.isPerson() && !machine.isHardware());
      assert.ok(person.isPerson() && !person.isMachine());
      assert.ok(machine.isPostQuantum() && person.isPostQuantum() && organization.isPostQuantum());
      for (const id of await classical()) assert.ok(!id.isPostQuantum());
    });

    it("refuses an Ed25519 key manager", async () => {
      await assert.rejects(VaultysId.generatePerson("ed25519", true), /require a dilithium/);
    });

    it("keeps version 1 and its DID when converted with toVersion", async () => {
      const id = await VaultysId.generatePerson("dilithium", true);
      const did = id.did;
      id.toVersion(0);
      assert.equal(id.version, 1);
      assert.equal(id.did, did);
    });
  });

  describe("key derivation and serialization", () => {
    it("derives k and the PRF key from the full seed", async () => {
      for (const id of await postQuantum()) {
        const km = kmOf(id);
        assert.ok(Buffer.from(km.kem!.publicKey).equals(deriveMlKemKeyPair(km.seed).publicKey));
        assert.ok(Buffer.from(km.prfKey!).equals(derivePrfKey(km.seed)));
        // independent from the X25519 secret key
        assert.ok(!Buffer.from(km.prfKey!).equals(Buffer.from(km.cypher.secretKey!)));
      }
    });

    it("serializes {v, x, e, k} with the expected lengths", async () => {
      const [dilithium, hybrid] = await postQuantum();
      assert.equal(dilithium.id.length, 3827);
      assert.equal(hybrid.id.length, 3859);
      for (const id of [dilithium, hybrid]) {
        const record = decodeRecord(id.id.subarray(1), "id");
        assert.deepStrictEqual(Object.keys(record), ["v", "x", "e", "k"]);
        assert.equal(record.v, 1);
        assert.equal((record.k as Uint8Array).length, MLKEM768_PK_LENGTH);
      }
    });

    it("round-trips through fromId and fromSecret", async () => {
      for (const id of await postQuantum()) {
        const pub = VaultysId.fromId(id.id);
        assert.equal(pub.type, id.type);
        assert.equal(pub.did, id.did);
        assert.ok(Buffer.from(kmOf(pub).kem!.publicKey).equals(Buffer.from(kmOf(id).kem!.publicKey)));
        const restored = VaultysId.fromSecret(id.getSecret());
        assert.equal(restored.type, id.type);
        assert.equal(restored.did, id.did);
        assert.deepStrictEqual(restored.didDocument, id.didDocument);
        assert.equal((await restored.hmac("test"))!.toString("hex"), (await id.hmac("test"))!.toString("hex"));
      }
    });

    it("gives the same entropy a different DID than the classical identity", async () => {
      const entropy = randomBytes(32);
      const pq = await VaultysId.fromEntropy(entropy, 0x11, "dilithium");
      const cl = await VaultysId.fromEntropy(entropy, 1, "dilithium");
      assert.notEqual(pq.did, cl.did);
      assert.equal(pq.keyManager.signer.publicKey.toString("hex"), cl.keyManager.signer.publicKey.toString("hex"));
      assert.equal((await VaultysId.fromEntropy(entropy, 0x11, "dilithium")).did, pq.did);
    });

    it("lists k in the DID document", async () => {
      const [id] = await postQuantum();
      const keys = id.didDocument.keyAgreement;
      assert.equal(keys.length, 2);
      assert.equal(keys[1].type, "MLKEM768KeyAgreementKey2025");
      assert.equal(keys[1].publicKeyMultibase, "m" + Buffer.from(kmOf(id).kem!.publicKey).toString("base64"));
      for (const cl of await classical()) assert.equal(cl.didDocument.keyAgreement.length, 1);
    });

    it("rejects malformed post-quantum ids", async () => {
      const [pq] = await postQuantum();
      const [ed, dilithium] = await classical();
      const record = decodeRecord(pq.id.subarray(1), "id");
      const reencode = (r: Record<string, unknown>) => Buffer.concat([Buffer.from([0x11]), Buffer.from(encode(r))]);
      const cases: [string, Buffer][] = [
        ["PQ type without k", withType(dilithium.id, 0x11)],
        ["PQ type with an Ed25519 key manager", withType(ed.id, 0x11)],
        ["classical type with k", withType(pq.id, 0x01)],
        ["version 0", reencode({ ...record, v: 0 })],
        ["k of the wrong length", reencode({ ...record, k: Buffer.alloc(32) })],
        ["reserved type 0x13", withType(pq.id, 0x13)],
        ["reserved type 0x14", withType(pq.id, 0x14)],
      ];
      for (const [name, id] of cases) assert.throws(() => VaultysId.fromId(id), /Invalid VaultysId id/, name);
    });

    it("is refused by the published 2.x library", async () => {
      const [pq] = await postQuantum();
      assert.throws(() => VaultysIdV2.fromId(pq.id));
    });
  });

  describe("PRF / HMAC key", () => {
    it("keys hmac() with the seed-derived PRF key", async () => {
      for (const id of await postQuantum()) {
        const expected = hmac("sha256", derivePrfKey(kmOf(id).seed), "VaultysID/message/end");
        assert.equal((await id.hmac("message"))!.toString("hex"), expected.toString("hex"));
      }
    });

    it("differs from the classical identity built from the same seed", async () => {
      const entropy = randomBytes(32);
      const pq = await VaultysId.fromEntropy(entropy, 0x11, "dilithium_ed25519");
      const cl = await VaultysId.fromEntropy(entropy, 1, "dilithium_ed25519");
      assert.notEqual((await pq.hmac("m"))!.toString("hex"), (await cl.hmac("m"))!.toString("hex"));
      assert.notEqual(pq.getOTPHmac(), cl.getOTPHmac());
    });

    it("encrypts and decrypts files", async () => {
      for (const id of await postQuantum()) {
        const manager = new IdManager(
          id,
          MemoryStorage(() => ""),
        );
        const file = { name: "a.txt", type: "text/plain", arrayBuffer: Buffer.from("post-quantum file") };
        const encrypted = await manager.encryptFile(file);
        const decrypted = await manager.decryptFile(encrypted!);
        assert.equal(decrypted.arrayBuffer.toString(), "post-quantum file");
        // a classical identity sharing the seed cannot decrypt it
        const twin = new IdManager(
          VaultysId.fromSecret(withType(Buffer.from(id.getSecret(), "hex"), 1)),
          MemoryStorage(() => ""),
        );
        await assert.rejects(twin.decryptFile(encrypted!), /Decryption failed/);
      }
    });
  });

  describe("DHIES", () => {
    it("uses v3 for post-quantum recipients and v2 otherwise, in every direction", async () => {
      const all = [...(await classical()), ...(await postQuantum())];
      for (const sender of all) {
        for (const recipient of all) {
          if (sender === recipient) continue;
          const encrypted = await sender.dhiesEncrypt("hello", recipient.id);
          assert.ok(encrypted);
          assert.equal(encrypted![0], recipient.isPostQuantum() ? DHIES_V3_TAG : 0x02);
          if (recipient.isPostQuantum()) assert.equal(encrypted!.length, DHIES_V3_MIN_LENGTH + 5);
          const decrypted = await recipient.dhiesDecrypt(encrypted!, sender.id);
          assert.equal(decrypted?.toString(), "hello");
        }
      }
    });

    it("authenticates the sender", async () => {
      const [alice, eve] = await classical();
      const [bob] = await postQuantum();
      const encrypted = await alice.dhiesEncrypt("hello", bob.id);
      assert.equal(await bob.dhiesDecrypt(encrypted!, eve.id), null);
    });

    it("makes post-quantum recipients reject v2", async () => {
      const [alice] = await classical();
      const [bob] = await postQuantum();
      const aliceCypher = await alice.keyManager.getCypher();
      const v2 = await dhiesV2Encrypt("hello", aliceCypher.diffieHellman, alice.keyManager.cypher.publicKey, bob.keyManager.cypher.publicKey);
      assert.equal(await bob.dhiesDecrypt(v2, alice.id), null);
    });

    it("rejects tampered ciphertexts", async () => {
      const [alice] = await classical();
      const [bob] = await postQuantum();
      const encrypted = await alice.dhiesEncrypt("hello", bob.id);
      for (const offset of [0, 1, 30, 100, 1144, encrypted!.length - 1]) {
        const tampered = Buffer.from(encrypted!);
        tampered[offset] ^= 0x01;
        assert.equal(await bob.dhiesDecrypt(tampered, alice.id), null, "offset " + offset);
      }
      assert.equal(await bob.dhiesDecrypt(encrypted!.subarray(0, DHIES_V3_MIN_LENGTH - 1), alice.id), null);
    });

    it("is deterministic with pinned randomness", async () => {
      const sender = (await DilithiumManager.createFromEntropy(Buffer.alloc(32, 1))) as DilithiumManager;
      const recipient = ((await DilithiumManager.createFromEntropy(Buffer.alloc(32, 2))) as DilithiumManager).enablePostQuantum();
      const testing = { ephemeralSecretKey: Buffer.alloc(32, 3), nonce: Buffer.alloc(24, 4), kemRandomness: Buffer.alloc(32, 5) };
      const senderCypher = await sender.getCypher();
      const encrypt = () => dhiesV3Encrypt("vector", senderCypher.diffieHellman, sender.cypher.publicKey, recipient.cypher.publicKey, recipient.kem!.publicKey, testing);
      const out = await encrypt();
      assert.ok(out.equals(await encrypt()));
      const recipientCypher = await recipient.getCypher();
      const decapsulate = async (ct: Buffer) => mlKemDecapsulate(ct, recipient.kem!.secretKey!);
      const decrypted = await dhiesV3Decrypt(out, recipientCypher.diffieHellman, decapsulate, recipient.cypher.publicKey, recipient.kem!.publicKey, sender.cypher.publicKey);
      assert.equal(decrypted?.toString(), "vector");
    });
  });

  describe("handshake (SRP) with classical identities", () => {
    it("exchanges contacts in both directions", async () => {
      for (const cl of await classical()) {
        for (const pq of await postQuantum()) {
          const m1 = new IdManager(
            cl,
            MemoryStorage(() => ""),
          );
          const m2 = new IdManager(
            pq,
            MemoryStorage(() => ""),
          );
          const channel = MemoryChannel.createBidirectionnal();
          const [c1, c2] = await Promise.all([m1.askContact(channel, { name: "cl" }), m2.acceptContact(channel.otherend!, { name: "pq" })]);
          assert.equal(c1.did, pq.did);
          assert.equal(c2.did, cl.did);
          assert.ok(c1.isPostQuantum() && !c2.isPostQuantum());
        }
      }
    });

    it("keeps k for stored contacts across a save and reload", async () => {
      const [cl] = await classical();
      const [pq] = await postQuantum();
      const store = MemoryStorage(() => "");
      const m1 = new IdManager(cl, store);
      const m2 = new IdManager(
        pq,
        MemoryStorage(() => ""),
      );
      const channel = MemoryChannel.createBidirectionnal();
      await Promise.all([m1.askContact(channel, {}), m2.acceptContact(channel.otherend!, {})]);

      const reloaded = new IdManager(cl, MemoryStorage(() => "").fromString(store.toString()));
      const contact = reloaded.getContact(pq.did)!;
      assert.ok(contact.isPostQuantum());
      assert.equal(contact.did, pq.did);
      const encrypted = await cl.dhiesEncrypt("hello", contact.id);
      assert.equal(encrypted![0], DHIES_V3_TAG);
      assert.equal((await pq.dhiesDecrypt(encrypted!, cl.id))?.toString(), "hello");
    });

    it("registers a post-quantum machine as an app", async () => {
      const [cl] = await classical();
      const server = await VaultysId.generateMachine("dilithium", true);
      const manager = new IdManager(
        cl,
        MemoryStorage(() => ""),
      );
      manager.saveContact(VaultysId.fromId(server.id));
      assert.equal(manager.contacts.length, 0);
      assert.equal(manager.apps.length, 1);
      assert.equal(manager.apps[0].did, server.did);
    });
  });
});
