import assert from "assert";
import "./shims";
import cbor from "cbor";
import { ed25519 } from "@noble/curves/ed25519.js";
import { encode } from "@msgpack/msgpack";
import { Buffer, Challenger, IdManager, MemoryChannel, MemoryStorage, VaultysId } from "../";
import { hash, randomBytes } from "../src/crypto";
import { deserialize, storagify, Store } from "../src/MemoryStorage";
import { DHIES_V2_TAG, dhiesV2Decrypt, dhiesV2Encrypt } from "../src/KeyManager/dhies";
import { DilithiumManager, Ed25519Manager, HybridManager } from "../src/KeyManager";
import SoftCredentials from "../src/platform/SoftCredentials";
import { enableSoftCredentials } from "../src/platform/softCredentialsConfig";
import { getWebAuthnProvider } from "../src/platform/webauthn";
import { PQ_COSE_ALG } from "../src/pqCrypto";
import { readFileSync } from "fs";
import { resolve } from "path";
import { generateSecurityV2Vectors } from "./interops/generate-security-v2-vectors";

type Alg = "ed25519" | "dilithium" | "dilithium_ed25519";

const sha256 = (data: Uint8Array) => hash("sha256", Buffer.from(data));
const allowAll = async () => true;

const reloadStore = (store: Store) =>
  storagify(
    deserialize(store.toString()),
    () => {},
    () => {},
  );

const connect = async (a: IdManager, b: IdManager) => {
  const channel = MemoryChannel.createBidirectionnal();
  const [contactOfA, contactOfB] = await Promise.all([a.askContact(channel), b.acceptContact(channel.otherend!)]);
  return { contactOfA, contactOfB };
};

const newManager = async (vid?: VaultysId) =>
  new IdManager(
    vid ?? (await VaultysId.generatePerson()),
    MemoryStorage(() => ""),
  );

describe("Breaking security changes", () => {
  describe("IdManager store / backup keep the exact identity", () => {
    const cases: { label: string; create: () => Promise<VaultysId>; manager: Function }[] = [
      { label: "ed25519 person", create: () => VaultysId.generatePerson("ed25519"), manager: Ed25519Manager },
      { label: "ed25519 machine", create: () => VaultysId.generateMachine("ed25519"), manager: Ed25519Manager },
      { label: "ed25519 organization (from entropy)", create: () => VaultysId.fromEntropy(randomBytes(32), 2, "ed25519"), manager: Ed25519Manager },
      { label: "dilithium person", create: () => VaultysId.generatePerson("dilithium"), manager: DilithiumManager },
      { label: "dilithium machine", create: () => VaultysId.generateMachine("dilithium"), manager: DilithiumManager },
      { label: "dilithium_ed25519 hybrid person", create: () => VaultysId.generatePerson("dilithium_ed25519"), manager: HybridManager },
      { label: "dilithium_ed25519 hybrid organization", create: () => VaultysId.generateOrganization("dilithium_ed25519"), manager: HybridManager },
    ];

    for (const { label, create, manager } of cases) {
      it(`round trips ${label} through store and backups`, async () => {
        const vid = await create();
        const original = new IdManager(
          vid,
          MemoryStorage(() => ""),
        );
        assert.equal(original.store.get("entropy"), undefined, "entropy alone must not be persisted");
        assert.ok(original.store.get("secret"));

        const check = (restored: IdManager | null) => {
          assert.ok(restored);
          assert.equal(restored!.vaultysId.did, vid.did);
          assert.equal(restored!.vaultysId.type, vid.type);
          assert.equal(restored!.vaultysId.id.toString("hex"), vid.id.toString("hex"));
          assert.ok(restored!.vaultysId.keyManager instanceof manager);
          assert.equal(restored!.vaultysId.getSecret(), vid.getSecret());
        };

        check(await IdManager.fromStore(reloadStore(original.store)));
        // twice: the restored store must itself restore identically
        check(await IdManager.fromStore(reloadStore((await IdManager.fromStore(reloadStore(original.store))).store)));
        check(await IdManager.importBackup(await original.exportBackup()));
      });
    }

    it("round trips an encrypted backup with its web of trust", async () => {
      const alice = await newManager(await VaultysId.generatePerson("dilithium_ed25519"));
      await connect(alice, await newManager());
      await connect(alice, await newManager(await VaultysId.generateMachine()));
      const backup = await alice.exportBackup(passphrase);
      const restored = await IdManager.importBackup(backup, passphrase);
      assert.ok(restored);
      assert.equal(restored!.vaultysId.did, alice.vaultysId.did);
      assert.equal(restored!.contacts.length + restored!.apps.length, 2);
      assert.equal(await restored!.verifyWebOfTrust(), true);
      assert.equal(await IdManager.importBackup(backup, "wrong passphrase"), null);
      assert.equal(await IdManager.importBackup(backup), null);
    }).timeout(30000);

    it("rejects empty passphrases", async () => {
      const alice = await newManager();
      await assert.rejects(alice.exportBackup(""), { message: "Empty passphrase is not allowed" });
    });

    it("rejects legacy entropy-only stores instead of guessing a (wrong) identity", async () => {
      const store = storagify({ metadata: {}, entropy: randomBytes(32) });
      await assert.rejects(IdManager.fromStore(store));
    });
  });

  describe("Handshake via IdManager", () => {
    it("acceptSRP refuses a first message that is not an INIT", async () => {
      const victim = await newManager();
      const attacker = await newManager(await VaultysId.generateMachine());
      // the attacker obtains a STEP1 where pk1 is the victim (relay) and sends it to the victim
      const honest = new Challenger(victim.vaultysId);
      honest.createChallenge("p2p", "auth");
      const relay = new Challenger(attacker.vaultysId);
      await relay.update(honest.getCertificate());

      const channel = MemoryChannel.createBidirectionnal();
      let acceptCalled = false;
      const accepting = victim.acceptSRP(channel.otherend!, "p2p", "auth", {}, async () => (acceptCalled = true));
      channel.send(relay.getCertificate());
      await assert.rejects(accepting);
      assert.equal(acceptCalled, false);
      const answer = await channel.receive();
      assert.deepEqual(Buffer.from(answer), Buffer.from([0]));
      assert.equal(victim.store.substore("wot").list().length, 0);
    });

    it("accept callbacks receive the REMOTE identity", async () => {
      const alice = await newManager();
      const bob = await newManager(await VaultysId.generateOrganization());
      const seen: string[] = [];
      const channel = MemoryChannel.createBidirectionnal();
      await Promise.all([alice.startSRP(channel, "p2p", "auth", {}, async (c) => (seen.push("alice saw " + VaultysId.fromId(c.id).toVersion(1).did), true)), bob.acceptSRP(channel.otherend!, "p2p", "auth", {}, async (c) => (seen.push("bob saw " + VaultysId.fromId(c.id).toVersion(1).did), true))]);
      assert.ok(seen.includes("alice saw " + VaultysId.fromId(bob.vaultysId.id).toVersion(1).did));
      assert.ok(seen.includes("bob saw " + VaultysId.fromId(alice.vaultysId.id).toVersion(1).did));
    });

    it("requestConnect / acceptConnect is an authenticated p2p/auth handshake saving the contact", async () => {
      const alice = await newManager();
      const bob = await newManager(await VaultysId.generateOrganization());
      let channel = MemoryChannel.createBidirectionnal();
      const [b, a] = await Promise.all([alice.requestConnect(channel), bob.acceptConnect(channel.otherend!)]);
      assert.equal(b.did, bob.vaultysId.did);
      assert.equal(a.did, alice.vaultysId.did);
      assert.ok(alice.getContact(bob.vaultysId.did));
      assert.ok(bob.getContact(alice.vaultysId.did));
      const cert = Challenger.deserializeCertificate(alice.getContact(bob.vaultysId.did)!.certificate!);
      assert.equal(cert.protocol, "p2p");
      assert.equal(cert.service, "auth");

      // pinned to the expected DID
      channel = MemoryChannel.createBidirectionnal();
      const [ok] = await Promise.all([alice.requestConnect(channel, bob.vaultysId.did), bob.acceptConnect(channel.otherend!, alice.vaultysId.did)]);
      assert.equal(ok.did, bob.vaultysId.did);

      const mallory = await newManager();
      channel = MemoryChannel.createBidirectionnal();
      const results = await Promise.allSettled([alice.requestConnect(channel, bob.vaultysId.did), mallory.acceptConnect(channel.otherend!)]);
      assert.equal(results[0].status, "rejected");
      assert.equal(results[1].status, "rejected");
    });
  });

  describe("Remote services are default deny", () => {
    it("acceptPRF without accept callback serves nothing", async () => {
      const alice = await newManager();
      const bob = await newManager();
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      alice.acceptPRF(channel);
      const result = await bob.requestPRF(channel.otherend!, "nostr");
      assert.notDeepEqual(result, await alice.vaultysId.hmac("prf|nostr|prf"));
      assert.equal(result?.length, 1);
    });

    it("acceptPRF never serves the file-encryption namespace to a remote peer", async () => {
      const alice = await newManager();
      const bob = await newManager();
      const appid = "encryption/" + randomBytes(32).toString("hex") + "/encryption";
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      alice.acceptPRF(channel, allowAll);
      const result = await bob.requestPRF(channel.otherend!, appid);
      assert.equal(result?.length, 1);
      assert.notDeepEqual(result, await alice.vaultysId.hmac("prf|" + appid + "|prf"));
    });

    it("acceptDecryptFile without accept callback serves nothing", async () => {
      const alice = await newManager();
      const bob = await newManager();
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      alice.acceptDecryptFile(channel.otherend!);
      const encrypted = await bob.requestEncryptFile(channel, { arrayBuffer: Buffer.from("hello"), type: "text/plain" });
      assert.equal(encrypted, null);
    });

    it("acceptSignFile without accept callback signs nothing", async () => {
      const alice = await newManager();
      const bob = await newManager();
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      alice.acceptSignFile(channel);
      const result = await bob.requestSignFile(channel.otherend!, { arrayBuffer: Buffer.from("hello"), type: "text/plain" });
      assert.equal(result, undefined);
      assert.equal(alice.store.substore("signatures").list().length, 0);
    });

    it("acceptDecrypt without accept callback decrypts nothing", async () => {
      const alice = await newManager();
      const bob = await newManager();
      const toDecrypt = await VaultysId.encrypt("secret", [alice.vaultysId.id]);
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      const results = await Promise.allSettled([alice.acceptDecrypt(channel), bob.requestDecrypt(channel.otherend!, Buffer.from(toDecrypt, "utf-8"))]);
      assert.equal(results[0].status, "rejected");
      assert.equal(results[1].status, "rejected");
    });
  });

  describe("DHIES v2", () => {
    for (const alg of ["ed25519", "dilithium", "dilithium_ed25519"] as Alg[]) {
      it(`round trips and authenticates the sender (${alg})`, async () => {
        const alice = await VaultysId.generatePerson(alg);
        const bob = await VaultysId.generateMachine(alg);
        const mallory = await VaultysId.generatePerson(alg);
        const message = "attack at dawn";
        const encrypted = (await alice.dhiesEncrypt(message, bob.id))!;
        assert.equal(encrypted[0], DHIES_V2_TAG);
        assert.equal(encrypted.length, 1 + 24 + 32 + 16 + Buffer.from(message).length);
        assert.equal((await bob.dhiesDecrypt(encrypted, alice.id))?.toString("utf-8"), message);
        assert.equal((await bob.dhiesDecrypt(encrypted, alice.id.toString("hex")))?.toString("utf-8"), message);
        // forged sender: Mallory's message can't pass as Alice's, and vice versa
        const forged = (await mallory.dhiesEncrypt(message, bob.id))!;
        assert.equal(await bob.dhiesDecrypt(forged, alice.id), null);
        assert.equal(await bob.dhiesDecrypt(encrypted, mallory.id), null);
        // only the recipient
        assert.equal(await mallory.dhiesDecrypt(encrypted, alice.id), null);
        // tampering
        for (const i of [0, 1, 30, 60, encrypted.length - 1]) {
          const t = Buffer.from(encrypted);
          t[i] ^= 0x01;
          assert.equal(await bob.dhiesDecrypt(t, alice.id), null);
        }
        assert.equal(await bob.dhiesDecrypt(encrypted.subarray(0, 72), alice.id), null);
        assert.equal(await bob.dhiesDecrypt(Buffer.from([]), alice.id), null);
      });
    }

    it("follows the spec construction exactly", async () => {
      const sender = nacl_keyPair();
      const recipient = nacl_keyPair();
      const ephemeral = randomBytes(32);
      const nonce = randomBytes(24);
      const dhS = async (pk: Buffer) => Buffer.from(scalarMult(sender.secretKey, pk));
      const dhR = async (pk: Buffer) => Buffer.from(scalarMult(recipient.secretKey, pk));
      const out = await dhiesV2Encrypt("hello", dhS, sender.publicKey, recipient.publicKey, { ephemeralSecretKey: ephemeral, nonce });
      const ePk = Buffer.from(scalarMultBase(ephemeral));
      assert.deepEqual(out.subarray(0, 1), Buffer.from([2]));
      assert.deepEqual(out.subarray(1, 25), nonce);
      assert.deepEqual(out.subarray(25, 57), ePk);
      const es = scalarMult(ephemeral, recipient.publicKey);
      const ss = scalarMult(sender.secretKey, recipient.publicKey);
      const k = hash("sha512", Buffer.concat([Buffer.from(es), Buffer.from(ss), Buffer.from("VAULTYS_DHIES_V2"), ePk, sender.publicKey, recipient.publicKey])).subarray(0, 32);
      const ct = secretbox(Buffer.from("hello"), nonce, k);
      assert.deepEqual(out.subarray(57), Buffer.from(ct));
      assert.equal((await dhiesV2Decrypt(out, dhR, recipient.publicKey, sender.publicKey))?.toString(), "hello");
      // low order point as ephemeral key gives an all-zero shared secret: rejected
      const lowOrder = Buffer.concat([out.subarray(0, 25), Buffer.alloc(32), out.subarray(57)]);
      assert.equal(await dhiesV2Decrypt(lowOrder, dhR, recipient.publicKey, sender.publicKey), null);
    });
  });

  describe("Signature domains", () => {
    it("VAULTYS_RAW, VAULTYS_SIGN and VAULTYS_HANDSHAKE_V1 never cross-verify", async () => {
      for (const alg of ["ed25519", "dilithium_ed25519"] as Alg[]) {
        const id = await VaultysId.generatePerson(alg);
        const data = randomBytes(64);
        const raw = await id.sign(data);
        const app = await id.signChallenge(data);
        const hs = await id.signHandshake(data);
        assert.ok(id.verify(data, raw));
        assert.ok(id.verifyChallenge(data, app, false));
        assert.ok(id.verifyHandshake(data, hs));
        assert.ok(!id.verifyChallenge(data, raw, false) && !id.verifyHandshake(data, raw));
        assert.ok(!id.verify(data, app) && !id.verifyHandshake(data, app));
        assert.ok(!id.verify(data, hs) && !id.verifyChallenge(data, hs, false));
        assert.ok(id.keyManager.verify(hash("sha256", Buffer.concat([Buffer.from("VAULTYS_RAW"), data])), raw));
        // a raw signature is not a signature of the data itself
        assert.ok(!id.keyManager.verify(data, raw));
      }
    });
  });

  describe("OTP", () => {
    it("is shared by both parties only, and uses a 64-bit counter", async () => {
      const alice = await newManager();
      const bob = await newManager(await VaultysId.generateOrganization());
      const { contactOfA: bobSeenByAlice, contactOfB: aliceSeenByBob } = await connect(alice, bob);
      const t = 1_700_000_000_000;
      const otpA = await alice.vaultysId.getOTP(bobSeenByAlice, "password", 1000, t);
      const otpB = await bob.vaultysId.getOTP(aliceSeenByBob, "password", 1000, t);
      assert.equal(otpA, otpB);
      assert.equal(otpA.length, 64);
      // a third party knowing the (public) certificate can't compute it
      const eve = await VaultysId.generatePerson();
      assert.notEqual(await eve.getOTP(bobSeenByAlice, "password", 1000, t), otpA);
      // prefix and time window matter
      assert.notEqual(await alice.vaultysId.getOTP(bobSeenByAlice, "other", 1000, t), otpA);
      assert.notEqual(await alice.vaultysId.getOTP(bobSeenByAlice, "password", 1000, t + 1000), otpA);
      // no more 1-byte truncation of the counter: counters 0 and 256 differ
      assert.notEqual(await alice.vaultysId.getOTP(bobSeenByAlice, "p", 1, 0), await alice.vaultysId.getOTP(bobSeenByAlice, "p", 1, 256));
      await assert.rejects(alice.vaultysId.getOTP(VaultysId.fromId(bob.vaultysId.id)), { message: "no certificate, cannot derive OTP" });
    });
  });

  describe("Untrusted parsing", () => {
    it("fromId / fromSecret reject malformed input with a plain Error", async () => {
      const ed = await VaultysId.generatePerson();
      const badIds: (Buffer | string)[] = ["", "00", "ff" + ed.id.toString("hex").slice(2), randomBytes(77), Buffer.concat([Buffer.from([1]), Buffer.from(encode({ v: 1, x: randomBytes(31), e: randomBytes(32) }))]), Buffer.concat([Buffer.from([1]), Buffer.from(encode({ v: 1, x: randomBytes(32), e: randomBytes(5) }))]), Buffer.concat([Buffer.from([1]), Buffer.from(encode({ v: 1, x: "nope", e: randomBytes(32) }))]), Buffer.concat([Buffer.from([3]), Buffer.from(encode({ v: 1, c: randomBytes(10), e: randomBytes(32) }))]), Buffer.concat([Buffer.from([1]), Buffer.from(encode([1, 2, 3]))]), ed.id.subarray(0, 40)];
      for (const id of badIds) {
        assert.throws(
          () => VaultysId.fromId(id),
          (e: Error) => e.constructor === Error && e.message.startsWith("Invalid VaultysId id"),
        );
      }
      const badSecrets = ["", "00", randomBytes(77).toString("hex"), "01" + Buffer.from(encode({ v: 1, x: randomBytes(10), e: randomBytes(32) })).toString("hex"), ed.getSecret().slice(0, 50)];
      for (const secret of badSecrets) {
        assert.throws(
          () => VaultysId.fromSecret(secret),
          (e: Error) => e.constructor === Error && e.message.startsWith("Invalid VaultysId secret"),
        );
      }
    });

    it("decrypt accepts a hex string sender id", async () => {
      const alice = await VaultysId.generatePerson();
      const bob = await VaultysId.generatePerson();
      const msg = await alice.signcrypt("hello bob", [bob.id]);
      assert.equal(await bob.decrypt(msg, alice.id.toString("hex")), "hello bob");
      assert.equal(await bob.decrypt(msg, alice.id), "hello bob");
    });
  });

  describe("WebAuthn", () => {
    it("never falls back silently to SoftCredentials", async () => {
      enableSoftCredentials(false);
      try {
        assert.throws(() => getWebAuthnProvider());
        await assert.rejects(SoftCredentials.create(SoftCredentials.createRequest(-8)));
        // parsing a public FIDO2 id needs no authenticator
        enableSoftCredentials(true);
        const attestation = await SoftCredentials.create(SoftCredentials.createRequest(-8));
        enableSoftCredentials(false);
        const vid = await VaultysId.fido2FromAttestation(attestation);
        assert.ok(VaultysId.fromId(vid.id));
        await assert.rejects(vid.signChallenge(Buffer.from("x")));
      } finally {
        enableSoftCredentials(true);
      }
      assert.ok(getWebAuthnProvider());
    });

    it("assertions require webauthn.get, user presence and the configured rpId/origin", () => {
      const sk = ed25519.utils.randomSecretKey();
      const cose = cbor.encode(
        new Map<number, number | Uint8Array>([
          [1, 1],
          [3, -8],
          [-1, 6],
          [-2, ed25519.getPublicKey(sk)],
        ]),
      );
      const make = (type: string, flags: number, rpId = "Vaultys ID", origin = "test") => {
        const clientDataJSON = Buffer.from(JSON.stringify({ type, challenge: "abc", origin }));
        const authenticatorData = Buffer.concat([sha256(Buffer.from(rpId)), Buffer.from([flags]), Buffer.alloc(4)]);
        const signature = Buffer.from(ed25519.sign(Buffer.concat([authenticatorData, sha256(clientDataJSON)]), sk));
        return { authenticatorData, clientDataJSON, signature };
      };
      assert.equal(SoftCredentials.simpleVerify(cose, make("webauthn.get", 0x05), true), true);
      assert.equal(SoftCredentials.simpleVerify(cose, make("webauthn.get", 0x01), false), true);
      assert.equal(SoftCredentials.simpleVerify(cose, make("webauthn.create", 0x05), true), false);
      assert.equal(SoftCredentials.simpleVerify(cose, make("webauthn.get", 0x04), true), false);
      assert.equal(SoftCredentials.simpleVerify(cose, make("webauthn.get", 0x04), false), false);
      assert.equal(SoftCredentials.simpleVerify(cose, make("webauthn.get", 0x01), true), false);
      assert.equal(SoftCredentials.simpleVerify(cose, make("webauthn.get", 0x05), true, { rpId: "Vaultys ID", origin: "test" }), true);
      assert.equal(SoftCredentials.simpleVerify(cose, make("webauthn.get", 0x05, "evil.com"), true, { rpId: "Vaultys ID" }), false);
      assert.equal(SoftCredentials.simpleVerify(cose, make("webauthn.get", 0x05, "Vaultys ID", "https://evil.com"), true, { origin: "test" }), false);
      assert.equal(SoftCredentials.simpleVerify(cose, { authenticatorData: Buffer.alloc(10), clientDataJSON: Buffer.from("{}"), signature: Buffer.alloc(64) }, false), false);
    });

    it("FIDO2 Dilithium5 credentials expose their public key", async () => {
      const attestation = await SoftCredentials.create(SoftCredentials.createRequest(PQ_COSE_ALG.DILITHIUM5));
      const vid = await VaultysId.fido2FromAttestation(attestation);
      assert.equal(vid.keyManager.signer.publicKey.length, 2592);
      const restored = VaultysId.fromId(vid.id);
      assert.equal(restored.keyManager.signer.publicKey.length, 2592);
      const signature = await vid.signChallenge(Buffer.from("hello"));
      assert.ok(restored.verifyChallenge(Buffer.from("hello"), signature, true));
    });
  });
});

describe("Cross-language security-v2 vectors", () => {
  it("committed vectors are reproducible and valid", async () => {
    const committed = JSON.parse(readFileSync(resolve(__dirname, "interops/security-v2-vectors.json"), "utf-8"));
    const regenerated = JSON.parse(JSON.stringify(await generateSecurityV2Vectors()));
    assert.deepStrictEqual(regenerated, committed);

    const alice = VaultysId.fromSecret(committed.identities.alice.secret);
    const bob = VaultysId.fromSecret(committed.identities.bob.secret);
    assert.equal(alice.id.toString("hex"), committed.identities.alice.id);
    assert.equal(bob.id.toString("hex"), committed.identities.bob.id);
    assert.equal(await Challenger.verifyCertificate(Buffer.from(committed.handshake.complete, "hex")), true);
    const unsigned = Buffer.from(committed.handshake.unsignedBytes, "hex");
    assert.equal(hash("sha256", Buffer.concat([Buffer.from("VAULTYS_HANDSHAKE_V1"), unsigned])).toString("hex"), committed.handshake.handshakeDigest);
    assert.ok(VaultysId.fromId(committed.identities.alice.id).verifyHandshake(unsigned, Buffer.from(committed.handshake.sign1, "hex")));
    const plaintext = await bob.dhiesDecrypt(Buffer.from(committed.dhiesV2.ciphertext, "hex"), alice.id);
    assert.equal(plaintext?.toString("utf-8"), committed.dhiesV2.plaintext);
    assert.ok(VaultysId.fromId(committed.identities.alice.id).verify(Buffer.from(committed.rawSignature.messageHex, "hex"), Buffer.from(committed.rawSignature.signature, "hex")));
  });
});

// small nacl helpers kept local to the spec-construction test
import nacl from "tweetnacl";
const passphrase = "correct horse battery staple";
const nacl_keyPair = () => {
  const kp = nacl.box.keyPair();
  return { publicKey: Buffer.from(kp.publicKey), secretKey: Buffer.from(kp.secretKey) };
};
const scalarMult = (sk: Uint8Array, pk: Uint8Array) => nacl.scalarMult(sk, pk);
const scalarMultBase = (sk: Uint8Array) => nacl.scalarMult.base(sk);
const secretbox = (m: Uint8Array, n: Uint8Array, k: Uint8Array) => nacl.secretbox(m, n, k);
