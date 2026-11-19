/**
 * Deterministic cross-language vectors for post-quantum identities
 * (rfc/PQ-ENCRYPTION.md §11): identity types 0x10-0x12, ML-KEM-768 key `k`,
 * PRF key, DHIES v3, and negative vectors.
 *
 *   npx tsx test/interops/generate-pq-identity-vectors.ts
 *
 * Writes test/interops/pq-identity-vectors.json and copies it to
 * ../go/test/compatibility/testdata/ and ../rust/tests/data/.
 * Running it twice produces byte-identical output.
 */
import { createHmac } from "crypto";
import { copyFileSync, mkdirSync, writeFileSync } from "fs";
import { dirname, resolve } from "path";
import { Buffer } from "buffer/";
import nacl from "tweetnacl";
import { encode } from "@msgpack/msgpack";
import VaultysId from "../../src/VaultysId";
import CypherManager from "../../src/KeyManager/CypherManager";
import { hash } from "../../src/crypto";
import { dhiesV2Decrypt, dhiesV2Encrypt, dhiesV3Encrypt } from "../../src/KeyManager/dhies";
import { deriveMlKemKeyPair, derivePrfKey, mlKemEncapsulate } from "../../src/pqCrypto";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import DilithiumManager from "../../src/KeyManager/DilithiumManager";
import HybridManager from "../../src/KeyManager/HybridManager";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const label = (text: string) => Buffer.from(text, "ascii");
/** Pinned test inputs: SHA-512 of a readable label, truncated. Never use such values outside tests. */
const pinned = (name: string, length: number) => Buffer.from(hash("sha512", label("VaultysID PQ test vector/" + name)).subarray(0, length));

type Alg = "dilithium" | "hybrid";
const ALG_NAME: Record<Alg, string> = { dilithium: "dilithium", hybrid: "dilithium_ed25519" };
const ROLE_NAME: Record<number, string> = { 0x10: "machine", 0x11: "person", 0x12: "organization" };

/** type || MessagePack secret record, as VaultysId.getSecret() writes it for a version 1 key manager. */
const pqSecret = (alg: Alg, type: number, seed: Buffer) => Buffer.concat([Buffer.from([type]), Buffer.from(encode(alg === "dilithium" ? { v: 1, s: seed } : { v: 1, alg: "hybrid", s: seed }))]);

const kmOf = (id: VaultysId) => id.keyManager as CypherManager;

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error("vector generation: " + message);
}

const rejectsId = (id: Buffer) => {
  try {
    VaultysId.fromId(id);
    return false;
  } catch {
    return true;
  }
};

const rejectsSecret = (secret: Buffer) => {
  try {
    VaultysId.fromSecret(secret);
    return false;
  } catch {
    return true;
  }
};

export async function generatePqIdentityVectors() {
  // ---- identities -------------------------------------------------------------------
  const identities: Record<string, any> = {};
  const ids: Record<string, VaultysId> = {};
  for (const alg of ["dilithium", "hybrid"] as Alg[]) {
    for (const type of [0x10, 0x11, 0x12]) {
      const name = `pq_${alg}_${ROLE_NAME[type]}`;
      const seed = pinned("seed/" + name, 64);
      const secret = pqSecret(alg, type, seed);
      const id = VaultysId.fromSecret(secret);
      const km = kmOf(id);
      assert(id.type === type && id.isPostQuantum(), name + ": type");
      assert(id.getSecret() === hex(secret), name + ": secret round trip");
      const ek = deriveMlKemKeyPair(seed).publicKey;
      const prfKey = derivePrfKey(seed);
      assert(Buffer.from(km.kem!.publicKey).equals(ek), name + ": ek");
      assert(Buffer.from(km.prfKey!).equals(prfKey), name + ": prf key");
      const parsed = VaultysId.fromId(id.id);
      assert(parsed.id.equals(id.id) && parsed.did === id.did, name + ": id round trip");
      ids[name] = id;
      identities[name] = {
        algorithm: ALG_NAME[alg],
        type,
        seed: hex(seed),
        secret: hex(secret),
        signingPublicKey: hex(km.signer.publicKey),
        cypherPublicKey: hex(km.cypher.publicKey),
        ek: hex(ek),
        ekSha256: hex(hash("sha256", ek)),
        prfKey: hex(prfKey),
        idLength: id.id.length,
        id: hex(id.id),
        did: id.did,
      };
    }
  }
  // A classical sender: any identity with an X25519 key can send DHIES v3 (§5.4).
  const classicalEntropy = pinned("entropy/classical_ed25519_person", 32);
  const classical = await VaultysId.fromEntropy(classicalEntropy, 1, "ed25519");
  ids.classical_ed25519_person = classical;
  identities.classical_ed25519_person = {
    algorithm: "ed25519",
    type: classical.type,
    entropy: hex(classicalEntropy),
    secret: classical.getSecret(),
    signingPublicKey: hex(classical.keyManager.signer.publicKey),
    cypherPublicKey: hex(classical.keyManager.cypher.publicKey),
    id: hex(classical.id),
    did: classical.did,
  };

  // ---- PRF ----------------------------------------------------------------------------
  const prfMessage = "VaultysID PRF test vector";
  const secretHashData = Buffer.from("OTP-12345", "utf-8");
  const prf = [];
  for (const name of Object.keys(identities).filter((n) => n.startsWith("pq_"))) {
    const id = ids[name];
    const km = kmOf(id);
    const mac = await id.hmac(prfMessage);
    const secretHash = km.getSecretHash(secretHashData);
    const prfKey = Buffer.from(identities[name].prfKey, "hex");
    // the formulas of §3.2, independently of CypherManager
    assert(
      mac &&
        mac.equals(
          Buffer.from(
            createHmac("sha256", prfKey)
              .update("VaultysID/" + prfMessage + "/end")
              .digest(),
          ),
        ),
      name + ": hmac formula",
    );
    assert(secretHash.equals(hash("sha256", Buffer.concat([secretHashData, label("secrethash"), prfKey]))), name + ": getSecretHash formula");
    prf.push({ identity: name, message: prfMessage, hmac: hex(mac), secretHashData: hex(secretHashData), secretHash: hex(secretHash) });
  }

  // ---- signatures ------------------------------------------------------------------------
  // VaultysId.sign() signs SHA-256("VAULTYS_RAW" || message) with hedged (randomized)
  // ML-DSA, which cannot be reproduced. These vectors use the deterministic variant of
  // FIPS 204 (rnd = 0, noble `extraEntropy: false`), a valid signature for any verifier,
  // with the same construction as the key managers: ML-DSA-87 alone for Dilithium,
  // sig_ed || ML-DSA-87(digest || sig_ed) for Hybrid.
  const signatureMessage = Buffer.from("VaultysID PQ signature test vector", "utf-8");
  const signatureDigest = hash("sha256", Buffer.concat([label("VAULTYS_RAW"), signatureMessage]));
  const signatures = [];
  for (const name of ["pq_dilithium_person", "pq_hybrid_person"]) {
    const id = ids[name];
    let signature: Buffer;
    if (id.keyManager instanceof HybridManager) {
      const km = id.keyManager as HybridManager;
      const edSignature = Buffer.from(ed25519.sign(signatureDigest, km.edSigner!.secretKey!));
      const pqSignature = Buffer.from(ml_dsa87.sign(Buffer.concat([signatureDigest, edSignature]), km.pqSigner!.secretKey!, { extraEntropy: false }));
      signature = Buffer.concat([edSignature, pqSignature]);
    } else {
      const km = id.keyManager as DilithiumManager;
      signature = Buffer.from(ml_dsa87.sign(signatureDigest, km.signer.secretKey!, { extraEntropy: false }));
    }
    assert(VaultysId.fromId(id.id).verify(signatureMessage, signature), name + ": signature does not verify");
    signatures.push({ identity: name, domain: "VAULTYS_RAW", message: hex(signatureMessage), digest: hex(signatureDigest), signature: hex(signature) });
  }

  // ---- DHIES v3 -------------------------------------------------------------------------
  const plaintexts: Record<string, Buffer> = {
    text: Buffer.from("VaultysID DHIES v3 cross-language test vector", "utf-8"),
    empty: Buffer.alloc(0),
    binary: Buffer.from(Array.from({ length: 300 }, (_, i) => i % 256)),
  };
  const cases: [string, string, string, string][] = [
    ["dilithium_to_dilithium", "pq_dilithium_person", "pq_dilithium_machine", "text"],
    ["hybrid_to_dilithium", "pq_hybrid_person", "pq_dilithium_organization", "empty"],
    ["classical_to_dilithium", "classical_ed25519_person", "pq_dilithium_person", "binary"],
    ["dilithium_to_hybrid", "pq_dilithium_organization", "pq_hybrid_machine", "text"],
    ["classical_to_hybrid", "classical_ed25519_person", "pq_hybrid_organization", "text"],
  ];
  const dhiesV3 = [];
  for (const [name, senderName, recipientName, plaintextName] of cases) {
    const sender = ids[senderName];
    const recipient = ids[recipientName];
    const senderKm = kmOf(sender);
    const recipientKm = kmOf(recipient);
    const plaintext = plaintexts[plaintextName];
    const ephemeralSecretKey = pinned("ephemeral/" + name, 32);
    const kemRandomness = pinned("kem-m/" + name, 32);
    const nonce = pinned("nonce/" + name, 24);
    const senderCypher = await senderKm.getCypher();
    const out = await dhiesV3Encrypt(plaintext, senderCypher.diffieHellman, senderKm.cypher.publicKey, recipientKm.cypher.publicKey, recipientKm.kem!.publicKey, {
      ephemeralSecretKey,
      nonce,
      kemRandomness,
    });

    // recompute every intermediate value from §5.2
    const ePk = Buffer.from(nacl.box.keyPair.fromSecretKey(ephemeralSecretKey).publicKey);
    const es = Buffer.from(nacl.scalarMult(ephemeralSecretKey, recipientKm.cypher.publicKey));
    const ss = Buffer.from(nacl.scalarMult(senderKm.cypher.secretKey!, recipientKm.cypher.publicKey));
    const { cipherText: kemCt, sharedSecret: kss } = mlKemEncapsulate(recipientKm.kem!.publicKey, kemRandomness);
    const info = Buffer.concat([label("VAULTYS_DHIES_V3"), ePk, senderKm.cypher.publicKey, recipientKm.cypher.publicKey, hash("sha256", recipientKm.kem!.publicKey), kemCt]);
    const k = hash("sha512", Buffer.concat([es, ss, kss, info])).subarray(0, 32);
    const expected = Buffer.concat([Buffer.from([0x03]), nonce, ePk, kemCt, Buffer.from(nacl.secretbox(plaintext, nonce, k))]);
    assert(out.equals(expected), name + ": output differs from §5.2");
    assert(out.length === plaintext.length + 1161, name + ": overhead");
    const opened = await recipient.dhiesDecrypt(out, sender.id);
    assert(opened && opened.equals(plaintext), name + ": does not decrypt");

    dhiesV3.push({
      name,
      sender: senderName,
      recipient: recipientName,
      plaintext: hex(plaintext),
      ephemeralSecretKey: hex(ephemeralSecretKey),
      kemRandomness: hex(kemRandomness),
      nonce: hex(nonce),
      ephemeralPublicKey: hex(ePk),
      es: hex(es),
      ss: hex(ss),
      kemCiphertext: hex(kemCt),
      kss: hex(kss),
      info: hex(info),
      key: hex(k),
      out: hex(out),
    });
  }

  // ---- negative vectors -------------------------------------------------------------------
  const pqPerson = ids.pq_dilithium_person;
  const pqPersonKm = kmOf(pqPerson);
  const classicalKm = kmOf(classical);
  const ek = pqPersonKm.kem!.publicKey;
  const pqRecord = (record: Record<string, unknown>, type = 0x11) => Buffer.concat([Buffer.from([type]), Buffer.from(encode(record))]);

  const invalidIds = [
    { name: "pq_type_with_ed25519_key_manager", reason: "an Ed25519 key manager under a PQ type (x of 32 bytes)", id: pqRecord({ v: 1, x: classicalKm.signer.publicKey, e: classicalKm.cypher.publicKey, k: ek }) },
    { name: "pq_id_missing_k", reason: "a PQ type byte on a Dilithium record without k", id: pqRecord({ v: 1, x: pqPersonKm.signer.publicKey, e: pqPersonKm.cypher.publicKey }) },
    { name: "pq_id_k_too_short", reason: "k of 1183 bytes", id: pqRecord({ v: 1, x: pqPersonKm.signer.publicKey, e: pqPersonKm.cypher.publicKey, k: ek.subarray(0, 1183) }) },
    { name: "pq_id_k_too_long", reason: "k of 1185 bytes", id: pqRecord({ v: 1, x: pqPersonKm.signer.publicKey, e: pqPersonKm.cypher.publicKey, k: Buffer.concat([ek, Buffer.from([0])]) }) },
    { name: "pq_id_version_0", reason: "PQ ids only exist in version 1", id: pqRecord({ v: 0, x: pqPersonKm.signer.publicKey, e: pqPersonKm.cypher.publicKey, k: ek }) },
    { name: "pq_id_e_too_short", reason: "e of 31 bytes", id: pqRecord({ v: 1, x: pqPersonKm.signer.publicKey, e: pqPersonKm.cypher.publicKey.subarray(0, 31), k: ek }) },
    { name: "reserved_type_0x13", reason: "type 0x13 is reserved (PQ FIDO2)", id: Buffer.concat([Buffer.from([0x13]), pqPerson.id.subarray(1)]) },
    { name: "reserved_type_0x14", reason: "type 0x14 is reserved (PQ FIDO2PRF)", id: Buffer.concat([Buffer.from([0x14]), pqPerson.id.subarray(1)]) },
  ].map((v) => {
    assert(rejectsId(v.id), v.name + " is accepted by TypeScript");
    return { name: v.name, reason: v.reason, id: hex(v.id) };
  });

  const pqDilithiumSeed = Buffer.from(identities.pq_dilithium_person.seed, "hex");
  const invalidSecrets = [
    { name: "pq_secret_version_0", reason: "PQ secrets only exist in version 1", secret: Buffer.concat([Buffer.from([0x11]), Buffer.from(encode({ v: 0, s: pqDilithiumSeed }))]) },
    { name: "pq_type_with_ed25519_secret", reason: "an Ed25519 secret under a PQ type", secret: Buffer.concat([Buffer.from([0x11]), Buffer.from(classical.getSecret(), "hex").subarray(1)]) },
    { name: "pq_secret_reserved_type_0x13", reason: "type 0x13 is reserved", secret: pqSecret("dilithium", 0x13, pqDilithiumSeed) },
  ].map((v) => {
    assert(rejectsSecret(v.secret), v.name + " is accepted by TypeScript");
    return { name: v.name, reason: v.reason, secret: hex(v.secret) };
  });

  // DHIES messages that a PQ recipient must reject
  const base = dhiesV3[0]; // dilithium_to_dilithium
  const baseOut = Buffer.from(base.out, "hex");
  const mutate = (f: (b: Buffer) => void) => {
    const copy = Buffer.from(baseOut);
    f(copy);
    return copy;
  };
  const sender = ids[base.sender];
  const recipient = ids[base.recipient];
  const recipientKm = kmOf(recipient);
  const senderCypher = await kmOf(sender).getCypher();
  const recipientCypher = await recipientKm.getCypher();
  // a well-formed DHIES v2 message to the recipient's X25519 key: valid for a classical
  // recipient holding the same X25519 key, but a PQ recipient must refuse it (§5.4)
  const v2Plaintext = Buffer.from("DHIES v2 to a post-quantum recipient", "utf-8");
  const v2 = await dhiesV2Encrypt(v2Plaintext, senderCypher.diffieHellman, kmOf(sender).cypher.publicKey, recipientKm.cypher.publicKey, {
    ephemeralSecretKey: pinned("ephemeral/v2_to_pq", 32),
    nonce: pinned("nonce/v2_to_pq", 24),
  });
  const v2Opened = await dhiesV2Decrypt(v2, recipientCypher.diffieHellman, recipientKm.cypher.publicKey, kmOf(sender).cypher.publicKey);
  assert(v2Opened && v2Opened.equals(v2Plaintext), "the v2 negative vector is not a valid v2 message");

  const invalidMessages = [
    { name: "dhies_v2_to_pq_recipient", reason: "a valid DHIES v2 message addressed to a PQ identity (anti-downgrade, §5.4)", sender: base.sender, ciphertext: v2 },
    { name: "wrong_sender", reason: "decrypted with another sender id", sender: "pq_hybrid_person", ciphertext: baseOut },
    { name: "tampered_kem_ciphertext", reason: "one bit flipped in kem_ct (ML-KEM implicit rejection, then secretbox failure)", sender: base.sender, ciphertext: mutate((b) => (b[57 + 100] ^= 0x01)) },
    { name: "tampered_ephemeral_key", reason: "one bit flipped in e_pk", sender: base.sender, ciphertext: mutate((b) => (b[25] ^= 0x02)) },
    { name: "low_order_ephemeral_key", reason: "e_pk = 0: es is all zeros", sender: base.sender, ciphertext: mutate((b) => b.fill(0, 25, 57)) },
    { name: "tampered_nonce", reason: "one bit flipped in the nonce", sender: base.sender, ciphertext: mutate((b) => (b[1] ^= 0x80)) },
    { name: "tampered_secretbox", reason: "one bit flipped in the secretbox tag", sender: base.sender, ciphertext: mutate((b) => (b[1145] ^= 0x01)) },
    { name: "wrong_version_byte", reason: "0x02 in front of a v3 body", sender: base.sender, ciphertext: mutate((b) => (b[0] = 0x02)) },
    { name: "truncated_below_minimum", reason: "1160 bytes, one less than the minimum", sender: base.sender, ciphertext: baseOut.subarray(0, 1160) },
  ];
  const invalidDhies = [];
  for (const v of invalidMessages) {
    const opened = await recipient.dhiesDecrypt(v.ciphertext, ids[v.sender].id);
    assert(opened === null, v.name + " is accepted by TypeScript");
    invalidDhies.push({ name: v.name, reason: v.reason, sender: v.sender, recipient: base.recipient, ciphertext: hex(v.ciphertext) });
  }

  return {
    description: "VaultysID post-quantum identities and DHIES v3 cross-language vectors (rfc/PQ-ENCRYPTION.md §11), generated by the TypeScript reference, deterministic",
    generator: "typescript/test/interops/generate-pq-identity-vectors.ts",
    notes: ["Seeds, entropy, ephemeral keys, ML-KEM randomness and nonces are pinned test values (SHA-512 of a label); never reuse them.", "secret = type || MessagePack {v: 1, s: seed} (Dilithium) or {v: 1, alg: 'hybrid', s: seed} (Hybrid).", "dhiesV3[].key is k of §5.2; es, ss, kss and info are intermediate values given for debugging.", "kemRandomness is the 32-byte m of FIPS 203 ML-KEM.Encaps_internal."],
    identities,
    prf,
    signatures,
    dhiesV3,
    negative: { ids: invalidIds, secrets: invalidSecrets, dhies: invalidDhies },
  };
}

if (require.main === module) {
  generatePqIdentityVectors()
    .then((vectors) => {
      const json = JSON.stringify(vectors, null, 2) + "\n";
      const main = resolve(__dirname, "pq-identity-vectors.json");
      writeFileSync(main, json);
      console.log("wrote", main);
      for (const target of [resolve(__dirname, "../../../go/test/compatibility/testdata/pq-identity-vectors.json"), resolve(__dirname, "../../../rust/tests/data/pq-identity-vectors.json")]) {
        mkdirSync(dirname(target), { recursive: true });
        copyFileSync(main, target);
        console.log("copied to", target);
      }
    })
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
