import nacl from "tweetnacl";
import { Buffer } from "buffer/";
import { hash, randomBytes, secureErase } from "../crypto";
import { mlKemEncapsulate, MLKEM768_CT_LENGTH, MLKEM768_PK_LENGTH } from "../pqCrypto";

/**
 * DHIES v2 — sender-authenticated Diffie-Hellman Integrated Encryption Scheme.
 *
 *   (e_sk, e_pk) = fresh X25519 keypair
 *   es = X25519(e_sk, R_pk); ss = X25519(S_sk, R_pk)   (rejected if all zeros)
 *   info = "VAULTYS_DHIES_V2" || e_pk || S_pk || R_pk
 *   k = SHA-512(es || ss || info)[0:32]
 *   ct = XSalsa20-Poly1305 secretbox(plaintext, nonce(24), k)
 *   output = 0x02 || nonce || e_pk || ct
 */

export const DHIES_V2_TAG = 0x02;
export const DHIES_V2_INFO = Buffer.from("VAULTYS_DHIES_V2", "ascii");
const NONCE_LENGTH = nacl.secretbox.nonceLength; // 24
const KEY_LENGTH = 32;
const MAC_LENGTH = nacl.secretbox.overheadLength; // 16
export const DHIES_V2_MIN_LENGTH = 1 + NONCE_LENGTH + KEY_LENGTH + MAC_LENGTH;

/** X25519 with our static secret key (may require a hardware round-trip, hence async). */
export type StaticDiffieHellman = (publicKey: Buffer) => Promise<Buffer | Uint8Array>;

const isAllZero = (data: Uint8Array) => {
  let acc = 0;
  for (let i = 0; i < data.length; i++) acc |= data[i];
  return acc === 0;
};

const checkKey = (key: Uint8Array, name: string) => {
  if (!(key instanceof Uint8Array) || key.length !== KEY_LENGTH) throw new Error(`DHIES: invalid ${name}`);
};

const deriveKey = (es: Uint8Array, ss: Uint8Array, ePk: Uint8Array, sPk: Uint8Array, rPk: Uint8Array) => {
  if (isAllZero(es) || isAllZero(ss)) throw new Error("DHIES: degenerate shared secret");
  const material = Buffer.concat([Buffer.from(es), Buffer.from(ss), DHIES_V2_INFO, Buffer.from(ePk), Buffer.from(sPk), Buffer.from(rPk)]);
  const digest = hash("sha512", material);
  const k = Buffer.from(digest.subarray(0, KEY_LENGTH));
  secureErase(material);
  secureErase(digest);
  return k;
};

/**
 * Encrypt `message` from the sender (static DH + public key) to `recipientPublicKey`.
 * `testing` lets deterministic vector generators pin the ephemeral key and nonce;
 * never use it in production code.
 */
export async function dhiesV2Encrypt(message: string | Uint8Array, senderDH: StaticDiffieHellman, senderPublicKey: Uint8Array, recipientPublicKey: Uint8Array, testing?: { ephemeralSecretKey?: Uint8Array; nonce?: Uint8Array }): Promise<Buffer> {
  checkKey(senderPublicKey, "sender public key");
  checkKey(recipientPublicKey, "recipient public key");
  const plaintext = typeof message === "string" ? Buffer.from(message, "utf8") : Buffer.from(message);

  const ephemeral = testing?.ephemeralSecretKey ? nacl.box.keyPair.fromSecretKey(Buffer.from(testing.ephemeralSecretKey)) : nacl.box.keyPair();
  const nonce = testing?.nonce ? Buffer.from(testing.nonce) : randomBytes(NONCE_LENGTH);
  if (nonce.length !== NONCE_LENGTH) throw new Error("DHIES: invalid nonce");

  const es = nacl.scalarMult(ephemeral.secretKey, recipientPublicKey);
  const ss = Buffer.from(await senderDH(Buffer.from(recipientPublicKey)));
  try {
    const k = deriveKey(es, ss, ephemeral.publicKey, senderPublicKey, recipientPublicKey);
    const ct = nacl.secretbox(plaintext, nonce, k);
    secureErase(k);
    return Buffer.concat([Buffer.from([DHIES_V2_TAG]), nonce, Buffer.from(ephemeral.publicKey), Buffer.from(ct)]);
  } finally {
    secureErase(es);
    secureErase(ss);
    secureErase(ephemeral.secretKey);
  }
}

/**
 * Decrypt a DHIES v2 message with our static DH, authenticating that it was
 * produced by the owner of `senderPublicKey`. Returns null on any failure.
 */
export async function dhiesV2Decrypt(encrypted: Uint8Array, recipientDH: StaticDiffieHellman, recipientPublicKey: Uint8Array, senderPublicKey: Uint8Array): Promise<Buffer | null> {
  try {
    checkKey(senderPublicKey, "sender public key");
    checkKey(recipientPublicKey, "recipient public key");
    if (!(encrypted instanceof Uint8Array) || encrypted.length < DHIES_V2_MIN_LENGTH || encrypted[0] !== DHIES_V2_TAG) return null;
    const data = Buffer.from(encrypted);
    const nonce = data.subarray(1, 1 + NONCE_LENGTH);
    const ePk = data.subarray(1 + NONCE_LENGTH, 1 + NONCE_LENGTH + KEY_LENGTH);
    const ct = data.subarray(1 + NONCE_LENGTH + KEY_LENGTH);

    const es = Buffer.from(await recipientDH(Buffer.from(ePk)));
    const ss = Buffer.from(await recipientDH(Buffer.from(senderPublicKey)));
    try {
      const k = deriveKey(es, ss, ePk, senderPublicKey, recipientPublicKey);
      const plaintext = nacl.secretbox.open(ct, nonce, k);
      secureErase(k);
      return plaintext ? Buffer.from(plaintext) : null;
    } finally {
      secureErase(es);
      secureErase(ss);
    }
  } catch {
    return null;
  }
}

/**
 * DHIES v3 — DHIES v2 plus an ML-KEM-768 encapsulation to a post-quantum
 * recipient (rfc/PQ-ENCRYPTION.md §5). Confidential if either X25519 or
 * ML-KEM-768 holds; sender authentication still relies on X25519 (ss).
 *
 *   (kem_ct, kss) = ML-KEM-768.Encaps(R_ek)
 *   info = "VAULTYS_DHIES_V3" || e_pk || S_pk || R_pk || SHA-256(R_ek) || kem_ct
 *   k = SHA-512(es || ss || kss || info)[0:32]
 *   output = 0x03 || nonce || e_pk || kem_ct || ct
 */

export const DHIES_V3_TAG = 0x03;
export const DHIES_V3_INFO = Buffer.from("VAULTYS_DHIES_V3", "ascii");
export const DHIES_V3_MIN_LENGTH = 1 + NONCE_LENGTH + KEY_LENGTH + MLKEM768_CT_LENGTH + MAC_LENGTH;

/** ML-KEM-768 decapsulation with our decapsulation key. */
export type KemDecapsulate = (cipherText: Buffer) => Promise<Buffer | Uint8Array>;

const checkKemKey = (key: Uint8Array) => {
  if (!(key instanceof Uint8Array) || key.length !== MLKEM768_PK_LENGTH) throw new Error("DHIES: invalid recipient ML-KEM public key");
};

const deriveKeyV3 = (es: Uint8Array, ss: Uint8Array, kss: Uint8Array, ePk: Uint8Array, sPk: Uint8Array, rPk: Uint8Array, rEk: Uint8Array, kemCt: Uint8Array) => {
  if (isAllZero(es) || isAllZero(ss)) throw new Error("DHIES: degenerate shared secret");
  const material = Buffer.concat([Buffer.from(es), Buffer.from(ss), Buffer.from(kss), DHIES_V3_INFO, Buffer.from(ePk), Buffer.from(sPk), Buffer.from(rPk), hash("sha256", rEk), Buffer.from(kemCt)]);
  const digest = hash("sha512", material);
  const k = Buffer.from(digest.subarray(0, KEY_LENGTH));
  secureErase(material);
  secureErase(digest);
  return k;
};

/**
 * Encrypt `message` from the sender (static DH + public key) to a post-quantum
 * recipient. `testing` pins the ephemeral key, the nonce and the ML-KEM
 * encapsulation randomness for deterministic vectors; never use it in production code.
 */
export async function dhiesV3Encrypt(message: string | Uint8Array, senderDH: StaticDiffieHellman, senderPublicKey: Uint8Array, recipientPublicKey: Uint8Array, recipientKemPublicKey: Uint8Array, testing?: { ephemeralSecretKey?: Uint8Array; nonce?: Uint8Array; kemRandomness?: Uint8Array }): Promise<Buffer> {
  checkKey(senderPublicKey, "sender public key");
  checkKey(recipientPublicKey, "recipient public key");
  checkKemKey(recipientKemPublicKey);
  const plaintext = typeof message === "string" ? Buffer.from(message, "utf8") : Buffer.from(message);

  const ephemeral = testing?.ephemeralSecretKey ? nacl.box.keyPair.fromSecretKey(Buffer.from(testing.ephemeralSecretKey)) : nacl.box.keyPair();
  const nonce = testing?.nonce ? Buffer.from(testing.nonce) : randomBytes(NONCE_LENGTH);
  if (nonce.length !== NONCE_LENGTH) throw new Error("DHIES: invalid nonce");

  const es = nacl.scalarMult(ephemeral.secretKey, recipientPublicKey);
  const ss = Buffer.from(await senderDH(Buffer.from(recipientPublicKey)));
  const { cipherText: kemCt, sharedSecret: kss } = mlKemEncapsulate(recipientKemPublicKey, testing?.kemRandomness);
  try {
    const k = deriveKeyV3(es, ss, kss, ephemeral.publicKey, senderPublicKey, recipientPublicKey, recipientKemPublicKey, kemCt);
    const ct = nacl.secretbox(plaintext, nonce, k);
    secureErase(k);
    return Buffer.concat([Buffer.from([DHIES_V3_TAG]), nonce, Buffer.from(ephemeral.publicKey), kemCt, Buffer.from(ct)]);
  } finally {
    secureErase(es);
    secureErase(ss);
    secureErase(kss);
    secureErase(ephemeral.secretKey);
  }
}

/**
 * Decrypt a DHIES v3 message with our static DH and ML-KEM decapsulation,
 * authenticating that it was produced by the owner of `senderPublicKey`.
 * Returns null on any failure.
 */
export async function dhiesV3Decrypt(encrypted: Uint8Array, recipientDH: StaticDiffieHellman, recipientDecapsulate: KemDecapsulate, recipientPublicKey: Uint8Array, recipientKemPublicKey: Uint8Array, senderPublicKey: Uint8Array): Promise<Buffer | null> {
  try {
    checkKey(senderPublicKey, "sender public key");
    checkKey(recipientPublicKey, "recipient public key");
    checkKemKey(recipientKemPublicKey);
    if (!(encrypted instanceof Uint8Array) || encrypted.length < DHIES_V3_MIN_LENGTH || encrypted[0] !== DHIES_V3_TAG) return null;
    const data = Buffer.from(encrypted);
    let offset = 1;
    const nonce = data.subarray(offset, (offset += NONCE_LENGTH));
    const ePk = data.subarray(offset, (offset += KEY_LENGTH));
    const kemCt = data.subarray(offset, (offset += MLKEM768_CT_LENGTH));
    const ct = data.subarray(offset);

    const es = Buffer.from(await recipientDH(Buffer.from(ePk)));
    const ss = Buffer.from(await recipientDH(Buffer.from(senderPublicKey)));
    const kss = Buffer.from(await recipientDecapsulate(Buffer.from(kemCt)));
    try {
      const k = deriveKeyV3(es, ss, kss, ePk, senderPublicKey, recipientPublicKey, recipientKemPublicKey, kemCt);
      const plaintext = nacl.secretbox.open(ct, nonce, k);
      secureErase(k);
      return plaintext ? Buffer.from(plaintext) : null;
    } finally {
      secureErase(es);
      secureErase(ss);
      secureErase(kss);
    }
  } catch {
    return null;
  }
}
