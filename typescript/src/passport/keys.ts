import { Buffer } from "buffer/";
import { pow } from "@noble/curves/abstract/modular.js";
import { brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 } from "@noble/curves/misc.js";
import { p256, p384, p521 } from "@noble/curves/nist.js";
import { sha1 } from "@noble/hashes/legacy.js";
import { sha224, sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { requireBytes } from "../KeyManager/validation";

// OID value octets, without the DER tag and length.
const OID_RSA = "2a864886f70d010101";
const OID_EC = "2a8648ce3d0201";
const OID_AA = "678108010105"; // 2.23.136.1.1.5
const OID_PLAIN_ECDSA = "04007f000701010401";
const curves = new Map([
  ["2a8648ce3d030107", { curve: p256, bits: 256 }],
  ["2b81040022", { curve: p384, bits: 384 }],
  ["2b81040023", { curve: p521, bits: 521 }],
  ["2b2403030208010107", { curve: brainpoolP256r1, bits: 256 }],
  ["2b240303020801010b", { curve: brainpoolP384r1, bits: 384 }],
  ["2b240303020801010d", { curve: brainpoolP512r1, bits: 512 }],
]);

type Digest = { (data: Uint8Array): Uint8Array; outputLen: number };
const ecHashes = new Map<number, Digest>([
  [1, sha224],
  [2, sha256],
  [3, sha384],
  [4, sha512],
]);
const rsaTrailers = new Map<number, Digest>([
  [0x38cc, sha224],
  [0x34cc, sha256],
  [0x36cc, sha384],
  [0x35cc, sha512],
]);

// Only single-byte tags and canonical definite lengths are needed for DG14 and DG15.
class DerReader {
  #offset = 0;
  constructor(private readonly data: Buffer) {}

  get done() {
    return this.#offset === this.data.length;
  }

  read(tag: number) {
    if (this.data[this.#offset++] !== tag || this.#offset >= this.data.length) throw new Error("Invalid passport DER tag");
    let length = this.data[this.#offset++];
    if (length >= 0x80) {
      const count = length & 0x7f;
      if (count < 1 || count > 2 || this.#offset + count > this.data.length || this.data[this.#offset] === 0) throw new Error("Invalid passport DER length");
      length = this.data.readUIntBE(this.#offset, count);
      if (length < 128) throw new Error("Invalid passport DER length");
      this.#offset += count;
    }
    const end = this.#offset + length;
    if (end > this.data.length) throw new Error("Truncated passport DER value");
    const value = this.data.slice(this.#offset, end);
    this.#offset = end;
    return value;
  }

  finish() {
    if (!this.done) throw new Error("Trailing passport DER data");
  }
}

function unwrap(data: Buffer, tag: number) {
  const reader = new DerReader(data);
  const value = reader.read(tag);
  reader.finish();
  return value;
}

export function readDG15(dg15: Uint8Array) {
  const data = requireBytes(dg15, "passport DG15");
  if (data.length > 1024) throw new Error("Passport DG15 is too large");
  return data[0] === 0x6f ? unwrap(data, 0x6f) : data;
}

export function readDG14Hash(dg14: Uint8Array) {
  const data = requireBytes(dg14, "passport DG14");
  const infos = new DerReader(unwrap(data[0] === 0x6e ? unwrap(data, 0x6e) : data, 0x31));
  let hashId = 0;
  while (!infos.done) {
    const entry = new DerReader(infos.read(0x30));
    if (entry.read(0x06).toString("hex") !== OID_AA) continue;
    if (hashId !== 0 || entry.read(0x02).toString("hex") !== "01") throw new Error("Invalid passport ActiveAuthenticationInfo");
    const oid = entry.read(0x06);
    entry.finish();
    hashId = oid[oid.length - 1] - 1;
    if (oid.slice(0, -1).toString("hex") !== OID_PLAIN_ECDSA || !ecHashes.has(hashId)) throw new Error("Unsupported passport AA hash");
  }
  return hashId;
}

const asInteger = (bytes: Buffer) => BigInt("0x" + bytes.toString("hex"));

function positiveInteger(bytes: Buffer) {
  if (!bytes.length || bytes[0] >= 0x80 || (bytes[0] === 0 && (bytes.length === 1 || bytes[1] < 0x80))) {
    throw new Error("Invalid passport RSA integer");
  }
  return bytes[0] === 0 ? bytes.slice(1) : bytes;
}

function rsaMatches(value: bigint, length: number, challenge: Buffer) {
  const block = Buffer.from(value.toString(16).padStart(length * 2, "0"), "hex");
  if (block[0] !== 0x6a) return false;
  const implicit = block[block.length - 1] === 0xbc;
  const digest = implicit ? sha1 : rsaTrailers.get(block.readUInt16BE(block.length - 2));
  if (!digest) return false;
  const digestEnd = block.length - (implicit ? 1 : 2);
  const digestStart = digestEnd - digest.outputLen;
  const actual = Buffer.from(digest(Buffer.concat([block.slice(1, digestStart), challenge])));
  return actual.equals(block.slice(digestStart, digestEnd));
}

export function parsePassportKey(spki: Buffer, hashId: number) {
  if (spki.length > 1024) throw new Error("Passport AA public key is too large");
  const key = new DerReader(unwrap(spki, 0x30));
  const algorithm = new DerReader(key.read(0x30));
  const oid = algorithm.read(0x06).toString("hex");
  const bits = key.read(0x03);
  key.finish();
  if (bits[0] !== 0) throw new Error("Invalid passport public key bit string");
  const publicKey = bits.slice(1);

  if (oid === OID_RSA) {
    if (hashId !== 0 || algorithm.read(0x05).length !== 0) throw new Error("Invalid passport RSA parameters");
    algorithm.finish();
    const rsa = new DerReader(unwrap(publicKey, 0x30));
    const modulus = positiveInteger(rsa.read(0x02));
    const exponent = positiveInteger(rsa.read(0x02));
    rsa.finish();
    if (modulus.length < 128 || modulus.length > 512 || modulus[0] < 0x80 || exponent.length > 4) throw new Error("Unsupported passport RSA key size");
    const n = asInteger(modulus);
    const e = asInteger(exponent);
    if (!(n & 1n) || !(e & 1n) || e < 3n) throw new Error("Invalid passport RSA public key");
    return {
      size: modulus.length,
      verify: (challenge: Buffer, signature: Buffer) => {
        if (signature.length !== modulus.length) return false;
        const s = asInteger(signature);
        if (s === 0n || s >= n) return false;
        const representative = pow(s, e, n);
        return rsaMatches(representative, modulus.length, challenge) || rsaMatches(n - representative, modulus.length, challenge);
      },
    };
  }

  if (oid !== OID_EC) throw new Error("Unsupported passport AA public key algorithm");
  if (!hashId) throw new Error("Passport ECDSA requires DG14 ActiveAuthenticationInfo");
  const params = curves.get(algorithm.read(0x06).toString("hex"));
  algorithm.finish();
  const digest = ecHashes.get(hashId);
  if (!params || !digest || digest.outputLen * 8 > params.bits) throw new Error("Unsupported passport ECDSA curve or hash");
  const size = 2 * Math.ceil(params.bits / 8);
  if (publicKey.length !== 1 + size || publicKey[0] !== 0x04) throw new Error("Passport ECDSA requires an uncompressed public key");
  params.curve.Point.fromBytes(publicKey).assertValidity();
  return {
    size,
    verify: (challenge: Buffer, signature: Buffer) => signature.length === size && params.curve.verify(signature, digest(challenge), publicKey, { prehash: false, lowS: false, format: "compact" }),
  };
}
