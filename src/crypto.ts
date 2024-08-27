import { randomBytes } from "crypto";
import nacl from "tweetnacl";
import { Buffer } from "buffer";
import { sha224, sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";

const getAlgorithm = (alg: string) => {
  const cleanAlg = alg.replaceAll("-", "").toLowerCase();
  if (cleanAlg === "sha256") return sha256.create();
  if (cleanAlg === "sha512") return sha512.create();
  if (cleanAlg === "sha224") return sha224.create();
  return sha256.create();
};

const _randomBytes = (size: number) => Buffer.from(randomBytes ? randomBytes(size) : crypto.getRandomValues(new Uint8Array(size)));

const hash = (alg: string, buffer: Buffer) => Buffer.from(getAlgorithm(alg).update(buffer).digest());
const secretbox = nacl.secretbox;
const toBase64 = (bufferLike: Buffer) => Buffer.from(bufferLike).toString("base64");
const toHex = (bufferLike: Buffer) => Buffer.from(bufferLike).toString("hex");
const toUTF8 = (bufferLike: Buffer) => Buffer.from(bufferLike).toString("utf-8");
const fromBase64 = (string: string) => Buffer.from(string, "base64");
const fromHex = (string: string) => Buffer.from(string, "hex");
const fromUTF8 = (string: string) => Buffer.from(string, "utf-8");
const secureErase = (buffer: Buffer) => {
  for (let i = 0; i < buffer.length; i++) {
    buffer[i] = 0;
  }
};

export { Buffer, hash, _randomBytes as randomBytes, secretbox, toBase64, toHex, toUTF8, fromBase64, fromHex, fromUTF8, secureErase };
