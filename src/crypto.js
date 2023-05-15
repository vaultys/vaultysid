import { createHash, randomBytes } from "crypto";
import nacl from "tweetnacl";
import { Buffer } from "buffer";

const hash = (alg, buffer) => createHash(alg).update(buffer).digest();
const secretbox = nacl.secretbox;
const toBase64 = (bufferLike) => Buffer.from(bufferLike).toString("base64");
const toHex = (bufferLike) => Buffer.from(bufferLike).toString("hex");
const toUTF8 = (bufferLike) => Buffer.from(bufferLike).toString("utf-8");
const fromBase64 = (string) => Buffer.from(string, "base64");
const fromHex = (string) => Buffer.from(string, "hex");
const fromUTF8 = (string) => Buffer.from(string, "utf-8");

export {
  Buffer,
  hash,
  randomBytes,
  secretbox,
  toBase64,
  toHex,
  toUTF8,
  fromBase64,
  fromHex,
  fromUTF8,
};
