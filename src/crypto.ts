import { randomBytes } from "crypto";
import nacl from "tweetnacl";
import { Buffer } from "buffer";
import { sha224, sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";

const getAlgorithm = (alg: string) => {
  const cleanAlg = alg.replaceAll("-","").toLowerCase()
  if(cleanAlg === "sha256") return sha256.create();
  if(cleanAlg === "sha512") return sha512.create();
  if(cleanAlg === "sha224") return sha224.create();
  return sha256.create();
} 

const hash = (alg: string, buffer: Buffer) => Buffer.from(getAlgorithm(alg).update(buffer).digest());
const secretbox = nacl.secretbox;
const toBase64 = (bufferLike: Buffer) => Buffer.from(bufferLike).toString("base64");
const toHex = (bufferLike: Buffer) => Buffer.from(bufferLike).toString("hex");
const toUTF8 = (bufferLike: Buffer) => Buffer.from(bufferLike).toString("utf-8");
const fromBase64 = (string: string) => Buffer.from(string, "base64");
const fromHex = (string: string) => Buffer.from(string, "hex");
const fromUTF8 = (string: string) => Buffer.from(string, "utf-8");

export { Buffer, hash, randomBytes, secretbox, toBase64, toHex, toUTF8, fromBase64, fromHex, fromUTF8 };
