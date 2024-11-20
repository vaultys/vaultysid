/// <reference types="node" />
import nacl from "tweetnacl";
import { Buffer } from "buffer";
declare const _randomBytes: (size: number) => Buffer;
declare const hash: (alg: string, buffer: Buffer) => Buffer;
declare const secretbox: nacl.secretbox;
declare const toBase64: (bufferLike: Buffer) => string;
declare const toHex: (bufferLike: Buffer) => string;
declare const toUTF8: (bufferLike: Buffer) => string;
declare const fromBase64: (string: string) => Buffer;
declare const fromHex: (string: string) => Buffer;
declare const fromUTF8: (string: string) => Buffer;
declare const secureErase: (buffer: Buffer) => void;
export { Buffer, hash, _randomBytes as randomBytes, secretbox, toBase64, toHex, toUTF8, fromBase64, fromHex, fromUTF8, secureErase };
