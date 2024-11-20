"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.secureErase = exports.fromUTF8 = exports.fromHex = exports.fromBase64 = exports.toUTF8 = exports.toHex = exports.toBase64 = exports.secretbox = exports.randomBytes = exports.hash = exports.Buffer = void 0;
const crypto_1 = require("crypto");
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const buffer_1 = require("buffer");
Object.defineProperty(exports, "Buffer", { enumerable: true, get: function () { return buffer_1.Buffer; } });
const sha256_1 = require("@noble/hashes/sha256");
const sha512_1 = require("@noble/hashes/sha512");
const getAlgorithm = (alg) => {
    const cleanAlg = alg.replaceAll("-", "").toLowerCase();
    if (cleanAlg === "sha256")
        return sha256_1.sha256.create();
    if (cleanAlg === "sha512")
        return sha512_1.sha512.create();
    if (cleanAlg === "sha224")
        return sha256_1.sha224.create();
    return sha256_1.sha256.create();
};
const _randomBytes = (size) => buffer_1.Buffer.from(crypto_1.randomBytes ? (0, crypto_1.randomBytes)(size) : crypto.getRandomValues(new Uint8Array(size)));
exports.randomBytes = _randomBytes;
const hash = (alg, buffer) => buffer_1.Buffer.from(getAlgorithm(alg).update(buffer).digest());
exports.hash = hash;
const secretbox = tweetnacl_1.default.secretbox;
exports.secretbox = secretbox;
const toBase64 = (bufferLike) => buffer_1.Buffer.from(bufferLike).toString("base64");
exports.toBase64 = toBase64;
const toHex = (bufferLike) => buffer_1.Buffer.from(bufferLike).toString("hex");
exports.toHex = toHex;
const toUTF8 = (bufferLike) => buffer_1.Buffer.from(bufferLike).toString("utf-8");
exports.toUTF8 = toUTF8;
const fromBase64 = (string) => buffer_1.Buffer.from(string, "base64");
exports.fromBase64 = fromBase64;
const fromHex = (string) => buffer_1.Buffer.from(string, "hex");
exports.fromHex = fromHex;
const fromUTF8 = (string) => buffer_1.Buffer.from(string, "utf-8");
exports.fromUTF8 = fromUTF8;
const secureErase = (buffer) => {
    for (let i = 0; i < buffer.length; i++) {
        buffer[i] = 0;
    }
};
exports.secureErase = secureErase;
