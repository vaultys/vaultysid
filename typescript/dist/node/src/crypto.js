"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.secureErase = exports.fromUTF8 = exports.fromHex = exports.fromBase64 = exports.toUTF8 = exports.toHex = exports.toBase64 = exports.secretbox = exports.randomBytes = exports.hmac = exports.hash = exports.Buffer = void 0;
const tweetnacl_1 = __importStar(require("tweetnacl"));
const buffer_1 = require("buffer/");
Object.defineProperty(exports, "Buffer", { enumerable: true, get: function () { return buffer_1.Buffer; } });
const sha2_js_1 = require("@noble/hashes/sha2.js");
const hmac_js_1 = require("@noble/hashes/hmac.js");
const getAlgorithm = (alg) => {
    const cleanAlg = alg.replaceAll("-", "").toLowerCase();
    if (cleanAlg === "sha256")
        return sha2_js_1.sha256;
    if (cleanAlg === "sha512")
        return sha2_js_1.sha512;
    if (cleanAlg === "sha224")
        return sha2_js_1.sha224;
    return sha2_js_1.sha256;
};
const _randomBytes = (size) => buffer_1.Buffer.from((0, tweetnacl_1.randomBytes)(size));
exports.randomBytes = _randomBytes;
const hash = (alg, buffer) => buffer_1.Buffer.from(getAlgorithm(alg).create().update(buffer).digest());
exports.hash = hash;
const _hmac = (alg, key, data) => buffer_1.Buffer.from((0, hmac_js_1.hmac)(getAlgorithm(alg), key, typeof data === "string" ? buffer_1.Buffer.from(data, "utf8") : data));
exports.hmac = _hmac;
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
