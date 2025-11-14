"use strict";
var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var _NodeWebAuthn_origin;
Object.defineProperty(exports, "__esModule", { value: true });
exports.NodeWebAuthn = exports.BrowserWebAuthn = void 0;
exports.getWebAuthnProvider = getWebAuthnProvider;
exports.createCredentialRequest = createCredentialRequest;
const SoftCredentials_1 = __importDefault(require("./SoftCredentials"));
// Browser implementation
class BrowserWebAuthn {
    constructor(origin = "test") {
        this.origin = origin;
    }
    isAvailable() {
        return typeof window !== "undefined" && typeof window.PublicKeyCredential !== "undefined";
    }
    async create(options) {
        if (!this.isAvailable()) {
            throw new Error("WebAuthn is not available in this environment");
        }
        return (await navigator.credentials.create({ publicKey: options }));
    }
    async get(options) {
        if (!this.isAvailable()) {
            throw new Error("WebAuthn is not available in this environment");
        }
        return (await navigator.credentials.get({ publicKey: options }));
    }
}
exports.BrowserWebAuthn = BrowserWebAuthn;
// Node.js implementation using SoftCredentials
class NodeWebAuthn {
    constructor(origin = "test") {
        _NodeWebAuthn_origin.set(this, void 0);
        __classPrivateFieldSet(this, _NodeWebAuthn_origin, origin, "f");
    }
    isAvailable() {
        return true; // Always available in mock mode
    }
    async create(options) {
        return await SoftCredentials_1.default.create({
            publicKey: options,
        }, __classPrivateFieldGet(this, _NodeWebAuthn_origin, "f"));
    }
    async get(options) {
        return await SoftCredentials_1.default.get({
            publicKey: options,
        }, __classPrivateFieldGet(this, _NodeWebAuthn_origin, "f"));
    }
}
exports.NodeWebAuthn = NodeWebAuthn;
_NodeWebAuthn_origin = new WeakMap();
// Factory function
function getWebAuthnProvider(options) {
    if (typeof window !== "undefined") {
        return new BrowserWebAuthn();
    }
    return new NodeWebAuthn(options?.origin);
}
// Helper to create credential request
function createCredentialRequest(alg, prf = false) {
    return SoftCredentials_1.default.createRequest(alg, prf);
}
