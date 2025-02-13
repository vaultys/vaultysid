"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NodeWebAuthn = exports.BrowserWebAuthn = void 0;
exports.getWebAuthnProvider = getWebAuthnProvider;
exports.createCredentialRequest = createCredentialRequest;
const SoftCredentials_1 = __importDefault(require("./SoftCredentials"));
// Browser implementation
class BrowserWebAuthn {
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
        this.origin = origin;
    }
    isAvailable() {
        return true; // Always available in mock mode
    }
    async create(options) {
        return await SoftCredentials_1.default.create({
            publicKey: options,
        }, this.origin);
    }
    async get(options) {
        return await SoftCredentials_1.default.get({
            publicKey: options,
        }, this.origin);
    }
}
exports.NodeWebAuthn = NodeWebAuthn;
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
