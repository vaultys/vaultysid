"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("./crypto");
const cbor_1 = __importDefault(require("cbor"));
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const SoftCredentials_1 = __importDefault(require("./platform/SoftCredentials"));
const msgpack_1 = require("@msgpack/msgpack");
const Fido2Manager_1 = __importDefault(require("./Fido2Manager"));
const buffer_1 = require("buffer/");
const lookup = {
    usb: 1,
    nfc: 2,
    ble: 4,
    internal: 8,
    hybrid: 16,
    "smart-card": 32,
};
const getTransports = (num) => Object.keys(lookup).filter((i) => num && lookup[i]);
const fromTransports = (transports) => transports.reduceRight((memo, i) => memo + (lookup[i] ? lookup[i] : 0), 0);
const getAuthTypeFromCkey = (ckey) => {
    const decoded = cbor_1.default.decode(ckey, { extendedResults: true });
    const type = decoded.value.get(1);
    if (type === 1) {
        return "Ed25519VerificationKey2020";
    }
    else if (type === 2) {
        return "P256VerificationKey2020";
    }
    else
        return "Unknown";
};
const getSignerFromCkey = (ckey) => {
    const k = cbor_1.default.decode(ckey, { extendedResults: true }).value;
    let publicKey = buffer_1.Buffer.from([]);
    if (k.get(3) == -7)
        publicKey = buffer_1.Buffer.concat([buffer_1.Buffer.from("04", "hex"), k.get(-2), k.get(-3)]);
    else if (k.get(3) == -8)
        publicKey = k.get(-2);
    return { publicKey };
};
class Fido2PRFManager extends Fido2Manager_1.default {
    constructor() {
        super();
        this.prfsalt = buffer_1.Buffer.from("VaultysID salt");
    }
    static async createFromAttestation(attestation) {
        const f2m = new Fido2PRFManager();
        f2m.ckey = SoftCredentials_1.default.getCOSEPublicKey(attestation);
        //console.log(attestation, f2m.ckey);
        f2m.authType = getAuthTypeFromCkey(f2m.ckey);
        f2m.fid = buffer_1.Buffer.from(attestation.id, "base64");
        // fix for firefox, getTransports not available ! https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse/getTransports
        const response = attestation.response;
        const transports = response.getTransports ? response.getTransports() : ["usb"];
        f2m._transports = fromTransports(transports);
        // signing
        f2m.signer = getSignerFromCkey(f2m.ckey);
        await f2m.getCypher();
        delete f2m.cypher.secretKey;
        return f2m;
    }
    getSecret() {
        return buffer_1.Buffer.from((0, msgpack_1.encode)({
            v: this.version,
            f: this.fid,
            t: this._transports,
            c: this.ckey,
            e: this.cypher.publicKey,
        }));
    }
    static fromSecret(secret) {
        const data = (0, msgpack_1.decode)(secret);
        const f2m = new Fido2PRFManager();
        f2m.version = data.v ?? 0;
        f2m.capability = "private";
        f2m.fid = typeof data.f === "string" ? buffer_1.Buffer.from(data.f, "base64") : data.f;
        f2m._transports = data.t ? data.t : 15;
        f2m.ckey = data.c;
        f2m.authType = getAuthTypeFromCkey(f2m.ckey);
        f2m.signer = getSignerFromCkey(data.c);
        f2m.cypher = { publicKey: data.e };
        return f2m;
    }
    cleanSecureData() {
        if (this.cypher?.secretKey) {
            (0, crypto_1.secureErase)(this.cypher.secretKey);
            delete this.cypher.secretKey;
        }
    }
    async getCypher() {
        if (!this.cypher?.secretKey) {
            const publicKey = {
                challenge: buffer_1.Buffer.from([]),
                userVerification: "preferred",
                allowCredentials: [
                    {
                        type: "public-key",
                        id: this.fid,
                        transports: getTransports(this._transports),
                    },
                ],
                extensions: {
                    prf: {
                        eval: {
                            // Input the contextual information
                            first: this.prfsalt,
                            // There is a "second" optional field too
                            // Though it is intended for key rotation.
                        },
                    },
                },
            };
            const result = await this.webAuthn.get(publicKey);
            const { prf } = result.getClientExtensionResults();
            const first = prf?.results?.first;
            if (!first)
                throw new Error("PRF failed");
            const cypher = tweetnacl_1.default.box.keyPair.fromSecretKey(new Uint8Array(first));
            this.cypher = {
                publicKey: buffer_1.Buffer.from(cypher.publicKey),
                secretKey: buffer_1.Buffer.from(cypher.secretKey),
            };
        }
        return super.getCypher();
    }
    async createRevocationCertificate() {
        // impossible
        return null;
    }
}
exports.default = Fido2PRFManager;
