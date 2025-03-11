"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("./crypto");
const Fido2Manager_1 = __importDefault(require("./Fido2Manager"));
const Fido2PRFManager_1 = __importDefault(require("./Fido2PRFManager"));
const KeyManager_1 = __importDefault(require("./KeyManager"));
const SoftCredentials_1 = __importDefault(require("./platform/SoftCredentials"));
const webauthn_1 = require("./platform/webauthn");
const buffer_1 = require("buffer/");
const TYPE_MACHINE = 0;
const TYPE_PERSON = 1;
const TYPE_ORGANIZATION = 2;
const TYPE_FIDO2 = 3;
const TYPE_FIDO2PRF = 4;
class VaultysId {
    constructor(keyManager, certificate, type = TYPE_MACHINE) {
        this.encrypt = VaultysId.encrypt;
        this.type = type;
        this.keyManager = keyManager;
        this.certificate = certificate;
    }
    // // Set the index of the proof in case of previous key for this protocol/service have been compromised
    // setProofIndex(protocol, service, index) {
    //   this.proofIndices[`${protocol}-${service}`] = index;
    // }
    // createSwapingCertificate(protocol, service) {
    //   let proofIndex = this.proofIndices[`${protocol}-${service}`]
    //     ? this.proofIndices[`${protocol}-${service}`]
    //     : 0;
    //   const pk = this.getKey({
    //     protocol,
    //     service,
    //     proofIndex,
    //   });
    //   const newPk = this.getKey({
    //     protocol,
    //     service,
    //     proofIndex: proofIndex + 1,
    //   });
    //   const xPub = this.device.getProofXPub({
    //     protocol,
    //     service,
    //     index,
    //   });
    //   const derivation = PDM.getProofDerivation(protocol, service, index);
    //   const revocationCertificate = `vaultys://p2p/revocation?pk=${pk}&npk=${newPk}&xpub=${xpub}&index=${derivation}`;
    // }
    static fromId(id, certificate, encoding = "hex") {
        let cleanId = id;
        if (id.data) {
            // Buffer thing
            cleanId = buffer_1.Buffer.from(id.data);
        }
        if (id instanceof Uint8Array) {
            // Buffer thing
            cleanId = buffer_1.Buffer.from(id);
        }
        if (typeof id == "string") {
            cleanId = buffer_1.Buffer.from(id, encoding);
        }
        const type = cleanId[0];
        if (type == TYPE_FIDO2) {
            const f2m = Fido2Manager_1.default.fromId(cleanId.slice(1));
            return new VaultysId(f2m, certificate, type);
        }
        else if (type == TYPE_FIDO2PRF) {
            const f2m = Fido2PRFManager_1.default.fromId(cleanId.slice(1));
            return new VaultysId(f2m, certificate, type);
        }
        else {
            const km = KeyManager_1.default.fromId(cleanId.slice(1));
            return new VaultysId(km, certificate, type);
        }
    }
    static async fromEntropy(entropy, type) {
        const cleanedEntropy = entropy;
        const km = await KeyManager_1.default.create_Id25519_fromEntropy(cleanedEntropy);
        return new VaultysId(km, undefined, type);
    }
    static async createWebauthn(passkey = true, onPRFEnabled) {
        const options = VaultysId.createPublicKeyCredentialCreationOptions(passkey);
        const webAuthn = (0, webauthn_1.getWebAuthnProvider)();
        const attestation = await webAuthn.create(options);
        if (!attestation)
            return null;
        else
            return VaultysId.fido2FromAttestation(attestation, onPRFEnabled);
    }
    static async fido2FromAttestation(attestation, onPRFEnabled) {
        // should be somehow valid.
        SoftCredentials_1.default.verifyPackedAttestation(attestation.response, true);
        if (attestation.getClientExtensionResults().prf?.enabled && (!onPRFEnabled || (await onPRFEnabled()))) {
            const f2m = await Fido2PRFManager_1.default.createFromAttestation(attestation);
            return new VaultysId(f2m, undefined, TYPE_FIDO2PRF);
        }
        else {
            const f2m = await Fido2Manager_1.default.createFromAttestation(attestation);
            return new VaultysId(f2m, undefined, TYPE_FIDO2);
        }
    }
    static async machineFromEntropy(entropy) {
        return VaultysId.fromEntropy(entropy, TYPE_MACHINE);
    }
    static async organizationFromEntropy(entropy) {
        return VaultysId.fromEntropy(entropy, TYPE_ORGANIZATION);
    }
    static async personFromEntropy(entropy) {
        return VaultysId.fromEntropy(entropy, TYPE_PERSON);
    }
    static fromSecret(secret, encoding = "hex") {
        const secretBuffer = buffer_1.Buffer.from(secret, encoding);
        const type = secretBuffer[0];
        if (type == TYPE_FIDO2) {
            const f2m = Fido2Manager_1.default.fromSecret(secretBuffer.slice(1));
            return new VaultysId(f2m, undefined, type);
        }
        else if (type == TYPE_FIDO2PRF) {
            const f2m = Fido2PRFManager_1.default.fromSecret(secretBuffer.slice(1));
            return new VaultysId(f2m, undefined, type);
        }
        else {
            const km = KeyManager_1.default.fromSecret(secretBuffer.slice(1));
            return new VaultysId(km, undefined, type);
        }
    }
    static async generatePerson() {
        const km = await KeyManager_1.default.generate_Id25519();
        return new VaultysId(km, undefined, TYPE_PERSON);
    }
    static async generateOrganization() {
        const km = await KeyManager_1.default.generate_Id25519();
        return new VaultysId(km, undefined, TYPE_ORGANIZATION);
    }
    static async generateMachine() {
        const km = await KeyManager_1.default.generate_Id25519();
        return new VaultysId(km, undefined, TYPE_MACHINE);
    }
    get relationshipCertificate() {
        return this.certificate;
    }
    getSecret(encoding = "hex") {
        return buffer_1.Buffer.concat([buffer_1.Buffer.from([this.type]), this.keyManager.getSecret()]).toString(encoding);
    }
    get fingerprint() {
        const t = buffer_1.Buffer.from([this.type]).toString("hex");
        const fp = t + (0, crypto_1.hash)("SHA224", this.keyManager.id).toString("hex");
        return fp
            .slice(0, 40)
            .toUpperCase()
            .match(/.{1,4}/g)
            .join(" ");
    }
    get did() {
        const t = buffer_1.Buffer.from([this.type]).toString("hex");
        const fp = t + (0, crypto_1.hash)("SHA224", this.keyManager.id).toString("hex");
        return `did:vaultys:${fp.slice(0, 40)}`;
    }
    get didDocument() {
        return {
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
            id: this.did,
            authentication: [
                {
                    id: `${this.did}#keys-1`,
                    type: this.keyManager.authType,
                    controller: this.did,
                    publicKeyMultibase: "m" + buffer_1.Buffer.from(this.keyManager.signer.publicKey).toString("base64"),
                },
            ],
            keyAgreement: [
                {
                    id: `${this.did}#keys-2`,
                    type: this.keyManager.encType,
                    controller: this.did,
                    publicKeyMultibase: "m" + buffer_1.Buffer.from(this.keyManager.cypher.publicKey).toString("base64"),
                },
            ],
        };
    }
    get id() {
        return buffer_1.Buffer.concat([buffer_1.Buffer.from([this.type]), this.keyManager.id]);
    }
    toVersion(v) {
        this.keyManager.version = v;
        return this;
    }
    get version() {
        return this.keyManager.version;
    }
    isHardware() {
        return this.type === TYPE_FIDO2 || this.type === TYPE_FIDO2PRF;
    }
    isMachine() {
        return this.type === TYPE_MACHINE;
    }
    isPerson() {
        return this.type === TYPE_PERSON;
    }
    getOTPHmac(timelock = 1 * 3600000) {
        const otp = Math.floor(new Date().getTime() / timelock);
        return this.keyManager.getSecretHash(buffer_1.Buffer.from(`OTP-${otp}`)).toString("hex");
    }
    // Need to think about insecure use of this function
    getOTP(prefix = "password", timelock = 24 * 3600000) {
        if (this.certificate) {
            const otp = Math.floor(new Date().getTime() / timelock);
            const toHash = buffer_1.Buffer.concat([buffer_1.Buffer.from(prefix, "utf-8"), buffer_1.Buffer.from(this.certificate), buffer_1.Buffer.from([otp])]);
            return (0, crypto_1.hash)("SHA256", toHash).toString("hex");
        }
        throw new Error("no certificate, cannot derive OTP");
    }
    async performDiffieHellman(otherVaultysId) {
        return this.keyManager.performDiffieHellman(otherVaultysId.keyManager);
    }
    /**
     * Static method to perform a Diffie-Hellman key exchange between two VaultysId instances
     * @param vaultysId1 First VaultysId instance
     * @param vaultysId2 Second VaultysId instance
     * @returns A shared secret that both parties can derive
     */
    static async diffieHellman(vaultysId1, vaultysId2) {
        return vaultysId1.performDiffieHellman(vaultysId2);
    }
    async signChallenge(challenge) {
        if (typeof challenge == "string") {
            challenge = buffer_1.Buffer.from(challenge, "hex");
        }
        const result = (0, crypto_1.hash)("sha256", buffer_1.Buffer.concat([this.id, challenge]));
        return this.keyManager.sign(result);
    }
    verifyChallenge(challenge, signature, userVerification) {
        if (typeof challenge == "string") {
            challenge = buffer_1.Buffer.from(challenge, "hex");
        }
        if (typeof signature == "string") {
            signature = buffer_1.Buffer.from(signature, "hex");
        }
        const result = (0, crypto_1.hash)("sha256", buffer_1.Buffer.concat([this.id, challenge]));
        return this.keyManager.verify(result, signature, userVerification);
    }
    async signcrypt(plaintext, recipientIds) {
        return this.keyManager.signcrypt(plaintext, recipientIds.map((id) => {
            if (typeof id === "string")
                return buffer_1.Buffer.from(id.slice(2), "hex");
            else
                return id.slice(1);
        }));
    }
    static async encrypt(plaintext, recipientIds) {
        return KeyManager_1.default.encrypt(plaintext, recipientIds.map((id) => {
            if (typeof id === "string")
                return buffer_1.Buffer.from(id.slice(2), "hex");
            else
                return id.slice(1);
        }));
    }
    async decrypt(encryptedMessage, senderId) {
        let cleanId;
        if (senderId) {
            if (typeof senderId === "string")
                cleanId = buffer_1.Buffer.from(senderId.slice(2));
            // @ts-ignore
            else
                cleanId = senderId.subarray(1);
        }
        return this.keyManager.decrypt(encryptedMessage, cleanId);
    }
    async hmac(message) {
        const cypher = await this.keyManager.getCypher();
        return cypher.hmac(message);
    }
}
VaultysId.createPublicKeyCredentialCreationOptions = (passkey) => {
    const safari = /^((?!chrome|android).)*applewebkit/i.test(navigator.userAgent);
    const hint = passkey ? "client-device" : "security-key";
    const options = {
        challenge: (0, crypto_1.randomBytes)(32),
        rp: {
            name: "Vaultys ID",
        },
        user: {
            id: (0, crypto_1.randomBytes)(16),
            name: "Vaultys ID",
            displayName: "Vaultys Wallet ID",
        },
        attestation: safari ? "none" : "direct", // SAFARI Dead, they removed direct attestation
        authenticatorSelection: {
            authenticatorAttachment: passkey ? "platform" : "cross-platform",
            residentKey: passkey ? "required" : "discouraged",
            userVerification: "preferred",
        },
        // @ts-ignore not yet in dom types
        hints: [hint],
        extensions: {
            prf: {
                eval: {
                    first: buffer_1.Buffer.from("VaultysID salt", "utf-8"),
                },
            },
        },
        pubKeyCredParams: [
            {
                type: "public-key",
                alg: -7, // SECP256/ECDSA, Ed25519/EdDSA (-8) not supported natively on mobile or yubikey (crying)
            },
            {
                type: "public-key",
                alg: -8, // Ed25519/EdDSA prefered
            },
            {
                type: "public-key",
                alg: -257, // RS256
            },
            // {
            //   "type": "public-key",
            //   "alg": -36
            // },
            // {
            //   "type": "public-key",
            //   "alg": -37
            // },
            // {
            //   "type": "public-key",
            //   "alg": -38
            // },
            // {
            //   "type": "public-key",
            //   "alg": -39
            // },
            // {
            //   "type": "public-key",
            //   "alg": -258
            // },
            // {
            //   "type": "public-key",
            //   "alg": -259
            // }
        ],
    };
    return options;
};
exports.default = VaultysId;
