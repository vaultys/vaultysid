"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("./crypto");
const KeyManager_1 = require("./KeyManager");
const SoftCredentials_1 = __importDefault(require("./platform/SoftCredentials"));
const webauthn_1 = require("./platform/webauthn");
const buffer_1 = require("buffer/");
const pqCrypto_1 = require("./pqCrypto");
const CypherManager_1 = __importDefault(require("./KeyManager/CypherManager"));
const DeprecatedKeyManager_1 = __importDefault(require("./KeyManager/DeprecatedKeyManager"));
const TYPE_MACHINE = 0;
const TYPE_PERSON = 1;
const TYPE_ORGANIZATION = 2;
const TYPE_FIDO2 = 3;
const TYPE_FIDO2PRF = 4;
const SIGN_INCIPIT = buffer_1.Buffer.from("VAULTYS_SIGN", "utf8");
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
        if (typeof id === "string") {
            cleanId = buffer_1.Buffer.from(id, encoding);
        }
        const type = cleanId[0];
        if (type === TYPE_FIDO2) {
            const f2m = KeyManager_1.Fido2Manager.fromId(cleanId.slice(1));
            return new VaultysId(f2m, certificate, type);
        }
        else if (type === TYPE_FIDO2PRF) {
            const f2m = KeyManager_1.Fido2PRFManager.fromId(cleanId.slice(1));
            return new VaultysId(f2m, certificate, type);
        }
        else {
            // console.log(cleanId.length);
            if (cleanId.length === 1998) {
                const pqm = KeyManager_1.DilithiumManager.fromId(cleanId.slice(1));
                return new VaultysId(pqm, certificate, type);
            }
            else if (cleanId.length === 2030) {
                const pqm = KeyManager_1.HybridManager.fromId(cleanId.slice(1));
                return new VaultysId(pqm, certificate, type);
            }
            else if (cleanId.length === 77) {
                const km = KeyManager_1.Ed25519Manager.fromId(cleanId.slice(1));
                return new VaultysId(km, certificate, type);
            }
            else {
                const km = DeprecatedKeyManager_1.default.fromId(cleanId.slice(1));
                return new VaultysId(km, certificate, type);
            }
        }
    }
    static async fromEntropy(entropy, type, alg = "ed25519") {
        const cleanedEntropy = entropy;
        if (alg === "dilithium") {
            const km = await KeyManager_1.DilithiumManager.createFromEntropy(cleanedEntropy);
            return new VaultysId(km, undefined, type);
        }
        else if (alg === "dilithium_ed25519") {
            const km = await KeyManager_1.HybridManager.createFromEntropy(cleanedEntropy);
            return new VaultysId(km, undefined, type);
        }
        else {
            const km = await KeyManager_1.Ed25519Manager.createFromEntropy(cleanedEntropy);
            return new VaultysId(km, undefined, type);
        }
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
    static async createPQC() {
        const options = VaultysId.createPublicKeyCredentialOptionsPQC();
        const webAuthn = (0, webauthn_1.getWebAuthnProvider)();
        const attestation = await webAuthn.create(options);
        //console.log(attestation);
        if (!attestation)
            return null;
        else
            return VaultysId.fido2FromAttestation(attestation);
    }
    static async fido2FromAttestation(attestation, onPRFEnabled) {
        // should be somehow valid.
        SoftCredentials_1.default.verifyPackedAttestation(attestation.response, true);
        //console.log(SoftCredentials.verifyPackedAttestation(attestation.response as AuthenticatorAttestationResponse, true));
        if (attestation.getClientExtensionResults().prf?.enabled && (!onPRFEnabled || (await onPRFEnabled()))) {
            const f2m = await KeyManager_1.Fido2PRFManager.createFromAttestation(attestation);
            return new VaultysId(f2m, undefined, TYPE_FIDO2PRF);
        }
        else {
            const f2m = await KeyManager_1.Fido2Manager.createFromAttestation(attestation);
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
            const f2m = KeyManager_1.Fido2Manager.fromSecret(secretBuffer.slice(1));
            return new VaultysId(f2m, undefined, type);
        }
        else if (type == TYPE_FIDO2PRF) {
            const f2m = KeyManager_1.Fido2PRFManager.fromSecret(secretBuffer.slice(1));
            return new VaultysId(f2m, undefined, type);
        }
        else {
            // console.log(secretBuffer.length);
            if (secretBuffer.length === 73) {
                const pqm = KeyManager_1.DilithiumManager.fromSecret(secretBuffer.slice(1));
                return new VaultysId(pqm, undefined, type);
            }
            else if (secretBuffer.length === 84) {
                const pqm = KeyManager_1.HybridManager.fromSecret(secretBuffer.slice(1));
                return new VaultysId(pqm, undefined, type);
            }
            else {
                const km = KeyManager_1.Ed25519Manager.fromSecret(secretBuffer.slice(1));
                return new VaultysId(km, undefined, type);
            }
        }
    }
    static async generatePerson(alg = "ed25519") {
        if (alg === "dilithium") {
            const km = await KeyManager_1.DilithiumManager.generate();
            return new VaultysId(km, undefined, TYPE_PERSON);
        }
        else if (alg === "dilithium_ed25519") {
            const km = await KeyManager_1.HybridManager.generate();
            return new VaultysId(km, undefined, TYPE_PERSON);
        }
        else {
            const km = await KeyManager_1.Ed25519Manager.generate();
            return new VaultysId(km, undefined, TYPE_PERSON);
        }
    }
    static async generateOrganization(alg = "ed25519") {
        if (alg === "dilithium") {
            const km = await KeyManager_1.DilithiumManager.generate();
            return new VaultysId(km, undefined, TYPE_ORGANIZATION);
        }
        else if (alg === "dilithium_ed25519") {
            const km = await KeyManager_1.HybridManager.generate();
            return new VaultysId(km, undefined, TYPE_ORGANIZATION);
        }
        else {
            const km = await KeyManager_1.Ed25519Manager.generate();
            return new VaultysId(km, undefined, TYPE_ORGANIZATION);
        }
    }
    static async generateMachine(alg = "ed25519") {
        if (alg === "dilithium") {
            const km = await KeyManager_1.DilithiumManager.generate();
            return new VaultysId(km, undefined, TYPE_MACHINE);
        }
        else if (alg === "dilithium_ed25519") {
            const km = await KeyManager_1.HybridManager.generate();
            return new VaultysId(km, undefined, TYPE_MACHINE);
        }
        else {
            const km = await KeyManager_1.Ed25519Manager.generate();
            return new VaultysId(km, undefined, TYPE_MACHINE);
        }
    }
    get relationshipCertificate() {
        return this.certificate;
    }
    getSecret(encoding = "hex") {
        return buffer_1.Buffer.concat([buffer_1.Buffer.from([this.type]), this.keyManager.getSecret()]).toString(encoding);
    }
    get fingerprint() {
        const fp = buffer_1.Buffer.concat([buffer_1.Buffer.from([this.type]), (0, crypto_1.hash)("SHA224", this.keyManager.id)]).toString("hex");
        return fp
            .slice(0, 40)
            .toUpperCase()
            .match(/.{1,4}/g)
            .join(" ");
    }
    get did() {
        const fp = buffer_1.Buffer.concat([buffer_1.Buffer.from([this.type]), (0, crypto_1.hash)("SHA224", this.keyManager.id)]).toString("hex");
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
    /**
     * Encrypt a message using DHIES for a recipient
     * @param message Message to encrypt
     * @param recipientId Recipient's VaultysId ID
     * @returns Encrypted message or null if encryption fails
     */
    async dhiesEncrypt(message, recipientId) {
        let cleanId;
        if (typeof recipientId === "string") {
            cleanId = buffer_1.Buffer.from(recipientId.slice(2), "hex");
        }
        else {
            cleanId = recipientId.slice(1);
        }
        return this.keyManager.dhiesEncrypt(message, cleanId);
    }
    /**
     * Decrypt a message encrypted with DHIES
     * @param encryptedMessage Encrypted message from dhiesEncrypt
     * @returns Decrypted message as Buffer or null if decryption fails
     */
    async dhiesDecrypt(encryptedMessage, senderId) {
        let cleanId;
        if (typeof senderId === "string") {
            cleanId = buffer_1.Buffer.from(senderId.slice(2), "hex");
        }
        else {
            cleanId = senderId.slice(1);
        }
        return this.keyManager.dhiesDecrypt(encryptedMessage, cleanId);
    }
    async signChallenge_v0(challenge, oldId) {
        if (typeof challenge == "string") {
            challenge = buffer_1.Buffer.from(challenge, "hex");
        }
        const result = (0, crypto_1.hash)("sha256", buffer_1.Buffer.concat([oldId, challenge]));
        const signature = await this.keyManager.sign(result);
        if (!signature)
            throw new Error("Could not sign challenge");
        else
            return signature;
    }
    verifyChallenge_v0(challenge, signature, userVerification, oldId) {
        if (typeof challenge == "string") {
            challenge = buffer_1.Buffer.from(challenge, "hex");
        }
        if (typeof signature == "string") {
            signature = buffer_1.Buffer.from(signature, "hex");
        }
        const result = (0, crypto_1.hash)("sha256", buffer_1.Buffer.concat([oldId, challenge]));
        return this.keyManager.verify(result, signature, userVerification);
    }
    async signChallenge(challenge) {
        if (typeof challenge == "string") {
            challenge = buffer_1.Buffer.from(challenge, "hex");
        }
        const result = (0, crypto_1.hash)("sha256", buffer_1.Buffer.concat([SIGN_INCIPIT, challenge]));
        const signature = await this.keyManager.sign(result);
        if (!signature)
            throw new Error("Could not sign challenge");
        else
            return signature;
    }
    verifyChallenge(challenge, signature, userVerification) {
        if (typeof challenge == "string") {
            challenge = buffer_1.Buffer.from(challenge, "hex");
        }
        if (typeof signature == "string") {
            signature = buffer_1.Buffer.from(signature, "hex");
        }
        const result = (0, crypto_1.hash)("sha256", buffer_1.Buffer.concat([SIGN_INCIPIT, challenge]));
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
        return CypherManager_1.default.encrypt(plaintext, recipientIds.map((id) => {
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
VaultysId.createPublicKeyCredentialOptionsPQC = () => {
    const safari = /^((?!chrome|android).)*applewebkit/i.test(navigator.userAgent);
    const hint = "security-key";
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
            authenticatorAttachment: "cross-platform",
            residentKey: "discouraged",
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
        pubKeyCredParams: [{ type: "public-key", alg: pqCrypto_1.PQ_COSE_ALG.DILITHIUM2 }],
    };
    return options;
};
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
