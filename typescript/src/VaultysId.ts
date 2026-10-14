import { hash, hmac, randomBytes, secureErase } from "./crypto";
import KeyManager, { Ed25519Manager, Fido2Manager, Fido2PRFManager, DilithiumManager, HybridManager } from "./KeyManager";
import SoftCredentials from "./platform/SoftCredentials";
import { getWebAuthnProvider } from "./platform/webauthn";
import { Buffer } from "buffer/";
import { PQ_COSE_ALG } from "./pqCrypto";
import CypherManager from "./KeyManager/CypherManager";
import DeprecatedKeyManager from "./KeyManager/DeprecatedKeyManager";

const TYPE_MACHINE = 0;
const TYPE_PERSON = 1;
const TYPE_ORGANIZATION = 2;
const TYPE_FIDO2 = 3;
const TYPE_FIDO2PRF = 4;

const KNOWN_TYPES = [TYPE_MACHINE, TYPE_PERSON, TYPE_ORGANIZATION, TYPE_FIDO2, TYPE_FIDO2PRF];

// Signature domains. Every signature produced through VaultysId is computed over
// SHA-256(domain || data) so that a signature obtained in one context can never
// be replayed in another one.
// - VAULTYS_SIGN: public signChallenge / verifyChallenge (files, app challenges)
// - VAULTYS_HANDSHAKE_V1: the Challenger handshake only (signHandshake / verifyHandshake)
// - VAULTYS_RAW: the public raw sign / verify
const SIGN_INCIPIT = Buffer.from("VAULTYS_SIGN", "utf8");
export const HANDSHAKE_INCIPIT = Buffer.from("VAULTYS_HANDSHAKE_V1", "utf8");
export const RAW_INCIPIT = Buffer.from("VAULTYS_RAW", "utf8");

const toBuffer = (data: Buffer | Uint8Array | string, encoding: BufferEncoding = "hex") => (typeof data === "string" ? Buffer.from(data, encoding) : Buffer.from(data));

const isAllZero = (data: Uint8Array) => {
  let acc = 0;
  for (let i = 0; i < data.length; i++) acc |= data[i];
  return acc === 0;
};

type StringifiedBuffer = {
  data: number[];
  type: "Buffer";
};

export default class VaultysId {
  type: number;
  keyManager: KeyManager;
  certificate?: Buffer;

  constructor(keyManager: KeyManager, certificate?: Buffer, type: number = TYPE_MACHINE) {
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

  /**
   * Parse a serialized (public) VaultysId. Untrusted input never triggers an
   * uncaught TypeError: any malformed id throws `Error("Invalid VaultysId id: ...")`.
   */
  static fromId(id: StringifiedBuffer | Buffer | Uint8Array | string, certificate?: Buffer, encoding: BufferEncoding = "hex") {
    try {
      return VaultysId._fromId(id, certificate, encoding);
    } catch (error) {
      throw new Error("Invalid VaultysId id: " + ((error as Error)?.message ?? error));
    }
  }

  private static _fromId(id: StringifiedBuffer | Buffer | Uint8Array | string, certificate?: Buffer, encoding: BufferEncoding = "hex") {
    let cleanId: Buffer | undefined;
    if (typeof id === "string") {
      cleanId = Buffer.from(id, encoding);
    } else if (id instanceof Uint8Array) {
      // Buffer thing
      cleanId = Buffer.from(id);
    } else if (id && Array.isArray((id as StringifiedBuffer).data)) {
      // Buffer thing
      cleanId = Buffer.from((id as StringifiedBuffer).data);
    }
    if (!cleanId || cleanId.length < 2) throw new Error("empty or unsupported id");
    const type = cleanId[0];
    if (!KNOWN_TYPES.includes(type)) throw new Error("unknown identity type " + type);
    if (type === TYPE_FIDO2) {
      const f2m = Fido2Manager.fromId(cleanId.slice(1));
      return new VaultysId(f2m, certificate, type);
    } else if (type === TYPE_FIDO2PRF) {
      // console.log("TYPE_FIDO2PRF");
      const f2m = Fido2PRFManager.fromId(cleanId.slice(1));
      return new VaultysId(f2m, certificate, type);
    } else {
      //console.log(cleanId.length);
      if (cleanId.length === 2638) {
        const pqm = DilithiumManager.fromId(cleanId.slice(1));
        return new VaultysId(pqm, certificate, type);
      } else if (cleanId.length === 2638 + 32) {
        const pqm = HybridManager.fromId(cleanId.slice(1));
        return new VaultysId(pqm, certificate, type);
      } else if (cleanId.length === 77) {
        const km = Ed25519Manager.fromId(cleanId.slice(1));
        return new VaultysId(km, certificate, type);
      } else {
        // Legacy (bip32-ed25519) ids carry an extra `p` proof field and do not
        // match any of the lengths above (a v1 person id is 113 bytes, v0 116).
        // Keep reading them so identities created before the @stricahq/bip32ed25519
        // removal stay resolvable, with a byte-identical DID.
        const km = DeprecatedKeyManager.fromId(cleanId.slice(1));
        return new VaultysId(km, certificate, type);
      }
    }
  }

  // non standard, waiting for webauthn to support custom attestation for PQC credentials
  static createPublicKeyCredentialOptionsPQC = (): PublicKeyCredentialCreationOptions => {
    const safari = /^((?!chrome|android).)*applewebkit/i.test(navigator.userAgent);
    const hint = "security-key";

    const options: PublicKeyCredentialCreationOptions = {
      challenge: randomBytes(32),
      rp: {
        name: "Vaultys ID",
      },
      user: {
        id: randomBytes(16),
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
            first: Buffer.from("VaultysID salt", "utf-8"),
          },
        },
      },
      pubKeyCredParams: [{ type: "public-key", alg: PQ_COSE_ALG.DILITHIUM5 }],
    };

    return options;
  };

  static createPublicKeyCredentialCreationOptions = (passkey: boolean): PublicKeyCredentialCreationOptions => {
    const safari = /^((?!chrome|android).)*applewebkit/i.test(navigator.userAgent);
    const hint = passkey ? "client-device" : "security-key";

    const options: PublicKeyCredentialCreationOptions = {
      challenge: randomBytes(32),
      rp: {
        name: "Vaultys ID",
      },
      user: {
        id: randomBytes(16),
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
            first: Buffer.from("VaultysID salt", "utf-8"),
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

  static async fromEntropy(entropy: Buffer, type: number, alg: "dilithium_ed25519" | "dilithium" | "ed25519" = "ed25519") {
    const cleanedEntropy = entropy as Buffer;
    if (alg === "dilithium") {
      const km = await DilithiumManager.createFromEntropy(cleanedEntropy);
      return new VaultysId(km, undefined, type);
    } else if (alg === "dilithium_ed25519") {
      const km = await HybridManager.createFromEntropy(cleanedEntropy);
      return new VaultysId(km, undefined, type);
    } else {
      const km = await Ed25519Manager.createFromEntropy(cleanedEntropy);
      return new VaultysId(km, undefined, type);
    }
  }

  static async createWebauthn(passkey = true, onPRFEnabled?: () => Promise<boolean>) {
    const options = VaultysId.createPublicKeyCredentialCreationOptions(passkey);
    const webAuthn = getWebAuthnProvider();
    const attestation = await webAuthn.create(options);
    if (!attestation) return null;
    else return VaultysId.fido2FromAttestation(attestation as PublicKeyCredential, onPRFEnabled);
  }

  static async createPQC() {
    const options = VaultysId.createPublicKeyCredentialOptionsPQC();
    const webAuthn = getWebAuthnProvider();
    const attestation = await webAuthn.create(options);
    //console.log(attestation);
    if (!attestation) return null;
    else return VaultysId.fido2FromAttestation(attestation as PublicKeyCredential);
  }

  static async fido2FromAttestation(attestation: PublicKeyCredential, onPRFEnabled?: () => Promise<boolean>) {
    // should be somehow valid.
    SoftCredentials.verifyPackedAttestation(attestation.response as AuthenticatorAttestationResponse, true);
    //console.log(SoftCredentials.verifyPackedAttestation(attestation.response as AuthenticatorAttestationResponse, true));
    if (attestation.getClientExtensionResults().prf?.enabled && (!onPRFEnabled || (await onPRFEnabled()))) {
      const f2m = await Fido2PRFManager.createFromAttestation(attestation);
      return new VaultysId(f2m, undefined, TYPE_FIDO2PRF);
    } else {
      const f2m = await Fido2Manager.createFromAttestation(attestation);
      return new VaultysId(f2m, undefined, TYPE_FIDO2);
    }
  }

  static async machineFromEntropy(entropy: Buffer) {
    return VaultysId.fromEntropy(entropy, TYPE_MACHINE);
  }

  static async organizationFromEntropy(entropy: Buffer) {
    return VaultysId.fromEntropy(entropy, TYPE_ORGANIZATION);
  }

  static async personFromEntropy(entropy: Buffer) {
    return VaultysId.fromEntropy(entropy, TYPE_PERSON);
  }

  /**
   * Restore a VaultysId from its secret. Malformed input throws
   * `Error("Invalid VaultysId secret: ...")`, never an uncaught TypeError.
   */
  static fromSecret(secret: string, encoding: BufferEncoding = "hex") {
    try {
      return VaultysId._fromSecret(secret, encoding);
    } catch (error) {
      throw new Error("Invalid VaultysId secret: " + ((error as Error)?.message ?? error));
    }
  }

  private static _fromSecret(secret: string, encoding: BufferEncoding = "hex") {
    if (typeof secret !== "string") throw new Error("secret must be a string");
    const secretBuffer = Buffer.from(secret, encoding);
    if (secretBuffer.length < 2) throw new Error("empty secret");
    const type = secretBuffer[0];
    if (!KNOWN_TYPES.includes(type)) throw new Error("unknown identity type " + type);
    if (type == TYPE_FIDO2) {
      const f2m = Fido2Manager.fromSecret(secretBuffer.slice(1));
      return new VaultysId(f2m, undefined, type);
    } else if (type == TYPE_FIDO2PRF) {
      const f2m = Fido2PRFManager.fromSecret(secretBuffer.slice(1));
      return new VaultysId(f2m, undefined, type);
    } else {
      // console.log(secretBuffer.length);
      if (secretBuffer.length === 73) {
        const pqm = DilithiumManager.fromSecret(secretBuffer.slice(1));
        return new VaultysId(pqm, undefined, type);
      } else if (secretBuffer.length === 84) {
        const pqm = HybridManager.fromSecret(secretBuffer.slice(1));
        return new VaultysId(pqm, undefined, type);
      } else if (secretBuffer.length === 77) {
        const km = Ed25519Manager.fromSecret(secretBuffer.slice(1));
        return new VaultysId(km, undefined, type);
      } else {
        // Legacy secrets are 177 bytes (96-byte extended bip32 signing key + 32-byte
        // proof + 32-byte cypher key). They cannot be re-derived by Ed25519Manager,
        // so this fallback is the only way an existing wallet keeps its identity.
        const km = DeprecatedKeyManager.fromSecret(secretBuffer.slice(1));
        return new VaultysId(km, undefined, type);
      }
    }
  }

  static async generatePerson(alg: "dilithium_ed25519" | "dilithium" | "ed25519" = "ed25519") {
    if (alg === "dilithium") {
      const km = await DilithiumManager.generate();
      return new VaultysId(km, undefined, TYPE_PERSON);
    } else if (alg === "dilithium_ed25519") {
      const km = await HybridManager.generate();
      return new VaultysId(km, undefined, TYPE_PERSON);
    } else {
      const km = await Ed25519Manager.generate();
      return new VaultysId(km, undefined, TYPE_PERSON);
    }
  }

  static async generateOrganization(alg: "dilithium_ed25519" | "dilithium" | "ed25519" = "ed25519") {
    if (alg === "dilithium") {
      const km = await DilithiumManager.generate();
      return new VaultysId(km, undefined, TYPE_ORGANIZATION);
    } else if (alg === "dilithium_ed25519") {
      const km = await HybridManager.generate();
      return new VaultysId(km, undefined, TYPE_ORGANIZATION);
    } else {
      const km = await Ed25519Manager.generate();
      return new VaultysId(km, undefined, TYPE_ORGANIZATION);
    }
  }

  static async generateMachine(alg: "dilithium_ed25519" | "dilithium" | "ed25519" = "ed25519") {
    if (alg === "dilithium") {
      const km = await DilithiumManager.generate();
      return new VaultysId(km, undefined, TYPE_MACHINE);
    } else if (alg === "dilithium_ed25519") {
      const km = await HybridManager.generate();
      return new VaultysId(km, undefined, TYPE_MACHINE);
    } else {
      const km = await Ed25519Manager.generate();
      return new VaultysId(km, undefined, TYPE_MACHINE);
    }
  }

  get relationshipCertificate() {
    return this.certificate;
  }

  getSecret(encoding: BufferEncoding = "hex") {
    return Buffer.concat([Buffer.from([this.type]), this.keyManager.getSecret()]).toString(encoding);
  }

  get fingerprint() {
    const fp = Buffer.concat([Buffer.from([this.type]), hash("SHA224", this.keyManager.id)]).toString("hex");
    return fp
      .slice(0, 40)
      .toUpperCase()
      .match(/.{1,4}/g)!
      .join(" ");
  }

  get did() {
    const fp = Buffer.concat([Buffer.from([this.type]), hash("SHA224", this.keyManager.id)]).toString("hex");
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
          publicKeyMultibase: "m" + Buffer.from(this.keyManager.signer.publicKey).toString("base64"),
        },
      ],
      keyAgreement: [
        {
          id: `${this.did}#keys-2`,
          type: this.keyManager.encType,
          controller: this.did,
          publicKeyMultibase: "m" + Buffer.from(this.keyManager.cypher.publicKey).toString("base64"),
        },
      ],
    };
  }

  get id() {
    return Buffer.concat([Buffer.from([this.type]), this.keyManager.id]);
  }

  toVersion(v: 0 | 1) {
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
    return this.keyManager.getSecretHash(Buffer.from(`OTP-${otp}`)).toString("hex");
  }

  /**
   * One-time password shared between this identity and `remote` (a contact).
   *   key = SHA-256(X25519(own cypher secret key, remote cypher public key))
   *   otp = HMAC-SHA256(key, prefix || certificate || uint64be(floor(time / timelock)))
   * The certificate is the relationship certificate (remote.certificate, or ours).
   * Only the two parties of the relationship can compute it.
   */
  async getOTP(remote: VaultysId, prefix = "password", timelock = 24 * 3600000, time = Date.now()) {
    if (!remote || !remote.keyManager?.cypher?.publicKey) throw new Error("a remote VaultysId is required to derive an OTP");
    const certificate = remote.certificate ?? this.certificate;
    if (!certificate) throw new Error("no certificate, cannot derive OTP");
    if (!(timelock > 0)) throw new Error("invalid timelock");
    const remotePublicKey = Buffer.from(remote.keyManager.cypher.publicKey);
    if (remotePublicKey.length !== 32) throw new Error("invalid remote cypher public key");
    const cypher = await this.keyManager.getCypher();
    const shared = Buffer.from(await cypher.diffieHellman(remotePublicKey));
    if (isAllZero(shared)) throw new Error("degenerate Diffie-Hellman shared secret");
    const key = hash("sha256", shared);
    secureErase(shared);
    const counter = Math.floor(time / timelock);
    const counterBuffer = Buffer.alloc(8);
    counterBuffer.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
    counterBuffer.writeUInt32BE(counter >>> 0, 4);
    const otp = hmac("sha256", key, Buffer.concat([Buffer.from(prefix, "utf-8"), Buffer.from(certificate), counterBuffer]));
    secureErase(key);
    return otp.toString("hex");
  }

  async performDiffieHellman(otherVaultysId: VaultysId): Promise<Buffer | null> {
    return this.keyManager.performDiffieHellman(otherVaultysId.keyManager);
  }

  /**
   * Static method to perform a Diffie-Hellman key exchange between two VaultysId instances
   * @param vaultysId1 First VaultysId instance
   * @param vaultysId2 Second VaultysId instance
   * @returns A shared secret that both parties can derive
   */
  static async diffieHellman(vaultysId1: VaultysId, vaultysId2: VaultysId): Promise<Buffer | null> {
    return vaultysId1.performDiffieHellman(vaultysId2);
  }

  /**
   * Encrypt a message using DHIES for a recipient
   * @param message Message to encrypt
   * @param recipientId Recipient's VaultysId ID
   * @returns Encrypted message or null if encryption fails
   */
  async dhiesEncrypt(message: string | Buffer, recipientId: Buffer | string): Promise<Buffer | null> {
    let cleanId: Buffer;
    if (typeof recipientId === "string") {
      cleanId = Buffer.from(recipientId.slice(2), "hex");
    } else {
      cleanId = recipientId.slice(1);
    }
    return this.keyManager.dhiesEncrypt(message, cleanId);
  }

  /**
   * Decrypt a message encrypted with DHIES
   * @param encryptedMessage Encrypted message from dhiesEncrypt
   * @returns Decrypted message as Buffer or null if decryption fails
   */
  async dhiesDecrypt(encryptedMessage: Buffer, senderId: Buffer | string): Promise<Buffer | null> {
    let cleanId: Buffer;
    if (typeof senderId === "string") {
      cleanId = Buffer.from(senderId.slice(2), "hex");
    } else {
      cleanId = senderId.slice(1);
    }
    return this.keyManager.dhiesDecrypt(encryptedMessage, cleanId);
  }

  private async signInDomain(domain: Buffer, data: Buffer | Uint8Array | string): Promise<Buffer> {
    const result = hash("sha256", Buffer.concat([domain, toBuffer(data)]));
    const signature = await this.keyManager.sign(result);
    if (!signature) throw new Error("Could not sign challenge");
    else return Buffer.from(signature);
  }

  private verifyInDomain(domain: Buffer, data: Buffer | Uint8Array | string, signature: Buffer | Uint8Array | string, userVerification: boolean) {
    try {
      const result = hash("sha256", Buffer.concat([domain, toBuffer(data)]));
      return this.keyManager.verify(result, toBuffer(signature), userVerification);
    } catch {
      return false;
    }
  }

  /** Sign an application challenge: signature over SHA-256("VAULTYS_SIGN" || challenge). */
  async signChallenge(challenge: Buffer | string): Promise<Buffer> {
    return this.signInDomain(SIGN_INCIPIT, challenge);
  }

  verifyChallenge(challenge: Buffer | string, signature: Buffer | string, userVerification: boolean) {
    return this.verifyInDomain(SIGN_INCIPIT, challenge, signature, userVerification);
  }

  /** Raw signature API: signature over SHA-256("VAULTYS_RAW" || data). */
  async sign(data: Buffer | Uint8Array | string): Promise<Buffer> {
    return this.signInDomain(RAW_INCIPIT, data);
  }

  verify(data: Buffer | Uint8Array | string, signature: Buffer | Uint8Array | string, userVerification = false) {
    return this.verifyInDomain(RAW_INCIPIT, data, signature, userVerification);
  }

  /**
   * @internal Handshake-only signature, over SHA-256("VAULTYS_HANDSHAKE_V1" || unsignedChallenge).
   * Must ONLY be called by the Challenger state machine.
   */
  async signHandshake(unsignedChallenge: Buffer | Uint8Array): Promise<Buffer> {
    return this.signInDomain(HANDSHAKE_INCIPIT, Buffer.from(unsignedChallenge));
  }

  /** @internal Handshake-only verification (always requires user verification for FIDO2). */
  verifyHandshake(unsignedChallenge: Buffer | Uint8Array, signature: Buffer | Uint8Array) {
    return this.verifyInDomain(HANDSHAKE_INCIPIT, Buffer.from(unsignedChallenge), Buffer.from(signature), true);
  }

  async signcrypt(plaintext: string, recipientIds: (Buffer | string)[]) {
    return this.keyManager.signcrypt(
      plaintext,
      recipientIds.map((id) => {
        if (typeof id === "string") return Buffer.from(id.slice(2), "hex");
        else return (id as Buffer).slice(1);
      }),
    );
  }

  static async encrypt(plaintext: string, recipientIds: (Buffer | string)[]) {
    return CypherManager.encrypt(
      plaintext,
      recipientIds.map((id) => {
        if (typeof id === "string") return Buffer.from(id.slice(2), "hex");
        else return (id as Buffer).slice(1);
      }),
    );
  }

  encrypt = VaultysId.encrypt;

  async decrypt(encryptedMessage: string, senderId?: Buffer | string) {
    let cleanId: Buffer | undefined;
    if (senderId) {
      if (typeof senderId === "string") cleanId = Buffer.from(senderId.slice(2), "hex");
      // @ts-ignore
      else cleanId = (senderId as Buffer).subarray(1);
    }
    return this.keyManager.decrypt(encryptedMessage, cleanId);
  }

  async hmac(message: string) {
    const cypher = await this.keyManager.getCypher();
    return cypher.hmac(message);
  }
}
