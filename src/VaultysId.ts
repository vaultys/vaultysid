import { createHmac, Hmac } from "crypto";
import { hash, randomBytes } from "./crypto";
import Fido2Manager from "./Fido2Manager";
import Fido2PRFManager from "./Fido2PRFManager";
import KeyManager from "./KeyManager";
import SoftCredentials from "./SoftCredentials";

const TYPE_MACHINE = 0;
const TYPE_PERSON = 1;
const TYPE_ORGANIZATION = 2;
const TYPE_FIDO2 = 3;
const TYPE_FIDO2PRF = 4;

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

  static fromId(id: StringifiedBuffer | Buffer | Uint8Array | string, certificate?: Buffer, encoding: BufferEncoding = "hex") {
    let cleanId: Buffer = id as Buffer;
    if ((id as StringifiedBuffer).data) {
      // Buffer thing
      cleanId = Buffer.from((id as StringifiedBuffer).data);
    }
    if (id instanceof Uint8Array) {
      // Buffer thing
      cleanId = Buffer.from(id);
    }
    if (typeof id == "string") {
      cleanId = Buffer.from(id, encoding);
    }
    const type = cleanId[0];
    if (type == TYPE_FIDO2) {
      const f2m = Fido2Manager.fromId(cleanId.slice(1));
      return new VaultysId(f2m, certificate, type);
    } else if (type == TYPE_FIDO2PRF) {
      const f2m = Fido2PRFManager.fromId(cleanId.slice(1));
      return new VaultysId(f2m, certificate, type);
    } else {
      const km = KeyManager.fromId(cleanId.slice(1));
      return new VaultysId(km, certificate, type);
    }
  }

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
      hints: [hint],
      extensions: {
        // @ts-expect-error "prf" is not yet included in dom types
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

  static async fromEntropy(entropy: Buffer, type: number) {
    const cleanedEntropy = entropy as Buffer;
    const km = await KeyManager.create_Id25519_fromEntropy(cleanedEntropy);

    return new VaultysId(km, undefined, type);
  }

  static async createWebauthn(passkey = true, onPRFEnabled?: () => Promise<boolean>) {
    const options = VaultysId.createPublicKeyCredentialCreationOptions(passkey);
    const attestation = await navigator.credentials.create({ publicKey: options });
    if (!attestation) return null;
    else return VaultysId.fido2FromAttestation(attestation as PublicKeyCredential, onPRFEnabled);
  }

  static async fido2FromAttestation(attestation: PublicKeyCredential, onPRFEnabled?: () => Promise<boolean>) {
    // should be somehow valid.
    await SoftCredentials.verifyPackedAttestation(attestation.response as AuthenticatorAttestationResponse, true);
    // @ts-expect-error prf not yet in dom
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

  static fromSecret(secret: string, encoding: BufferEncoding = "hex") {
    const secretBuffer = Buffer.from(secret, encoding);
    const type = secretBuffer[0];
    if (type == TYPE_FIDO2) {
      const f2m = Fido2Manager.fromSecret(secretBuffer.slice(1));
      return new VaultysId(f2m, undefined, type);
    } else if (type == TYPE_FIDO2PRF) {
      const f2m = Fido2PRFManager.fromSecret(secretBuffer.slice(1));
      return new VaultysId(f2m, undefined, type);
    } else {
      const km = KeyManager.fromSecret(secretBuffer.slice(1));
      return new VaultysId(km, undefined, type);
    }
  }
  static async generatePerson() {
    const km = await KeyManager.generate_Id25519();
    return new VaultysId(km, undefined, TYPE_PERSON);
  }

  static async generateOrganization() {
    const km = await KeyManager.generate_Id25519();
    return new VaultysId(km, undefined, TYPE_ORGANIZATION);
  }

  static async generateMachine() {
    const km = await KeyManager.generate_Id25519();
    return new VaultysId(km, undefined, TYPE_MACHINE);
  }

  get relationshipCertificate() {
    return this.certificate;
  }

  getSecret(encoding: BufferEncoding = "hex") {
    return Buffer.concat([Buffer.from([this.type]), this.keyManager.getSecret()]).toString(encoding);
  }

  get fingerprint() {
    const t = Buffer.from([this.type]).toString("hex");
    const fp = t + hash("SHA224", this.keyManager.id).toString("hex");
    return fp
      .slice(0, 40)
      .toUpperCase()
      .match(/.{1,4}/g)!
      .join(" ");
  }

  get did() {
    const t = Buffer.from([this.type]).toString("hex");
    const fp = t + hash("SHA224", this.keyManager.id).toString("hex");
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
          publicKeyMultibase: "m" + this.keyManager.signer.publicKey.toString("base64"),
        },
      ],
      keyAgreement: [
        {
          id: `${this.did}#keys-2`,
          type: this.keyManager.encType,
          controller: this.did,
          publicKeyMultibase: "m" + this.keyManager.cypher.publicKey.toString("base64"),
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

  // Need to think about insecure use of this function
  getOTP(prefix = "password", timelock = 24 * 3600000) {
    if (this.certificate) {
      const otp = Math.floor(new Date().getTime() / timelock);
      const toHash = Buffer.concat([Buffer.from(prefix, "utf-8"), Buffer.from(this.certificate), Buffer.from([otp])]);
      return hash("SHA256", toHash).toString("hex");
    }
    throw new Error("no certificate, cannot derive OTP");
  }

  async signChallenge(challenge: Buffer | string): Promise<Buffer> {
    if (typeof challenge == "string") {
      challenge = Buffer.from(challenge, "hex");
    }
    const result = hash("sha256", Buffer.concat([this.id, challenge as Buffer]));
    return this.keyManager.sign(result);
  }

  verifyChallenge(challenge: Buffer | string, signature: Buffer | string, userVerification: boolean) {
    if (typeof challenge == "string") {
      challenge = Buffer.from(challenge, "hex");
    }
    if (typeof signature == "string") {
      signature = Buffer.from(signature, "hex");
    }
    const result = hash("sha256", Buffer.concat([this.id, challenge as Buffer]));
    return this.keyManager.verify(result, signature as Buffer, userVerification);
  }

  async encrypt(plaintext: string, recipientIds: (Buffer | string)[]) {
    return this.keyManager.encrypt(
      plaintext,
      recipientIds.map((id) => {
        if (typeof id === "string") return Buffer.from(id.slice(2), "hex");
        else return (id as Buffer).slice(1);
      }),
    );
  }

  async decrypt(encryptedMessage: string, senderId?: Buffer | string) {
    let cleanId: Buffer | undefined;
    if (senderId) {
      if (typeof senderId === "string") cleanId = Buffer.from(senderId.slice(2));
      else cleanId = (senderId as Buffer).subarray(1);
    }
    return this.keyManager.decrypt(encryptedMessage, cleanId);
  }

  async hmac(message: string) {
    const cypher = await this.keyManager.getCypher();
    if (!cypher.secretKey) return null;
    const result = createHmac("sha256", cypher.secretKey.toString("hex"));
    result.update("VaultysID-" + message);
    return result.digest();
  }
}
