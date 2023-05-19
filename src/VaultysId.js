import { hash } from "./crypto.js";
import Fido2Manager from "./Fido2Manager.js";
import KeyManager from "./KeyManager.js";
import SoftCredentials from "./SoftCredentials.js";

const TYPE_MACHINE = 0;
const TYPE_PERSON = 1;
const TYPE_ORGANIZATION = 2;
const TYPE_FIDO2 = 3;

export default class VaultysId {
  constructor(keyManager, certificate, type = TYPE_MACHINE) {
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
    if (id.data) {
      // serialised Buffer
      id = Buffer.from(id.data);
    }
    if (id instanceof Uint8Array) {
      // Buffer thing
      id = Buffer.from(id);
    }
    if (typeof id == "string") {
      id = Buffer.from(id, encoding);
    }
    const type = id[0];
    if (type == TYPE_FIDO2) {
      const f2m = Fido2Manager.fromId(id.slice(1));
      return new VaultysId(f2m, certificate, type);
    } else {
      const km = KeyManager.fromId(id.slice(1));
      return new VaultysId(km, certificate, type);
    }
  }

  static async fromEntropy(entropy, type) {
    if (entropy.data) {
      // Buffer thing
      entropy = Buffer.from(entropy.data);
    }
    const km = await KeyManager.create_Id25519_fromEntropy(entropy);
    return new VaultysId(km, null, type);
  }

  static async fido2FromAttestation(attestation) {
    // should be somehow valid.
    await SoftCredentials.verifyPackedAttestation(attestation.response, true);
    const f2m = await Fido2Manager.createFromAttestation(attestation);
    return new VaultysId(f2m, null, TYPE_FIDO2);
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
    const secretBuffer = Buffer.from(secret, encoding);
    const type = secretBuffer[0];
    if (type == TYPE_FIDO2) {
      const f2m = Fido2Manager.fromSecret(secretBuffer.slice(1));
      return new VaultysId(f2m, null, type);
    } else {
      const km = KeyManager.fromSecret(secretBuffer.slice(1));
      return new VaultysId(km, null, type);
    }
  }
  static async generatePerson() {
    const km = await KeyManager.generate_Id25519();
    return new VaultysId(km, null, TYPE_PERSON);
  }

  static async generateOrganization() {
    const km = await KeyManager.generate_Id25519();
    return new VaultysId(km, null, TYPE_ORGANIZATION);
  }

  static async generateMachine() {
    const km = await KeyManager.generate_Id25519();
    return new VaultysId(km, null, TYPE_MACHINE);
  }

  get relationshipCertificate() {
    return this.certificate;
  }

  getSecret(encoding = "hex") {
    return Buffer.concat([
      Buffer.from([this.type]),
      this.keyManager.getSecret(),
    ]).toString(encoding);
  }

  get fingerprint() {
    const t = Buffer.from([this.type]).toString("hex");
    const fp = t + hash("SHA224", this.keyManager.id).toString("hex");
    return fp
      .slice(0, 40)
      .toUpperCase()
      .match(/.{1,4}/g)
      .join(" ");
  }

  get did() {
    const t = Buffer.from([this.type]).toString("hex");
    const fp = t + hash("SHA224", this.keyManager.id).toString("hex");
    return `did:vaultys:${fp.slice(0, 40)}`;
  }

  get didDocument() {
    return {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
      ],
      id: this.did,
      authentication: [
        {
          id: `${this.did}#keys-1`,
          type: this.keyManager.authType,
          controller: this.did,
          publicKeyMultibase:
            "m" + this.keyManager.signer.publicKey.toString("base64"),
        },
      ],
      keyAgreement: [
        {
          id: `${this.did}#keys-2`,
          type: this.keyManager.encType,
          controller: this.did,
          publicKeyMultibase:
            "m" + this.keyManager.cypher.publicKey.toString("base64"),
        },
      ],
    };
  }

  get id() {
    return Buffer.concat([Buffer.from([this.type]), this.keyManager.id]);
  }

  isHardware() {
    return this.type === TYPE_FIDO2;
  }

  getOTPHmac(timelock = 1 * 3600000) {
    const otp = Math.floor(new Date().getTime() / timelock);
    return this.keyManager
      .getSecretHash(Buffer.from(`OTP-${otp}`))
      .toString("hex");
  }

  // Need to think about insecure use of this function
  getOTP(prefix = "password", timelock = 24 * 3600000) {
    if (this.certificate) {
      const otp = Math.floor(new Date().getTime() / timelock);
      const toHash = Buffer.concat([
        Buffer.from(prefix, "utf-8"),
        Buffer.from(this.certificate),
        Buffer.from([otp]),
      ]);
      return hash("SHA256", toHash).toString("hex");
    }
    throw new Error("no certificate, cannot derive OTP");
  }

  async signChallenge(challenge) {
    if (challenge.data) {
      challenge = Buffer.from(challenge.data);
    }
    if (typeof challenge == "string") {
      challenge = Buffer.from(challenge, "hex");
    }
    const result = hash("sha256", Buffer.concat([this.id, challenge]));
    return this.keyManager.sign(result);
  }

  verifyChallenge(challenge, signature, userVerification) {
    if (challenge.data) {
      challenge = Buffer.from(challenge.data);
    }
    if (typeof challenge == "string") {
      challenge = Buffer.from(challenge, "hex");
    }
    if (signature.data) {
      signature = Buffer.from(signature.data);
    }
    if (typeof signature == "string") {
      signature = Buffer.from(signature, "hex");
    }
    const result = hash("sha256", Buffer.concat([this.id, challenge]));
    return this.keyManager.verify(result, signature, userVerification);
  }

  async encrypt(plaintext, recipientIds) {
    return this.keyManager.encrypt(
      plaintext,
      recipientIds.map((id) => {
        if (typeof id === "string") return Buffer.from(id.slice(2), "hex");
        else if (id.data) return Buffer.from(id.data).slice(1);
        else return id.slice(1);
      }),
    );
  }

  async decrypt(encryptedMessage, senderId = null) {
    let cleanId;
    if (senderId) {
      if (typeof senderId === "string")
        cleanId = Buffer.from(senderId.slice(2));
      else if (senderId.data) cleanId = Buffer.from(senderId.data).slice(1);
      else cleanId = senderId.slice(1);
    }
    return this.keyManager.decrypt(encryptedMessage, cleanId);
  }
}
