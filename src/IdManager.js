import Challenger from "./Challenger.js";
import Fido2Manager from "./Fido2Manager.js";
import KeyManager from "./KeyManager.js";
import SoftCredentials from "./SoftCredentials.js";
import VaultysId from "./VaultysId.js";
import { randomBytes } from "./crypto.js";

const getSignatureType = (challenge) => {
  if (challenge.startsWith("vaultys://login?")) {
    return "LOGIN";
  } else if (challenge.startsWith("vaultys://docsign?")) {
    return "DOCUMENT";
  } else {
    return "UNKNOWN";
  }
};

export default class IdManager {
  constructor(vaultysId, store) {
    this.vaultysId = vaultysId;
    this.store = store;
    if (!this.store.get("metadata")) {
      this.store.set("metadata", {});
    }
    if (this.vaultysId.keyManager.entropy)
      this.store.set("entropy", this.vaultysId.keyManager.entropy);
    else this.store.set("secret", this.vaultysId.getSecret());
    this.store.save();
  }

  static async fromStore(store) {
    const entropy = store.get("entropy");
    const secret = store.get("secret");
    if (secret) {
      if (entropy) {
        const secretBuffer = Buffer.from(secret, encoding);
        const type = secretBuffer[0];
        const vaultysId = await VaultysId.fromEntropy(entropy, type);
        return new IdManager(vaultysId, store);
      } else {
        const vaultysId = VaultysId.fromSecret(secret);
        return new IdManager(vaultysId, store);
      }
    } else if (entropy) {
      const vaultysId = await VaultysId.machineFromEntropy(entropy);
      return new IdManager(vaultysId, store);
    } else {
      const vaultysId = await VaultysId.generateMachine();
      return new IdManager(vaultysId, store);
    }
  }

  merge(otherStore) {
    // TODO: check if same profile ?
    // TODO: revamp contact metadata and sync
    ["contacts", "wot", "signatures"].forEach((table) => {
      let me = this.store.substore(table);
      let other = otherStore.substore(table);
      other.list().forEach((k) => {
        if (!me.get(k)) {
          m.set(k, other.get(k));
        }
      });
    });
    this.store.save();
  }

  isHardware() {
    return this.vaultysId.isHardware();
  }

  async signIn() {
    if (!this.vaultysId.isHardware()) return true;
    await window.CredentialUserInteractionRequest();
    const challenge = randomBytes(32);
    const creds = await navigator.credentials.get({
      publicKey: {
        challenge,
        allowCredentials: [
          {
            type: "public-key",
            id: Buffer.from(this.vaultysId.keyManager.fid, "base64"),
            transports: this.vaultysId.keyManager.transports,
          },
        ],
        userVerification: "discouraged",
      },
    });

    const extractedChallenge = SoftCredentials.extractChallenge(
      creds.response.clientDataJSON,
    );
    if (challenge.toString("base64") !== extractedChallenge) {
      return false;
    }
    return this.vaultysId.keyManager.verifyCredentials(creds);
  }

  get contacts() {
    const s = this.store.substore("contacts");
    return s
      .list()
      .map((c) => s.get(c))
      .map((vid) => {
        if (vid.type === 3) {
          return new VaultysId(
            Fido2Manager.instantiate(vid.keyManager),
            vid.certificate,
            vid.type,
          );
        } else {
          return new VaultysId(
            KeyManager.instantiate(vid.keyManager),
            vid.certificate,
            vid.type,
          );
        }
      });
  }

  getContact(did) {
    const c = this.store.substore("contacts").get(did);
    if (c.type === 3) {
      return new VaultysId(
        Fido2Manager.instantiate(c.keyManager),
        c.certificate,
        c.type,
      );
    } else {
      return new VaultysId(
        KeyManager.instantiate(c.keyManager),
        c.certificate,
        c.type,
      );
    }
  }

  setContactMetadata(did, name, value) {
    const c = this.store.substore("contacts").get(did);
    // console.log(c, did, name, value, this.store)
    if (c) {
      if (!c.metadata) {
        c.metadata = {};
      }
      c.metadata[name] = value;
    }
  }

  getContactMetadata(did, name) {
    const c = this.store.substore("contacts").get(did);
    if (c && c.metadata) {
      return c.metadata[name];
    }
    return null;
  }

  getContactMetadatas(did) {
    const c = this.store.substore("contacts").get(did);
    if (c && c.metadata) {
      return c.metadata;
    }
    return null;
  }

  async verifyRelationshipCertificate(did) {
    const c = this.store.substore("contacts").get(did);
    return Challenger.verifyCertificate(c.certificate);
  }

  set name(n) {
    this.store.get("metadata").name = n;
  }

  get name() {
    return this.store.get("metadata").name;
  }

  set phone(n) {
    this.store.get("metadata").phone = n;
  }

  get phone() {
    return this.store.get("metadata").phone;
  }

  set email(n) {
    this.store.get("metadata").email = n;
  }

  get email() {
    return this.store.get("metadata").email;
  }

  set avatar(n) {
    this.store.get("metadata").avatar = {
      data: Buffer.from(n.data).toString("base64"),
      type: n.type,
    };
  }

  get avatar() {
    const temp = this.store.get("metadata").avatar;
    if (!temp) return null;
    return {
      data: Buffer.from(temp.data, "base64"),
      type: temp.type,
    };
  }

  async signChallenge(challenge) {
    const signature = await this.vaultysId.signChallenge(challenge);
    this.store.substore("signatures").set(Date.now(), {
      signature,
      challenge,
    });
    this.store.save();
    return signature;
  }

  async signFile(hash) {
    const payload = {
      challenge: Buffer.from(
        `vaultys://docsign?hash=${hash.toString(
          "hex",
        )}&timestamp=${Date.now()}`,
        "utf-8",
      ),
    };
    payload.signature = await this.vaultysId.signChallenge(payload.challenge);
    this.store.substore("signatures").set(Date.now(), payload);
    this.store.save();
    return payload;
  }

  async verifyFile(challenge, signature, userVerifiation = true) {
    if (!challenge.startsWith("vaultys://docsign?")) {
      return false;
    }
    const url = new URL(challenge);
    if (
      url.search.match(/[a-z\d]+=[a-z\d]+/gi).length === 2 &&
      url.searchParams.get("hash") &&
      url.searchParams.get("timestamp")
    ) {
      return await this.vaultysId.verifyChallenge(
        Buffer.from(challenge, "utf-8"),
        signature,
        userVerifiation,
      );
    }

    return false;
  }

  getSignatures() {
    const store = this.store.substore("signatures");
    return store
      .list()
      .sort()
      .map((date) => {
        const payload = store.get(date);
        const challenge = Buffer.from(payload.challenge).toString("utf-8");
        return {
          date,
          payload,
          challenge,
          type: getSignatureType(challenge),
        };
      });
  }

  async verifyChallenge(challenge, signature) {
    return this.vaultysId.verifyChallenge(challenge, signature);
  }

  /***************************/
  /*   SIGNING PARTY HERE!   */
  /***************************/

  listCertificates() {
    const wot = this.store.substore("wot");
    return wot.list().map((timestamp) => {
      return {
        timestamp,
        certificate: Challenger.deserializeCertificate(wot.get(timestamp)),
      };
    });
  }

  async startSRP(channel, protocol, service) {
    const challenger = new Challenger(this.vaultysId);
    challenger.createChallenge(protocol, service);
    channel.send(challenger.getCertificate());
    const message = await channel.receive();
    await challenger.update(message);
    if (challenger.isComplete()) {
      const certificate = challenger.getCertificate();
      // there is a caveat here, we are not sure that thhe last bit of information has been received
      channel.send(certificate);
      this.store.substore("wot").set(Date.now(), certificate);
      // TODO create/update merkle tree + sign it
      return challenger;
    } else
      throw new Error(
        "Can't add a new contact if the protocol is not complete",
      );
  }

  async acceptSRP(channel, protocol, service) {
    const challenger = new Challenger(this.vaultysId);
    let message = await channel.receive();
    await challenger.update(message);
    const context = challenger.getContext();
    if (context.protocol != protocol || context.service != service) {
      throw new Error(
        `The challenge was expecting protocol 'p2p' and service 'auth', received '${protocol}' and '${service}'`,
      );
    }
    channel.send(challenger.getCertificate());
    message = await channel.receive();
    await challenger.update(message);
    if (challenger.isComplete()) {
      const certificate = challenger.getCertificate();
      channel.close();
      this.store.substore("wot").set(Date.now(), certificate);
      // TODO create/update merkle tree + sign it
      return challenger;
    } else
      throw new Error(
        "Can't add a new contact if the protocol is not complete",
      );
  }

  // We assume the we have sent contact information to create a *SECURE* communicationChannel so he is the only one listenning to it
  async askContact(channel) {
    const challenger = await this.startSRP(channel, "p2p", "auth");
    const contactId = challenger.getContactId();
    this.store.substore("contacts").set(contactId.did, contactId);
    this.store.save();
    return contactId;
  }

  // We assume the contact has sent information to create a *SECURE* communicationChannel so he is the only one listenning to it
  async acceptContact(channel) {
    const challenger = await this.acceptSRP(channel, "p2p", "auth");
    const contactId = challenger.getContactId();
    this.store.substore("contacts").set(contactId.did, contactId);
    this.store.save();
    return contactId;
  }

  // Connecting to itself on 2 different devices, checking this is same vaultysId on both ends
  async askMyself(channel) {
    const challenger = await this.startSRP(channel, "p2p", "selfauth");
    this.store.save();
    return challenger.isSelfAuth() && challenger.isComplete();
  }

  async acceptMyself(channel) {
    const challenger = await this.acceptSRP(channel, "p2p", "selfauth");
    this.store.save();
    return challenger.isSelfAuth() && challenger.isComplete();
  }
}
