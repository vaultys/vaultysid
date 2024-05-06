import Challenger from "./Challenger";
import Fido2Manager from "./Fido2Manager";
import KeyManager from "./KeyManager";
import { Channel } from "./MemoryChannel";
import { Store } from "./MemoryStorage";
import SoftCredentials from "./SoftCredentials";
import VaultysId from "./VaultysId";
import { randomBytes } from "./crypto";

const getSignatureType = (challenge: string) => {
  if (challenge.startsWith("vaultys://login?")) {
    return "LOGIN";
  } else if (challenge.startsWith("vaultys://docsign?")) {
    return "DOCUMENT";
  } else {
    return "UNKNOWN";
  }
};

export default class IdManager {
  vaultysId: VaultysId
  store: Store
  constructor(vaultysId: VaultysId, store: Store) {
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

  static async fromStore(store: Store) {
    const entropy = store.get("entropy");
    const secret = store.get("secret");
    if (secret) {
      if (entropy) {
        const secretBuffer = Buffer.from(secret, "base64");
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

  merge(otherStore: Store, master = true) {
    // TODO: check if same profile ?
    // TODO: revamp contact metadata and sync
    const master_store = master ? otherStore : this.store;
    const slave_store = master ? this.store : otherStore
    this.store.set("metadata", { ...slave_store.get("metadata"), ...master_store.get("metadata") });
    ["signatures", "wot"].forEach((table) => {
      let other = otherStore.substore(table);
      let me = this.store.substore(table);
      other.list().forEach((k) => {
        if (!me.get(k)) {
          me.set(k, other.get(k));
        }
      });
    });

    let other = otherStore.substore("contacts");
    let me = this.store.substore("contacts");
    const m = master ? other : me;
    const s = master ? me : other;
    other.list().forEach((did) => {
      if (!me.get(did)) {
        me.set(did, other.get(did));
      } else {
        const contact = me.get(did);
        contact.metadata = { ...s.get(did).metadata, ...m.get(did).metadata };
        me.set(did, contact);
      }
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
    const keyManager = this.vaultysId.keyManager as Fido2Manager;
    const creds = await navigator.credentials.get({
      publicKey: {
        challenge,
        allowCredentials: [
          {
            type: "public-key",
            id: keyManager.fid,
            transports: keyManager.transports,
          },
        ],
        userVerification: "discouraged",
      },
    }) as PublicKeyCredential;
    if (creds == null) return false;
    const response = creds.response as AuthenticatorAssertionResponse;
    const extractedChallenge = SoftCredentials.extractChallenge(Buffer.from(response.clientDataJSON));

    if (challenge.toString("base64") !== extractedChallenge) {
      return false;
    }
    return keyManager.verifyCredentials(creds);
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

  getContact(did: string) {
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

  setContactMetadata(did: string, name: string, value: any) {
    const c = this.store.substore("contacts").get(did);
    if (c) {
      if (!c.metadata) {
        c.metadata = {};
      }
      c.metadata[name] = value;
    }
  }

  getContactMetadata(did: string, name: string) {
    const c = this.store.substore("contacts").get(did);
    if (c && c.metadata) {
      return c.metadata[name];
    }
    return null;
  }

  getContactMetadatas(did: string) {
    const c = this.store.substore("contacts").get(did);
    if (c && c.metadata) {
      return c.metadata;
    }
    return null;
  }

  async verifyRelationshipCertificate(did: string) {
    const c = this.store.substore("contacts").get(did);
    return Challenger.verifyCertificate(c.certificate);
  }

  set name(n) {
    this.store.get("metadata").name = n;
  }

  get name() {
    return this.store.get("metadata").name;
  }

  get displayName() {
    const metadata = this.store.get("metadata");
    return metadata.firstname ? (metadata.firstname + " " + (metadata.name ?? "")) : (metadata.name ?? ("Anonymous " + this.vaultysId.fingerprint?.slice(-4)));
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

  // set avatar(n) {
  //   this.store.get("metadata").avatar = {
  //     data: Buffer.from(n.data).toString("base64"),
  //     type: n.type,
  //   };
  // }

  // get avatar() {
  //   const temp = this.store.get("metadata").avatar;
  //   if (!temp) return null;
  //   return {
  //     data: Buffer.from(temp.data, "base64"),
  //     type: temp.type,
  //   };
  // }

  async signChallenge(challenge: Buffer) {
    const signature = await this.vaultysId.signChallenge(challenge);
    this.store.substore("signatures").set("" + Date.now(), {
      signature,
      challenge,
    });
    this.store.save();
    return signature;
  }

  async signFile(hash: Buffer) {
    const challenge = Buffer.from(`vaultys://docsign?hash=${hash.toString("hex")}&timestamp=${Date.now()}`, "utf-8")
    const payload = {
      challenge,
      signature: await this.vaultysId.signChallenge(challenge)
    };
    this.store.substore("signatures").set(Date.now() + "", payload);
    this.store.save();
    return payload;
  }

  async verifyFile(challenge: Buffer, signature: Buffer, userVerifiation = true) {
    const data = challenge.toString("utf8");
    if (!data.startsWith("vaultys://docsign?")) {
      return false;
    }
    const url = new URL(data);
    if (
      url.search.match(/[a-z\d]+=[a-z\d]+/gi)?.length === 2 &&
      url.searchParams.get("hash") &&
      url.searchParams.get("timestamp")
    ) {
      return await this.vaultysId.verifyChallenge(challenge, signature, userVerifiation);
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

  async verifyChallenge(challenge: Buffer, signature: Buffer) {
    return this.vaultysId.verifyChallenge(challenge, signature, true);
  }

  async sync(channel: Channel, initiator = false) {
    if (initiator) {
      const challenger = await this.startSRP(channel, "p2p", "selfauth");

      if (challenger.isSelfAuth() && challenger.isComplete()) {
        const data = this.store.fromString((await channel.receive()).toString("utf-8"));
        channel.send(Buffer.from(this.store.toString(), "utf-8"));
        this.merge(data, !initiator)
      };
    } else {
      const challenger = await this.acceptSRP(channel, "p2p", "selfauth", true);

      if (challenger.isSelfAuth() && challenger.isComplete()) {
        channel.send(Buffer.from(this.store.toString(), "utf-8"));
        const data = this.store.fromString((await channel.receive()).toString("utf-8"));
        this.merge(data, !initiator);
      };
      channel.close();
    }
    this.store.save();
  }

  /***************************/
  /*   SIGNING PARTY HERE!   */
  /***************************/

  listCertificates() {
    const wot = this.store.substore("wot");
    return wot.list().map((timestamp) => {
      const c = wot.get(timestamp);
      if (c.timestamp) {
        return c;
      } else {
        const result = {
          ...Challenger.deserializeCertificate(wot.get(timestamp)),
          raw: c,
        }
        wot.set(timestamp, result);
        return result;
      }

    });
  }

  async startSRP(channel: Channel, protocol: string, service: string) {
    const challenger = new Challenger(this.vaultysId.toVersion(0));
    challenger.createChallenge(protocol, service, 0);
    const cert = challenger.getCertificate();
    if (!cert) {
      channel.close();
      channel.send(Buffer.from([0]));
      throw new Error("Error processing challenge");
    }

    channel.send(cert);
  
    try {
      const message = await channel.receive();
      // console.log(message)
      await challenger.update(message);
    } catch (error) {
      channel.send(Buffer.from([0]));
      throw new Error(error as string);
    }
    if (challenger.isComplete()) {
      const certificate = challenger.getCertificate();
      if (!certificate) {
        channel.close();
        channel.send(Buffer.from([0]));
        throw new Error("Error processing challenge");
      }
      // there is a caveat here, we are not sure that thhe last bit of information has been received
      channel.send(certificate);
      this.store.substore("wot").set(Date.now() + "", certificate);
      // TODO create/update merkle tree + sign it
      return challenger;
    } else {
      channel.send(Buffer.from([0]));
      throw new Error("Can't add a new contact if the protocol is not complete");
    }
  }

  async acceptSRP(channel: Channel, protocol: string, service: string, keepChannel = false) {
    const challenger = new Challenger(this.vaultysId.toVersion(0));
    try {
      let message = await channel.receive();
      await challenger.update(message);
    } catch (error) {
      channel.send(Buffer.from([0]));
      throw new Error(error as string);
    }

    const context = challenger.getContext();
    if (context.protocol != protocol || context.service != service) {
      channel.send(Buffer.from([0]));
      throw new Error(`The challenge was expecting protocol '${protocol}' and service '${service}', received '${context.protocol}' and '${context.service}'`);
    }

    const cert = challenger.getCertificate();
    if (!cert) {
      channel.close();
      channel.send(Buffer.from([0]));
      throw new Error("Error processing challenge");
    }

    channel.send(cert);
    
    try {
      let message = await channel.receive();
      await challenger.update(message);
    } catch (error) {
      channel.close();
      throw new Error(error as string);
    }
    if (challenger.isComplete()) {
      const certificate = challenger.getCertificate();
      if (!keepChannel) channel.close();
      this.store.substore("wot").set(Date.now() + "", certificate);
      // TODO create/update merkle tree + sign it
      return challenger;
    } else {
      channel.close();
      throw new Error("Can't add a new contact if the protocol is not complete");
    }

  }

  saveContact(contact: VaultysId) {
    if(contact.isMachine()) {
      this.store.substore("registrations").set(contact.did, {
        site: contact.did,
        serverId: contact?.id.toString("base64"),
        certificate: contact.certificate,
      })
    } else {
      this.store.substore("contacts").set(contact.did, contact);
    }
    
    this.store.save();
  }

  async askContact(channel: Channel) {
    const challenger = await this.startSRP(channel, "p2p", "auth");
    const contact = challenger.getContactId();
    this.saveContact(contact);
    return contact;
  }

  async acceptContact(channel: Channel) {
    const challenger = await this.acceptSRP(channel, "p2p", "auth");
    const contact = challenger.getContactId();
    this.saveContact(contact);
    return contact;
  }

  // Connecting to itself on 2 different devices, checking this is same vaultysId on both ends
  async askMyself(channel: Channel) {
    const challenger = await this.startSRP(channel, "p2p", "selfauth");
    return challenger.isSelfAuth() && challenger.isComplete();
  }

  async acceptMyself(channel: Channel) {
    const challenger = await this.acceptSRP(channel, "p2p", "selfauth");
    return challenger.isSelfAuth() && challenger.isComplete();
  }
}
