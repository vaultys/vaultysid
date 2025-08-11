import { Readable, Writable } from "stream";
import Challenger from "./Challenger";
import KeyManager, { Ed25519Manager, Fido2Manager, Fido2PRFManager, HybridManager, DilithiumManager } from "./KeyManager";
import { Channel, StreamChannel } from "./MemoryChannel";
import { storagify, Store } from "./MemoryStorage";
import SoftCredentials from "./platform/SoftCredentials";
import VaultysId from "./VaultysId";
import { hash, randomBytes, secureErase } from "./crypto";
import { decode, encode } from "@msgpack/msgpack";
import { Buffer } from "buffer/";
import nacl from "tweetnacl";
import { VaultysBackup } from "./platform/abstract";
import { platformCrypto } from "./platform";
import DeprecatedKeyManager from "./KeyManager/DeprecatedKeyManager";
import { crypto } from "..";

// "vaultys/encryption/" + version = 0x01
const ENCRYPTION_HEADER = Buffer.from("7661756c7479732f656e6372797074696f6e2f01", "hex");
const PRF_NONCE_LENGTH = 32;

const getSignatureType = (challenge: string) => {
  if (challenge.startsWith("vaultys://connect?")) {
    return "LOGIN";
  } else if (challenge.startsWith("vaultys://signfile?")) {
    return "DOCUMENT";
  } else {
    return "UNKNOWN";
  }
};

export type StoredContact = {
  type: number;
  keyManager: KeyManager | DeprecatedKeyManager;
  certificate: Buffer;
};

export type StoredApp = {
  site: string;
  serverId: string;
  certificate: Buffer;
};

export type FileSignature = {
  challenge: Buffer;
  signature: Buffer;
};

export type File = {
  arrayBuffer: Buffer;
  type: string;
  name?: string;
};

export const instanciateContact = (c: StoredContact) => {
  let vaultysId: VaultysId;
  if (c.type === 3) {
    vaultysId = new VaultysId(Fido2Manager.instantiate(c.keyManager), c.certificate, c.type);
  } else if (c.type === 4) {
    vaultysId = new VaultysId(Fido2PRFManager.instantiate(c.keyManager), c.certificate, c.type);
  } else {
    // console.log(c.keyManager.signer.publicKey.length);
    if (c.keyManager.signer.publicKey.length === 1952) {
      vaultysId = new VaultysId(DilithiumManager.instantiate(c.keyManager), c.certificate, c.type);
    } else if (c.keyManager.signer.publicKey.length === 1984) {
      vaultysId = new VaultysId(HybridManager.instantiate(c.keyManager), c.certificate, c.type);
    } else if ((c.keyManager as DeprecatedKeyManager).proof) {
      //console.log(c);
      vaultysId = new VaultysId(DeprecatedKeyManager.instantiate(c.keyManager), c.certificate, c.type);
    } else {
      vaultysId = new VaultysId(Ed25519Manager.instantiate(c.keyManager), c.certificate, c.type);
    }
  }
  return vaultysId;
};

export const instanciateApp = (a: StoredApp) => {
  return VaultysId.fromId(Buffer.from(a.serverId, "base64"), a.certificate);
};

export default class IdManager {
  vaultysId: VaultysId;
  store: Store;
  protocol_version: 0 | 1 = 0;

  constructor(vaultysId: VaultysId, store: Store) {
    this.vaultysId = vaultysId;
    this.store = store;
    if (!this.store.get("metadata")) {
      this.store.set("metadata", {});
    }
    if (this.vaultysId.keyManager.entropy) this.store.set("entropy", this.vaultysId.keyManager.entropy);
    else this.store.set("secret", this.vaultysId.getSecret());
    this.store.save();
  }

  setProtocolVersion(version: 0 | 1) {
    this.protocol_version = version;
  }

  /**
   * Exports the current profile as a backup
   * @param encrypted Whether to encrypt the backup
   * @param passphrase Optional passphrase for encryption (generated if not provided)
   * @returns Object containing backup data and optional passphrase
   */
  async exportBackup(passphrase?: string): Promise<Uint8Array> {
    if (!passphrase) {
      // Plaintext export
      const exportedData: VaultysBackup = {
        version: 1,
        data: Buffer.from(encode(this.store.toJSON())),
      };
      return encode(exportedData);
    } else {
      const backup = await platformCrypto.pbkdf2.encrypt(passphrase, Buffer.from(encode(this.store.toJSON())));
      if (!backup) throw new Error("Failed to encrypt backup");

      return encode(backup);
    }
  }

  /**
   * Imports a backup file
   * @param backupData The backup file data as Uint8Array
   * @param passphrase Optional passphrase for decryption (only needed for encrypted backups)
   * @returns Promise resolving to import result or null if import failed
   */
  static async importBackup(backupData: Uint8Array, passphrase?: string): Promise<IdManager | null> {
    try {
      // Decode the backup data
      const backup = decode(backupData) as VaultysBackup;
      //console.log(backup);
      let importedData: Buffer | null;

      if (backup.encryptInfo) {
        // This is an encrypted backup
        if (!passphrase) {
          throw new Error("Passphrase required for encrypted backup");
        }

        if (!backup.data) {
          throw new Error("Invalid backup format");
        }

        importedData = await platformCrypto.pbkdf2.decrypt(backup, passphrase);

        if (!importedData) {
          throw new Error("Failed to decrypt backup. Incorrect passphrase?");
        }
      } else {
        importedData = backup.data;
      }

      //console.log(decode(importedData));

      // Import the data into a new profile
      // console.log(importedData, decode(importedData));
      const store = storagify(
        decode(importedData) as object,
        () => {},
        () => {},
      );
      return await IdManager.fromStore(store);
    } catch (error) {
      console.error("Import error:", error);
      return null;
    }
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
    const slave_store = master ? this.store : otherStore;
    this.store.set("metadata", { ...slave_store.get("metadata"), ...master_store.get("metadata") });
    ["signatures", "wot"].forEach((table) => {
      const other = otherStore.substore(table);
      const me = this.store.substore(table);
      other.list().forEach((k) => {
        if (!me.get(k)) {
          me.set(k, other.get(k));
        }
      });
    });

    const other = otherStore.substore("contacts");
    const me = this.store.substore("contacts");
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

  async verifyWebOfTrust() {
    let verified = true;
    for (const certid of this.store.substore("wot").list()) {
      const cert = this.store.substore("wot").get(certid);
      verified = verified && (await Challenger.verifyCertificate(Buffer.from(cert)));
      //if (!verified) console.log(Challenger.deserializeCertificate(cert));
    }
    //console.log("wot", verified);
    for (const appid of this.store.substore("registrations").list()) {
      const app = this.store.substore("registrations").get(appid);
      verified = verified && appid === VaultysId.fromId(app.serverId, undefined, "base64").did;
    }
    //console.log("registrations", verified);
    for (const contact of this.contacts) {
      verified = verified && (await Challenger.verifyCertificate(Buffer.from(contact!.certificate!)));
    }
    //console.log("contacts", verified);
    for (const app of this.apps) {
      verified = verified && (await Challenger.verifyCertificate(Buffer.from(app!.certificate!)));
    }
    //console.log("apps", verified);

    return verified;
  }

  isHardware() {
    return this.vaultysId.isHardware();
  }

  async signIn() {
    if (!this.vaultysId.isHardware()) return true;
    await window.CredentialUserInteractionRequest();
    const challenge = randomBytes(PRF_NONCE_LENGTH);
    const keyManager = this.vaultysId.keyManager as Fido2Manager;
    const creds = (await navigator.credentials.get({
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
    })) as PublicKeyCredential;
    if (creds == null) return false;
    const response = creds.response as AuthenticatorAssertionResponse;
    const extractedChallenge = SoftCredentials.extractChallenge(response.clientDataJSON);

    if (challenge.toString("base64") !== extractedChallenge) {
      return false;
    }
    return keyManager.verifyCredentials(creds);
  }

  get contacts() {
    const s = this.store.substore("contacts");
    return s
      .list()
      .map((did) => s.get(did))
      .map(instanciateContact)
      .map((contact) => contact.toVersion(this.vaultysId.version));
  }

  get apps() {
    const s = this.store.substore("registrations");
    return s
      .list()
      .map((did) => s.get(did))
      .map(instanciateApp)
      .map((app) => app.toVersion(this.vaultysId.version));
  }

  getContact(did: string) {
    const c = this.store.substore("contacts").get(did);
    if (!c) return null;
    return instanciateContact(c).toVersion(this.vaultysId.version);
  }

  getApp(did: string) {
    const app = this.store.substore("registrations").get(did);
    if (!app) return null;
    return instanciateApp(app).toVersion(this.vaultysId.version);
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
    const c = this.store.substore("contacts").get(did) || this.store.substore("registrations").get(did);
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
    const result = metadata.firstname ? metadata.firstname + " " + (metadata.name ?? "") : metadata.name;
    return result?.length > 0 ? result : "Anonymous " + this.vaultysId.fingerprint?.slice(-4);
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

  async signFile(file: File) {
    const h = hash("sha256", file.arrayBuffer).toString("hex");
    const challenge = Buffer.from(`vaultys://signfile?hash=${h}&timestamp=${Date.now()}`, "utf-8");
    const payload: FileSignature = {
      challenge,
      signature: await this.vaultysId.signChallenge(challenge),
    };
    this.store.substore("signatures").set(Date.now() + "", payload);
    this.store.save();
    return payload;
  }

  verifyFile(file: File, fileSignature: FileSignature, contactId: VaultysId, userVerifiation = true) {
    const data = fileSignature.challenge.toString("utf8");
    if (!data.startsWith("vaultys://signfile?")) {
      return false;
    }
    const h = hash("sha256", file.arrayBuffer).toString("hex");
    const url = new URL(data);
    const fileHash = url.searchParams.get("hash");
    if (h !== fileHash) {
      return false;
    }
    if (url.search.match(/[a-z\d]+=[a-z\d]+/gi)?.length === 2 && url.searchParams.get("timestamp")) {
      return contactId.verifyChallenge(fileSignature.challenge, fileSignature.signature, userVerifiation);
    }
    return false;
  }

  async decryptFile(toDecrypt: File, channel?: Channel) {
    // Extract nonce and ciphertext from arrayBuffer
    const data = new Uint8Array(toDecrypt.arrayBuffer);
    const header = data.slice(0, ENCRYPTION_HEADER.length);
    if (Buffer.from(header).toString("hex") !== ENCRYPTION_HEADER.toString("hex")) {
      throw new Error("Invalid header for encrypted file");
    }
    const prfNonceBytes = data.slice(ENCRYPTION_HEADER.length, ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH);
    const nonceBytes = data.slice(ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH, ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH + nacl.secretbox.nonceLength);
    const ciphertext = data.slice(ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH + nacl.secretbox.nonceLength);

    const prf = channel ? await this.requestPRF(channel, "encryption/" + Buffer.from(prfNonceBytes).toString("hex") + "/encryption") : await this.vaultysId.hmac("prf|encryption/" + Buffer.from(prfNonceBytes).toString("hex") + "/encryption|prf");
    if (prf?.length !== PRF_NONCE_LENGTH) {
      throw new Error("Invalid PRF generated");
    }

    // Use sha256 hash of the PRF as the secretbox key (must be 32 bytes)
    const secretKey = hash("sha256", prf);
    secureErase(prf);

    // Decrypt using nacl.secretbox.open
    const decrypted = nacl.secretbox.open(ciphertext, nonceBytes, secretKey);
    secureErase(secretKey);

    if (!decrypted) {
      throw new Error("Decryption failed");
    }

    return {
      name: toDecrypt.name,
      type: toDecrypt.type,
      arrayBuffer: Buffer.from(decrypted),
    } as File;
  }

  async encryptFile(toEncrypt: File, channel?: Channel) {
    // Generate a secure random nonce for both the PRF and the secretbox
    const prfNonceBytes = randomBytes(PRF_NONCE_LENGTH);

    const prf = channel ? await this.requestPRF(channel, "encryption/" + Buffer.from(prfNonceBytes).toString("hex") + "/encryption") : await this.vaultysId.hmac("prf|encryption/" + prfNonceBytes.toString("hex") + "/encryption|prf");
    if (prf?.length !== PRF_NONCE_LENGTH) {
      return null;
    }

    // Use sha256 hash of the PRF as the secretbox key (must be 32 bytes)
    const secretKey = hash("sha256", prf);
    secureErase(prf);

    // Generate a random nonce for secretbox encryption
    const nonceBytes = nacl.randomBytes(nacl.secretbox.nonceLength);

    // Encrypt using nacl.secretbox
    const ciphertext = nacl.secretbox(new Uint8Array(toEncrypt.arrayBuffer), nonceBytes, secretKey);
    secureErase(secretKey);

    // Combine encryption nonce and ciphertext into a single buffer
    const result = new Uint8Array(ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH + nonceBytes.length + ciphertext.length);
    result.set(ENCRYPTION_HEADER);
    result.set(prfNonceBytes, ENCRYPTION_HEADER.length);
    result.set(nonceBytes, ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH);
    result.set(ciphertext, ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH + nonceBytes.length);

    return {
      name: toEncrypt.name,
      type: toEncrypt.type,
      arrayBuffer: Buffer.from(result), // Buffer contains secretbox nonce + ciphertext
    } as File;
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

  migrate(version: 0 | 1) {
    this.vaultysId.toVersion(version);
    const s = this.store.substore("contacts");
    for (const did of s.list()) {
      const data = s.get(did);
      const contact = instanciateContact(data);
      const newContact = contact.toVersion(version);
      if (newContact.did !== did) {
        s.set(newContact.did, { ...contact, ...newContact, metadata: data.metadata, oldDid: did });
        s.delete(did);
        //console.log(did, "->", newContact.did);
      }
    }

    const apps = this.store.substore("registrations");
    for (const did of apps.list()) {
      const data = apps.get(did);
      const site = instanciateApp(data);
      if (site) {
        const newSite = site.toVersion(version);
        if (newSite.did !== did) {
          const name = data.site === did ? newSite.did : data.site;
          apps.set(newSite.did, { site: name, oldDid: did, serverId: newSite.id.toString("base64"), certificate: data.certificate, timestamp: data.timestamp });
          apps.delete(did);
          // console.log(did, "->", newSite.did);
        }
      }
    }
    this.store.save();
  }

  async verifyChallenge(challenge: Buffer, signature: Buffer) {
    return this.vaultysId.verifyChallenge(challenge, signature, true);
  }

  async upload(channel: Channel, stream: Readable) {
    const challenger = await this.startSRP(channel, "p2p", "transfer");
    if (challenger.isComplete()) {
      const { upload } = StreamChannel(channel);
      await upload(stream);
    } else channel.send(Buffer.from([0]));
  }

  async download(channel: Channel, stream: Writable) {
    const challenger = await this.acceptSRP(channel, "p2p", "transfer");
    if (challenger.isComplete()) {
      const { download } = StreamChannel(channel);
      await download(stream);
    } else channel.send(Buffer.from([0]));
  }

  async requestConnect(channel: Channel, contactdid: string) {
    let contact = this.getContact(contactdid);
    if (!contact) contact = this.getApp(contactdid);
    if (!contact) throw new Error(contactdid + " is not in the Web of Trust");
    const rand = crypto.randomBytes(16);
    const dh = await this.vaultysId.performDiffieHellman(contact);
    if (!dh) throw new Error("Unable to perform DH");
    channel.send(rand);
    const result2 = await channel.receive();
    const result1 = hash("sha256", nacl.scalarMult(rand, dh));
    if (result1.toString("base64") === result2.toString("base64")) return result1;
    else throw new Error("Opening session failed with contact " + contactdid);
  }

  async acceptConnect(channel: Channel, contactdid: string) {
    let contact = this.getContact(contactdid);
    if (!contact) contact = this.getApp(contactdid);
    if (!contact) throw new Error(contactdid + " is not in the Web of Trust");
    const dh = await this.vaultysId.performDiffieHellman(contact);
    if (!dh) throw new Error("Unable to perform DH");
    const rand = await channel.receive();
    const rand2 = Buffer.concat([rand.slice(0, 16), crypto.randomBytes(16)]);
    const result1 = hash("sha256", nacl.scalarMult(rand2, dh));
  }

  async requestDecrypt(channel: Channel, toDecrypt: Buffer) {
    const challenger = await this.acceptSRP(channel, "p2p", "decrypt");
    if (challenger.isComplete()) {
      channel.send(toDecrypt);
      const new_encrypted = await channel.receive();
      const decrypted = await this.vaultysId.dhiesDecrypt(new_encrypted, challenger.getContactId().id);
      return decrypted;
    } else channel.send(Buffer.from([0]));
  }

  async acceptDecrypt(channel: Channel, accept?: (contact: VaultysId) => Promise<boolean>) {
    const challenger = await this.startSRP(channel, "p2p", "decrypt", {}, accept);
    if (challenger.isComplete()) {
      const toDecrypt = await channel.receive();
      const decrypted = await this.vaultysId.decrypt(toDecrypt.toString("utf-8"));
      if (decrypted) {
        const encrypted = await this.vaultysId.dhiesEncrypt(decrypted, challenger.getContactId().id);
        channel.send(encrypted ?? Buffer.from([0]));
      } else channel.send(Buffer.from([0]));
    } else channel.send(Buffer.from([0]));
  }

  async requestDecryptFile(channel: Channel, toDecrypt: File) {
    return this.decryptFile(toDecrypt, channel);
  }

  async requestEncryptFile(channel: Channel, toEncrypt: File) {
    return this.encryptFile(toEncrypt, channel);
  }

  async acceptDecryptFile(channel: Channel, accept?: (contact: VaultysId) => Promise<boolean>) {
    let result_contact = null;
    await this.acceptPRF(channel, (contact: VaultysId, appid: string) => {
      if (appid.length > 63 && appid.startsWith("encryption/") && appid.endsWith("/encryption")) {
        result_contact = contact;
        //TODO: maybe by default should be in web of trust?
        return accept?.(contact) || Promise.resolve(true);
      } else return Promise.resolve(false);
    });
    return result_contact;
  }

  // alias since this is symetric key encryption
  acceptEncryptFile = this.acceptDecryptFile;

  async requestSignFile(channel: Channel, file: File) {
    const challenger = await this.acceptSRP(channel, "p2p", "signfile");
    if (challenger.isComplete()) {
      channel.send(Buffer.from(encode(file)));
      const result = await channel.receive();
      const fileSignature = decode(result) as FileSignature;
      if (this.verifyFile(file, fileSignature, challenger.getContactId().toVersion(1))) {
        return fileSignature;
      } else return undefined;
    } else channel.send(Buffer.from([0]));
  }

  async acceptSignFile(channel: Channel, accept?: (contact: VaultysId, file: File) => Promise<boolean>) {
    const challenger = await this.startSRP(channel, "p2p", "signfile");
    if (challenger.isComplete()) {
      const result = await channel.receive();
      const file = decode(result) as File;
      if (!accept || (await accept(challenger.getContactId(), file))) {
        const result = await this.signFile(file);
        channel.send(Buffer.from(encode(result)));
      } else channel.send(Buffer.from([0]));
    } else channel.send(Buffer.from([0]));
  }

  async requestPRF(channel: Channel, appid: string, accept?: (contact: VaultysId) => Promise<boolean>) {
    if (appid.length < 3) {
      throw new Error("appid is too short, less than 3 characters");
    }
    if (appid.split("|").length > 1) {
      throw new Error("appid contains illegal character |");
    }
    const challenger = await this.acceptSRP(channel, "p2p", "prf", undefined, accept);
    if (challenger.isComplete()) {
      channel.send(Buffer.from(appid, "utf-8"));
      const prf = await channel.receive();
      return Buffer.from(prf);
    } else channel.send(Buffer.from([0]));
  }

  async acceptPRF(channel: Channel, accept?: (contact: VaultysId, appid: string) => Promise<boolean>) {
    const challenger = await this.startSRP(channel, "p2p", "prf");
    if (challenger.isComplete()) {
      const result = await channel.receive();
      const appid = result.toString("utf-8");
      if (appid.length < 3 || appid.split("|").length > 1) {
        // error if appid is too short or contains illegal character
        channel.send(Buffer.from([0]));
      } else if (!accept || (await accept(challenger.getContactId(), appid))) {
        const hmac = (await this.vaultysId.hmac("prf|" + appid + "|prf")) ?? Buffer.from([0]);
        channel.send(hmac);
        secureErase(hmac);
      } else channel.send(Buffer.from([0]));
    } else channel.send(Buffer.from([0]));
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
        };
        wot.set(timestamp, result);
        return result;
      }
    });
  }

  async startSRP(channel: Channel, protocol: string, service: string, metadata: Record<string, string> = {}, accept?: (contact: VaultysId) => Promise<boolean>) {
    const challenger = new Challenger(this.vaultysId);
    challenger.createChallenge(protocol, service, this.protocol_version, metadata);
    //console.log(challenger);
    const cert = challenger.getCertificate();
    if (!cert) {
      channel.close();
      channel.send(Buffer.from([0]));
      throw new Error("Error processing challenge");
    }

    channel.send(cert);

    try {
      const message = await channel.receive();
      // console.log("startSRP", message)
      const contact = Challenger.deserializeCertificate(message).pk2;
      if (!contact) {
        channel.send(Buffer.from([0]));
        throw new Error("Contact pk2 is not sent");
      }
      if (accept && !(await accept(VaultysId.fromId(contact)))) {
        channel.send(Buffer.from([0]));
        throw new Error("Contact refused");
      }
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
      // there is a caveat here, we are not sure that the last bit of information has been received
      channel.send(certificate);
      this.store.substore("wot").set(Date.now() + "", certificate);
      // TODO create/update merkle tree + sign it
      return challenger;
    } else {
      channel.send(Buffer.from([0]));
      throw new Error("Can't add a new contact if the protocol is not complete");
    }
  }

  async acceptSRP(channel: Channel, protocol: string, service: string, metadata: Record<string, string> = {}, accept?: (contact: VaultysId) => Promise<boolean>) {
    const challenger = new Challenger(this.vaultysId);
    try {
      const message = await channel.receive();
      const chal = Challenger.deserializeCertificate(message);
      if (!chal.pk1) {
        channel.send(Buffer.from([0]));
        throw new Error("Contact pk1 is not sent");
      }
      if (chal.protocol !== protocol) {
        channel.send(Buffer.from([0]));
        throw new Error("protocol is not the one expected: " + chal.protocol + " !=" + protocol);
      }
      if (chal.service !== service) {
        channel.send(Buffer.from([0]));
        throw new Error("service is not the one expected: " + chal.service + " !=" + service);
      }
      if (accept && !(await accept(VaultysId.fromId(chal.pk1)))) {
        channel.send(Buffer.from([0]));
        throw new Error("Contact refused");
      }
      await challenger.update(message, metadata);
    } catch (error) {
      channel.send(Buffer.from([0]));
      throw new Error(error as string);
    }

    const cert = challenger.getCertificate();
    if (!cert) {
      channel.send(Buffer.from([0]));
      await channel.close();
      throw new Error("Error processing challenge");
    }
    // console.log("acceptSRP sending 1")
    channel.send(cert);
    // console.log("acceptSRP sending 2")

    try {
      const message = await channel.receive();
      // console.log("acceptSRP 2", message)
      await challenger.update(message);
    } catch (error) {
      await channel.close();
      //console.log(challenger);
      throw new Error(error as string);
    }
    if (challenger.isComplete()) {
      const certificate = challenger.getCertificate();
      this.store.substore("wot").set(Date.now() + "", certificate);
      // TODO create/update merkle tree + sign it
      return challenger;
    } else {
      await channel.close();
      throw new Error("Can't add a new contact if the protocol is not complete");
    }
  }

  saveApp(app: VaultysId, name?: string) {
    app.toVersion(this.vaultysId.version);
    if (!app.isMachine()) {
      this.saveContact(app);
    } else {
      const appstore = this.store.substore("registrations");
      if (!appstore.get(app.did)) {
        appstore.set(app.did, {
          site: name ?? app.did,
          serverId: app.id.toString("base64"),
          certificate: app.certificate,
        } as StoredApp);
      }
    }
  }

  saveContact(contact: VaultysId) {
    contact.toVersion(this.vaultysId.version);
    if (contact.isMachine()) {
      this.saveApp(contact);
    } else {
      const contactstore = this.store.substore("contacts");
      if (!contactstore.get(contact.did)) {
        contactstore.set(contact.did, contact as StoredContact);
        this.store.save();
      }
    }
  }

  async askContact(channel: Channel, metadata: Record<string, string> = {}, accept?: (contact: VaultysId) => Promise<boolean>) {
    const challenger = await this.startSRP(channel, "p2p", "auth", metadata, accept);
    const contact = challenger.getContactId();
    this.saveContact(contact);
    return contact;
  }

  async acceptContact(channel: Channel, metadata: Record<string, string> = {}, accept?: (contact: VaultysId) => Promise<boolean>) {
    const challenger = await this.acceptSRP(channel, "p2p", "auth", metadata, accept);
    const contact = challenger.getContactId();
    this.saveContact(contact);
    return contact;
  }
}
