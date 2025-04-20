"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const Challenger_1 = __importDefault(require("./Challenger"));
const Fido2Manager_1 = __importDefault(require("./Fido2Manager"));
const KeyManager_1 = __importDefault(require("./KeyManager"));
const MemoryChannel_1 = require("./MemoryChannel");
const SoftCredentials_1 = __importDefault(require("./platform/SoftCredentials"));
const VaultysId_1 = __importDefault(require("./VaultysId"));
const crypto_1 = require("./crypto");
const Fido2PRFManager_1 = __importDefault(require("./Fido2PRFManager"));
const msgpack_1 = require("@msgpack/msgpack");
const buffer_1 = require("buffer/");
const tweetnacl_1 = __importDefault(require("tweetnacl"));
// "vaultys/encryption/" + version = 0x01
const ENCRYPTION_HEADER = buffer_1.Buffer.from("7661756c7479732f656e6372797074696f6e2f01", "hex");
const PRF_NONCE_LENGTH = 32;
const getSignatureType = (challenge) => {
    if (challenge.startsWith("vaultys://connect?")) {
        return "LOGIN";
    }
    else if (challenge.startsWith("vaultys://signfile?")) {
        return "DOCUMENT";
    }
    else {
        return "UNKNOWN";
    }
};
const instanciateContact = (c) => {
    let vaultysId;
    if (c.type === 3) {
        vaultysId = new VaultysId_1.default(Fido2Manager_1.default.instantiate(c.keyManager), c.certificate, c.type);
    }
    else if (c.type === 4) {
        vaultysId = new VaultysId_1.default(Fido2PRFManager_1.default.instantiate(c.keyManager), c.certificate, c.type);
    }
    else {
        vaultysId = new VaultysId_1.default(KeyManager_1.default.instantiate(c.keyManager), c.certificate, c.type);
    }
    return vaultysId;
};
const instanciateApp = (a) => {
    return VaultysId_1.default.fromId(buffer_1.Buffer.from(a.serverId, "base64"), a.certificate);
};
class IdManager {
    constructor(vaultysId, store) {
        // alias since this is symetric key encryption
        this.acceptEncryptFile = this.acceptDecryptFile;
        this.vaultysId = vaultysId;
        this.store = store;
        if (!this.store.get("metadata")) {
            this.store.set("metadata", {});
        }
        if (this.vaultysId.keyManager.entropy)
            this.store.set("entropy", this.vaultysId.keyManager.entropy);
        else
            this.store.set("secret", this.vaultysId.getSecret());
        this.store.save();
    }
    static async fromStore(store) {
        const entropy = store.get("entropy");
        const secret = store.get("secret");
        if (secret) {
            if (entropy) {
                const secretBuffer = buffer_1.Buffer.from(secret, "base64");
                const type = secretBuffer[0];
                const vaultysId = await VaultysId_1.default.fromEntropy(entropy, type);
                return new IdManager(vaultysId, store);
            }
            else {
                const vaultysId = VaultysId_1.default.fromSecret(secret);
                return new IdManager(vaultysId, store);
            }
        }
        else if (entropy) {
            const vaultysId = await VaultysId_1.default.machineFromEntropy(entropy);
            return new IdManager(vaultysId, store);
        }
        else {
            const vaultysId = await VaultysId_1.default.generateMachine();
            return new IdManager(vaultysId, store);
        }
    }
    merge(otherStore, master = true) {
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
            }
            else {
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
        if (!this.vaultysId.isHardware())
            return true;
        await window.CredentialUserInteractionRequest();
        const challenge = (0, crypto_1.randomBytes)(PRF_NONCE_LENGTH);
        const keyManager = this.vaultysId.keyManager;
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
        }));
        if (creds == null)
            return false;
        const response = creds.response;
        const extractedChallenge = SoftCredentials_1.default.extractChallenge(response.clientDataJSON);
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
    getContact(did) {
        const c = this.store.substore("contacts").get(did);
        if (!c)
            return null;
        return instanciateContact(c).toVersion(this.vaultysId.version);
    }
    getApp(did) {
        const app = this.store.substore("registrations").get(did);
        if (!app)
            return null;
        return instanciateApp(app).toVersion(this.vaultysId.version);
    }
    setContactMetadata(did, name, value) {
        const c = this.store.substore("contacts").get(did);
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
        const c = this.store.substore("contacts").get(did) || this.store.substore("registrations").get(did);
        return Challenger_1.default.verifyCertificate(c.certificate);
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
    async signChallenge(challenge) {
        const signature = await this.vaultysId.signChallenge(challenge);
        this.store.substore("signatures").set("" + Date.now(), {
            signature,
            challenge,
        });
        this.store.save();
        return signature;
    }
    async signFile(file) {
        const h = (0, crypto_1.hash)("sha256", file.arrayBuffer).toString("hex");
        const challenge = buffer_1.Buffer.from(`vaultys://signfile?hash=${h}&timestamp=${Date.now()}`, "utf-8");
        const payload = {
            challenge,
            signature: await this.vaultysId.signChallenge(challenge),
        };
        this.store.substore("signatures").set(Date.now() + "", payload);
        this.store.save();
        return payload;
    }
    verifyFile(file, fileSignature, contactId, userVerifiation = true) {
        const data = fileSignature.challenge.toString("utf8");
        if (!data.startsWith("vaultys://signfile?")) {
            return false;
        }
        const h = (0, crypto_1.hash)("sha256", file.arrayBuffer).toString("hex");
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
    async decryptFile(toDecrypt, channel) {
        // Extract nonce and ciphertext from arrayBuffer
        const data = new Uint8Array(toDecrypt.arrayBuffer);
        const header = data.slice(0, ENCRYPTION_HEADER.length);
        if (buffer_1.Buffer.from(header).toString("hex") !== ENCRYPTION_HEADER.toString("hex")) {
            throw new Error("Invalid header for encrypted file");
        }
        const prfNonceBytes = data.slice(ENCRYPTION_HEADER.length, ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH);
        const nonceBytes = data.slice(ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH, ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH + tweetnacl_1.default.secretbox.nonceLength);
        const ciphertext = data.slice(ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH + tweetnacl_1.default.secretbox.nonceLength);
        const prf = channel ? await this.requestPRF(channel, "encryption/" + buffer_1.Buffer.from(prfNonceBytes).toString("hex") + "/encryption") : await this.vaultysId.hmac("prf|encryption/" + buffer_1.Buffer.from(prfNonceBytes).toString("hex") + "/encryption|prf");
        if (prf?.length !== PRF_NONCE_LENGTH) {
            throw new Error("Invalid PRF generated");
        }
        // Use sha256 hash of the PRF as the secretbox key (must be 32 bytes)
        const secretKey = (0, crypto_1.hash)("sha256", prf);
        (0, crypto_1.secureErase)(prf);
        // Decrypt using nacl.secretbox.open
        const decrypted = tweetnacl_1.default.secretbox.open(ciphertext, nonceBytes, secretKey);
        (0, crypto_1.secureErase)(secretKey);
        if (!decrypted) {
            throw new Error("Decryption failed");
        }
        return {
            name: toDecrypt.name,
            type: toDecrypt.type,
            arrayBuffer: buffer_1.Buffer.from(decrypted),
        };
    }
    async encryptFile(toEncrypt, channel) {
        // Generate a secure random nonce for both the PRF and the secretbox
        const prfNonceBytes = (0, crypto_1.randomBytes)(PRF_NONCE_LENGTH);
        const prf = channel ? await this.requestPRF(channel, "encryption/" + buffer_1.Buffer.from(prfNonceBytes).toString("hex") + "/encryption") : await this.vaultysId.hmac("prf|encryption/" + prfNonceBytes.toString("hex") + "/encryption|prf");
        if (prf?.length !== PRF_NONCE_LENGTH) {
            return null;
        }
        // Use sha256 hash of the PRF as the secretbox key (must be 32 bytes)
        const secretKey = (0, crypto_1.hash)("sha256", prf);
        (0, crypto_1.secureErase)(prf);
        // Generate a random nonce for secretbox encryption
        const nonceBytes = tweetnacl_1.default.randomBytes(tweetnacl_1.default.secretbox.nonceLength);
        // Encrypt using nacl.secretbox
        const ciphertext = tweetnacl_1.default.secretbox(new Uint8Array(toEncrypt.arrayBuffer), nonceBytes, secretKey);
        (0, crypto_1.secureErase)(secretKey);
        // Combine encryption nonce and ciphertext into a single buffer
        const result = new Uint8Array(ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH + nonceBytes.length + ciphertext.length);
        result.set(ENCRYPTION_HEADER);
        result.set(prfNonceBytes, ENCRYPTION_HEADER.length);
        result.set(nonceBytes, ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH);
        result.set(ciphertext, ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH + nonceBytes.length);
        return {
            name: toEncrypt.name,
            type: toEncrypt.type,
            arrayBuffer: buffer_1.Buffer.from(result), // Buffer contains secretbox nonce + ciphertext
        };
    }
    getSignatures() {
        const store = this.store.substore("signatures");
        return store
            .list()
            .sort()
            .map((date) => {
            const payload = store.get(date);
            const challenge = buffer_1.Buffer.from(payload.challenge).toString("utf-8");
            return {
                date,
                payload,
                challenge,
                type: getSignatureType(challenge),
            };
        });
    }
    migrate(version) {
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
    async verifyChallenge(challenge, signature) {
        return this.vaultysId.verifyChallenge(challenge, signature, true);
    }
    async sync(channel, initiator = false) {
        if (initiator) {
            const challenger = await this.startSRP(channel, "p2p", "selfauth");
            if (challenger.isSelfAuth() && challenger.isComplete()) {
                const data = this.store.fromString((await channel.receive()).toString("utf-8"));
                channel.send(buffer_1.Buffer.from(this.store.toString(), "utf-8"));
                this.merge(data, !initiator);
            }
        }
        else {
            const challenger = await this.acceptSRP(channel, "p2p", "selfauth");
            if (challenger.isSelfAuth() && challenger.isComplete()) {
                channel.send(buffer_1.Buffer.from(this.store.toString(), "utf-8"));
                const data = this.store.fromString((await channel.receive()).toString("utf-8"));
                this.merge(data, !initiator);
            }
            channel.close();
        }
        this.store.save();
    }
    async upload(channel, stream) {
        const challenger = await this.startSRP(channel, "p2p", "transfer");
        if (challenger.isComplete()) {
            const { upload } = (0, MemoryChannel_1.StreamChannel)(channel);
            await upload(stream);
        }
        else
            channel.send(buffer_1.Buffer.from([0]));
    }
    async download(channel, stream) {
        const challenger = await this.acceptSRP(channel, "p2p", "transfer");
        if (challenger.isComplete()) {
            const { download } = (0, MemoryChannel_1.StreamChannel)(channel);
            await download(stream);
        }
        else
            channel.send(buffer_1.Buffer.from([0]));
    }
    async requestDecrypt(channel, toDecrypt) {
        const challenger = await this.acceptSRP(channel, "p2p", "decrypt");
        if (challenger.isComplete()) {
            channel.send(toDecrypt);
            const new_encrypted = await channel.receive();
            const decrypted = await this.vaultysId.dhiesDecrypt(new_encrypted, challenger.getContactId().id);
            return decrypted;
        }
        else
            channel.send(buffer_1.Buffer.from([0]));
    }
    async acceptDecrypt(channel, accept) {
        const challenger = await this.startSRP(channel, "p2p", "decrypt");
        if (challenger.isComplete()) {
            if (!accept || (await accept(challenger.getContactId()))) {
                const toDecrypt = await channel.receive();
                const decrypted = await this.vaultysId.decrypt(toDecrypt.toString("utf-8"));
                if (decrypted) {
                    const encrypted = await this.vaultysId.dhiesEncrypt(decrypted, challenger.getContactId().id);
                    channel.send(encrypted ?? buffer_1.Buffer.from([0]));
                }
                else
                    channel.send(buffer_1.Buffer.from([0]));
            }
        }
        else
            channel.send(buffer_1.Buffer.from([0]));
    }
    async requestDecryptFile(channel, toDecrypt) {
        return this.decryptFile(toDecrypt, channel);
    }
    async requestEncryptFile(channel, toEncrypt) {
        return this.encryptFile(toEncrypt, channel);
    }
    async acceptDecryptFile(channel, accept) {
        let result_contact = null;
        await this.acceptPRF(channel, (contact, appid) => {
            if (appid.length > 63 && appid.startsWith("encryption/") && appid.endsWith("/encryption")) {
                result_contact = contact;
                //TODO: maybe by default should be in web of trust?
                return accept?.(contact) || Promise.resolve(true);
            }
            else
                return Promise.resolve(false);
        });
        return result_contact;
    }
    async requestSignFile(channel, file) {
        const challenger = await this.acceptSRP(channel, "p2p", "signfile");
        if (challenger.isComplete()) {
            channel.send(buffer_1.Buffer.from((0, msgpack_1.encode)(file)));
            const result = await channel.receive();
            const fileSignature = (0, msgpack_1.decode)(result);
            if (this.verifyFile(file, fileSignature, challenger.getContactId().toVersion(1))) {
                return fileSignature;
            }
            else
                return undefined;
        }
        else
            channel.send(buffer_1.Buffer.from([0]));
    }
    async acceptSignFile(channel, accept) {
        const challenger = await this.startSRP(channel, "p2p", "signfile");
        if (challenger.isComplete()) {
            const result = await channel.receive();
            const file = (0, msgpack_1.decode)(result);
            if (!accept || (await accept(challenger.getContactId(), file))) {
                const result = await this.signFile(file);
                channel.send(buffer_1.Buffer.from((0, msgpack_1.encode)(result)));
            }
            else
                channel.send(buffer_1.Buffer.from([0]));
        }
        else
            channel.send(buffer_1.Buffer.from([0]));
    }
    async requestPRF(channel, appid) {
        if (appid.length < 3) {
            throw new Error("appid is too short, less than 3 characters");
        }
        if (appid.split("|").length > 1) {
            throw new Error("appid contains illegal character |");
        }
        const challenger = await this.acceptSRP(channel, "p2p", "prf");
        if (challenger.isComplete()) {
            channel.send(buffer_1.Buffer.from(appid, "utf-8"));
            const prf = await channel.receive();
            return buffer_1.Buffer.from(prf);
        }
        else
            channel.send(buffer_1.Buffer.from([0]));
    }
    async acceptPRF(channel, accept) {
        const challenger = await this.startSRP(channel, "p2p", "prf");
        if (challenger.isComplete()) {
            const result = await channel.receive();
            const appid = result.toString("utf-8");
            if (appid.length < 3 || appid.split("|").length > 1) {
                // error if appid is too short or contains illegal character
                channel.send(buffer_1.Buffer.from([0]));
            }
            else if (!accept || (await accept(challenger.getContactId(), appid))) {
                const hmac = (await this.vaultysId.hmac("prf|" + appid + "|prf")) ?? buffer_1.Buffer.from([0]);
                channel.send(hmac);
                (0, crypto_1.secureErase)(hmac);
            }
            else
                channel.send(buffer_1.Buffer.from([0]));
        }
        else
            channel.send(buffer_1.Buffer.from([0]));
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
            }
            else {
                const result = {
                    ...Challenger_1.default.deserializeCertificate(wot.get(timestamp)),
                    raw: c,
                };
                wot.set(timestamp, result);
                return result;
            }
        });
    }
    async startSRP(channel, protocol, service, metadata = {}) {
        const idV0 = VaultysId_1.default.fromSecret(this.vaultysId.getSecret()).toVersion(0);
        const challenger = new Challenger_1.default(idV0);
        challenger.createChallenge(protocol, service, 0, metadata);
        const cert = challenger.getCertificate();
        if (!cert) {
            channel.close();
            channel.send(buffer_1.Buffer.from([0]));
            throw new Error("Error processing challenge");
        }
        channel.send(cert);
        try {
            const message = await channel.receive();
            // console.log("startSRP", message)
            // TODO: accept contact id before going further
            //console.log(challenger);
            await challenger.update(message);
        }
        catch (error) {
            channel.send(buffer_1.Buffer.from([0]));
            throw new Error(error);
        }
        if (challenger.isComplete()) {
            const certificate = challenger.getCertificate();
            if (!certificate) {
                channel.close();
                channel.send(buffer_1.Buffer.from([0]));
                throw new Error("Error processing challenge");
            }
            // there is a caveat here, we are not sure that the last bit of information has been received
            channel.send(certificate);
            this.store.substore("wot").set(Date.now() + "", certificate);
            // TODO create/update merkle tree + sign it
            return challenger;
        }
        else {
            channel.send(buffer_1.Buffer.from([0]));
            throw new Error("Can't add a new contact if the protocol is not complete");
        }
    }
    async acceptSRP(channel, protocol, service, metadata = {}) {
        const idV0 = VaultysId_1.default.fromSecret(this.vaultysId.getSecret()).toVersion(0);
        const challenger = new Challenger_1.default(idV0);
        try {
            const message = await channel.receive();
            // console.log("acceptSRP", message)
            await challenger.update(message);
        }
        catch (error) {
            channel.send(buffer_1.Buffer.from([0]));
            throw new Error(error);
        }
        const cert = challenger.getCertificate();
        if (!cert) {
            channel.send(buffer_1.Buffer.from([0]));
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
        }
        catch (error) {
            await channel.close();
            throw new Error(error);
        }
        if (challenger.isComplete()) {
            const certificate = challenger.getCertificate();
            this.store.substore("wot").set(Date.now() + "", certificate);
            // TODO create/update merkle tree + sign it
            return challenger;
        }
        else {
            await channel.close();
            throw new Error("Can't add a new contact if the protocol is not complete");
        }
    }
    saveApp(app, name) {
        app.toVersion(this.vaultysId.version);
        if (!app.isMachine()) {
            this.saveContact(app);
        }
        else {
            const appstore = this.store.substore("registrations");
            if (!appstore.get(app.did)) {
                appstore.set(app.did, {
                    site: name ?? app.did,
                    serverId: app.id.toString("base64"),
                    certificate: app.certificate,
                });
            }
        }
    }
    saveContact(contact) {
        contact.toVersion(this.vaultysId.version);
        if (contact.isMachine()) {
            this.saveApp(contact);
        }
        else {
            const contactstore = this.store.substore("contacts");
            if (!contactstore.get(contact.did)) {
                contactstore.set(contact.did, contact);
                this.store.save();
            }
        }
    }
    async askContact(channel, metadata = {}) {
        const challenger = await this.startSRP(channel, "p2p", "auth");
        const contact = challenger.getContactId();
        this.saveContact(contact);
        return contact;
    }
    async acceptContact(channel, metadata = {}) {
        const challenger = await this.acceptSRP(channel, "p2p", "auth");
        const contact = challenger.getContactId();
        this.saveContact(contact);
        return contact;
    }
    // Connecting to itself on 2 different devices, checking this is same vaultysId on both ends
    // deprecated
    async askMyself(channel) {
        const challenger = await this.startSRP(channel, "p2p", "selfauth");
        return challenger.isSelfAuth() && challenger.isComplete();
    }
    // deprecated
    async acceptMyself(channel) {
        const challenger = await this.acceptSRP(channel, "p2p", "selfauth");
        return challenger.isSelfAuth() && challenger.isComplete();
    }
}
exports.default = IdManager;
