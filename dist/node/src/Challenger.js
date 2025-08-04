"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const msgpack_1 = require("@msgpack/msgpack");
const crypto_1 = require("./crypto");
const VaultysId_1 = __importDefault(require("./VaultysId"));
const buffer_1 = require("buffer/");
const ERROR = -2;
const UNINITIALISED = -1;
const INIT = 0;
const STEP1 = 1;
const COMPLETE = 2;
const writeString = (name, value) => buffer_1.Buffer.concat([buffer_1.Buffer.from([0xa0 + name.length]), buffer_1.Buffer.from(name, "ascii"), buffer_1.Buffer.from([0xa0 + value.length]), buffer_1.Buffer.from(value, "ascii")]);
const writeBuffer = (name, value) => {
    const nameHeader = buffer_1.Buffer.concat([buffer_1.Buffer.from([0xa0 + name.length]), buffer_1.Buffer.from(name, "ascii")]);
    let lengthHeader;
    if (value.length <= 65535) {
        // bin16: binary data whose length is upto (2^16)-1 bytes
        lengthHeader = buffer_1.Buffer.from([0xc5, (value.length >> 8) & 0xff, value.length & 0xff]);
    }
    else {
        // bin32: binary data whose length is upto (2^32)-1 bytes
        lengthHeader = buffer_1.Buffer.from([0xc6, (value.length >> 24) & 0xff, (value.length >> 16) & 0xff, (value.length >> 8) & 0xff, value.length & 0xff]);
    }
    return buffer_1.Buffer.concat([nameHeader, lengthHeader, value]);
};
const writeInt = (name, value) => {
    // console.log(value)
    const start = buffer_1.Buffer.concat([buffer_1.Buffer.from([0xa0 + name.length]), buffer_1.Buffer.from(name, "ascii")]);
    let end;
    if (value >= 0 && value <= 0x7f) {
        end = buffer_1.Buffer.from([value]);
    }
    else if (value < 0 && value >= -0x20) {
        end = buffer_1.Buffer.from([value]);
    }
    else if (value > 0 && value <= 0xff) {
        // uint8
        end = buffer_1.Buffer.from([0xcc, value]);
    }
    else if (value >= -0x80 && value <= 0x7f) {
        // int8
        end = buffer_1.Buffer.from([0xd0, value]);
    }
    else if (value > 0 && value <= 0xffff) {
        // uint16
        end = buffer_1.Buffer.from([0xcd, value >>> 8, value]);
    }
    else if (value >= -0x8000 && value <= 0x7fff) {
        // int16
        end = buffer_1.Buffer.from([0xd1, value >>> 8, value]);
    }
    else if (value > 0 && value <= 0xffffffff) {
        // uint32
        end = buffer_1.Buffer.from([0xce, value >>> 24, value >>> 16, value >>> 8, value]);
    }
    else if (value >= -0x80000000 && value <= 0x7fffffff) {
        // int32
        end = buffer_1.Buffer.from([0xd2, value >>> 24, value >>> 16, value >>> 8, value]);
    }
    else if (value > 0 && value <= 0xffffffffffffffffn) {
        // uint64
        // Split 64 bit number into two 32 bit numbers because JavaScript only regards
        // 32 bits for bitwise operations.
        const hi = value / 2 ** 32;
        const lo = value % 2 ** 32;
        end = buffer_1.Buffer.from([0xd3, hi >>> 24, hi >>> 16, hi >>> 8, hi, lo >>> 24, lo >>> 16, lo >>> 8, lo]);
    }
    else {
        end = buffer_1.Buffer.from([0x00]);
    }
    return buffer_1.Buffer.concat([start, end]);
};
const encode_v0 = ({ version, protocol, service, timestamp, pk1, pk2, nonce, metadata }) => {
    const p = buffer_1.Buffer.concat([
        buffer_1.Buffer.from([0x87]),
        writeString("protocol", protocol),
        writeString("service", service),
        writeInt("timestamp", timestamp),
        writeBuffer("pk1", pk1),
        writeBuffer("pk2", pk2),
        writeBuffer("nonce", nonce),
        buffer_1.Buffer.from([0xa0 + "metadata".length]),
        buffer_1.Buffer.from("metadata", "ascii"),
        buffer_1.Buffer.from([0x80]), // empty metadata
    ]);
    // console.log(p.toString("base64"));
    return p;
};
const encode_v0_full = ({ version, protocol, service, timestamp, pk1, pk2, nonce, sign1, sign2, metadata }) => {
    const p = buffer_1.Buffer.concat([
        buffer_1.Buffer.from([0x89]),
        writeString("protocol", protocol),
        writeString("service", service),
        writeInt("timestamp", timestamp),
        writeBuffer("pk1", pk1),
        writeBuffer("pk2", pk2),
        writeBuffer("nonce", nonce),
        writeBuffer("sign1", sign1),
        writeBuffer("sign2", sign2),
        buffer_1.Buffer.from([0xa0 + "metadata".length]),
        buffer_1.Buffer.from("metadata", "ascii"),
        buffer_1.Buffer.from([0x80]), // empty metadata
    ]);
    //console.log(p.toString("ascii"))
    return p;
};
const deserialize = (challenge) => {
    const unpacked = (0, msgpack_1.decode)(buffer_1.Buffer.from(challenge));
    const state = {
        state: ERROR,
        error: "",
    };
    if (!unpacked.version) {
        unpacked.version = 0;
    }
    const result = {
        ...unpacked,
        ...state,
    };
    try {
        if (!result.timestamp || !result.protocol || !result.service) {
            result.state = ERROR;
            result.error = "[ERROR] Challenge is missing values";
        }
        else if (!result.pk2 && !!result.pk1 && !result.sign1 && !result.sign2 && result.nonce?.length === 16) {
            result.state = INIT;
        }
        else if (!result.sign1 && result.nonce?.length === 32 && !!result.pk1 && !!result.pk2 && !!result.sign2) {
            result.state = STEP1;
            const id2 = VaultysId_1.default.fromId(result.pk2);
            const challenge = serializeUnsigned(result);
            if (!id2.verifyChallenge(challenge, result.sign2, true) && !id2.verifyChallenge_v0(challenge, result.sign2, true, result.pk2)) {
                result.state = ERROR;
                result.error = "[STEP1] failed the verification of pk2";
            }
        }
        else if (!!result.sign1 && result.nonce?.length === 32 && !!result.pk1 && !!result.pk2 && !!result.sign2) {
            result.state = COMPLETE;
            //console.log(result);
            const id1 = VaultysId_1.default.fromId(result.pk1);
            const id2 = VaultysId_1.default.fromId(result.pk2);
            if (id1.version !== unpacked.version || id2.version !== unpacked.version) {
                //console.log(id1.version, id2.version, unpacked.version);
                result.state = ERROR;
                result.error = "[COMPLETE] pk1 and pk2 are using different serialization version";
            }
            const challenge = serializeUnsigned(result);
            if (!id2.verifyChallenge(challenge, result.sign2, true) && !id2.verifyChallenge_v0(challenge, result.sign2, true, result.pk2)) {
                result.state = ERROR;
                result.error = "[COMPLETE] failed the verification of pk2";
            }
            if (!id1.verifyChallenge(challenge, result.sign1, true) && !id1.verifyChallenge_v0(challenge, result.sign1, true, result.pk1)) {
                result.state = ERROR;
                //console.log(id1);
                result.error = "[COMPLETE] failed the verification of pk1";
            }
        }
    }
    catch (error) {
        result.error = "[" + result.state + " -> ERROR] " + error;
        result.state = ERROR;
        throw error;
    }
    return result;
};
const serialize = (data) => {
    if (data.state == INIT) {
        const { version, protocol, service, timestamp, pk1, nonce, metadata } = data;
        const picked = { version, protocol, service, timestamp, pk1, nonce, metadata };
        const encoded = (0, msgpack_1.encode)(picked);
        return buffer_1.Buffer.from(encoded);
    }
    if (data.state == STEP1) {
        const { version, protocol, service, timestamp, pk1, pk2, nonce, sign2, metadata } = data;
        const picked = {
            version,
            protocol,
            service,
            timestamp,
            pk1,
            pk2,
            nonce,
            sign2,
            metadata,
        };
        const encoded = (0, msgpack_1.encode)(picked);
        return buffer_1.Buffer.from(encoded);
    }
    if (data.state == COMPLETE) {
        const { version, protocol, service, timestamp, pk1, pk2, nonce, sign1, sign2, metadata } = data;
        const picked = {
            version,
            protocol,
            service,
            timestamp,
            pk1,
            pk2,
            nonce,
            sign1,
            sign2,
            metadata,
        };
        const encoded = (0, msgpack_1.encode)(picked);
        return buffer_1.Buffer.from(encoded);
    }
    return null;
};
const serializeUnsigned = (challenge) => {
    const { version, protocol, service, timestamp, pk1, pk2, nonce, metadata } = challenge;
    const picked = { version, protocol, service, timestamp, pk1, pk2, nonce, metadata };
    return version === 0 ? encode_v0(picked) : buffer_1.Buffer.from((0, msgpack_1.encode)(picked));
};
const isLive = (challenge, liveliness, time = Date.now()) => {
    return challenge.timestamp > time - liveliness && challenge.timestamp < time + liveliness;
};
class Challenger {
    constructor(vaultysId, liveliness = 60 * 1000) {
        this.version = 0;
        this.state = UNINITIALISED;
        // create a copy of VaultysId
        this.vaultysId = VaultysId_1.default.fromSecret(vaultysId.getSecret());
        this.liveliness = liveliness;
    }
    static async verifyCertificate(certificate) {
        const deser = deserialize(certificate);
        return deser.state === COMPLETE;
    }
    static async fromCertificate(certificate, liveliness) {
        const deser = deserialize(certificate);
        if (!deser.version) {
            deser.version = 0;
        }
        if (deser.state === INIT) {
            const challenger = new Challenger(VaultysId_1.default.fromId(deser.pk1).toVersion(deser.version), liveliness);
            challenger.challenge = deser;
            challenger.mykey = deser.pk1;
            challenger.state = INIT;
        }
        else if (deser.state === STEP1) {
            const challenger = new Challenger(VaultysId_1.default.fromId(deser.pk2).toVersion(deser.version), liveliness);
            challenger.challenge = deser;
            challenger.mykey = deser.pk2;
            challenger.hisKey = deser.pk1;
            challenger.state = STEP1;
            return challenger;
        }
    }
    async setChallenge(challengeString) {
        if (this.state !== UNINITIALISED) {
            this.state = ERROR;
            throw new Error("Challenger already initialised, can't reset the state");
        }
        this.challenge = deserialize(challengeString);
        this.version = this.challenge.version;
        if (!isLive(this.challenge, this.liveliness)) {
            this.state = ERROR;
            this.challenge.error = "challenge timestamp failed the liveliness at first signature";
            throw new Error(this.challenge.error);
        }
        if (this.challenge.state === ERROR) {
            this.state = ERROR;
            throw new Error(this.challenge.error);
        }
        else if (this.challenge.state === INIT) {
            //this.vaultysId.toVersion(this.challenge.version);
            this.mykey = this.vaultysId.id;
            this.challenge.pk2 = this.mykey;
            this.hisKey = this.challenge.pk1;
            this.challenge.nonce = buffer_1.Buffer.concat([this.challenge.nonce || new Uint8Array(), (0, crypto_1.randomBytes)(16)]);
            const serialized = this.getUnsignedChallenge();
            if (!serialized)
                throw new Error("Error processing Challenge");
            this.challenge.sign2 = (await this.vaultysId.signChallenge(serialized)) || undefined;
            this.challenge.state = this.state = STEP1;
        }
        else if (this.challenge.state === COMPLETE) {
            //this.vaultysId.toVersion(this.challenge.version);
            this.mykey = this.vaultysId.id;
            if (!this.challenge.pk1?.equals(this.mykey) && !this.challenge.pk1?.equals(this.mykey)) {
                this.state = ERROR;
                throw new Error("Can't link the vaultys id to this challenge");
            }
            else {
                this.state = COMPLETE;
            }
        }
        else {
            throw new Error("Challenge is from a protocol already launched, this is completely unsafe");
        }
    }
    getContext() {
        return {
            protocol: this.challenge?.protocol,
            service: this.challenge?.service,
            metadata: this.challenge?.metadata,
        };
    }
    createChallenge(protocol, service, version = 0, metadata) {
        this.version = version;
        if (this.state == UNINITIALISED) {
            this.mykey = this.vaultysId.toVersion(version).id;
            // console.log(this)
            this.challenge = {
                version,
                protocol,
                service,
                metadata: metadata ? { pk1: metadata } : {},
                timestamp: Date.now(),
                pk1: this.mykey,
                nonce: (0, crypto_1.randomBytes)(16),
                state: INIT,
            };
            this.state = INIT;
        }
        else {
            this.state = ERROR;
            throw new Error("Challenger already initialised, can't reset the state");
        }
    }
    getCertificate() {
        if (!this.challenge)
            return buffer_1.Buffer.from([]);
        return serialize(this.challenge) || buffer_1.Buffer.from([]);
    }
    getUnsignedChallenge() {
        return serializeUnsigned(this.challenge);
    }
    getContactDid() {
        if (!this.hisKey)
            return null;
        return VaultysId_1.default.fromId(this.hisKey).did;
    }
    getContactId() {
        // to be sure this function is not misused, we get the id of the contact only once the protocol is complete
        if (this.isComplete()) {
            const contact = VaultysId_1.default.fromId(this.hisKey, this.getCertificate() || undefined);
            return contact;
        }
        else
            throw new Error("The challenge is not COMPLETE, it is unsafe to get the Contact ID before");
    }
    static fromString(vaultysId, challengeString) {
        const challenger = new Challenger(vaultysId);
        challenger.setChallenge(challengeString);
        return challenger;
    }
    hasFailed() {
        return this.state == ERROR;
    }
    isComplete() {
        return this.state == COMPLETE;
    }
    async init(challenge) {
        if (this.state !== UNINITIALISED) {
            throw new Error("Can't init INITIALISED challenge");
        }
        const tempchallenge = deserialize(challenge);
        this.version = tempchallenge.version = tempchallenge.version ? 1 : 0;
        this.vaultysId.toVersion(this.version);
        if (tempchallenge.state === INIT) {
            if (tempchallenge.pk2?.toString("base64") !== this.vaultysId.id.toString("base64")) {
                this.state = ERROR;
                throw new Error("challenge is not corresponding to the right id");
            }
            this.challenge = tempchallenge;
            this.version = tempchallenge.version;
            this.mykey = this.challenge.pk2 = this.vaultysId.id;
            this.hisKey = this.challenge.pk1;
            this.challenge.state = this.state = INIT;
            return;
        }
        if (tempchallenge.state === STEP1) {
            if (tempchallenge.pk2?.toString("base64") !== this.vaultysId.id.toString("base64")) {
                this.state = ERROR;
                throw new Error("challenge is not corresponding to the right id");
            }
            this.challenge = tempchallenge;
            this.version = tempchallenge.version;
            this.mykey = this.challenge.pk2;
            this.hisKey = this.challenge.pk1;
            this.state = this.challenge.state = STEP1;
            return;
        }
    }
    async update(challenge, metadata) {
        if (this.state === ERROR) {
            throw new Error("Can't update errorneous challenge");
        }
        else if (this.state === COMPLETE) {
            throw new Error("Can't update COMPLETE challenge");
        }
        else {
            const tempchallenge = deserialize(challenge);
            // console.log(this.state, tempchallenge.state);
            if (!tempchallenge) {
                this.state = ERROR;
                throw new Error("Can't read the new incoming challenge");
            }
            if (tempchallenge.state === ERROR) {
                //console.log(tempchallenge.pk1?.length, tempchallenge.pk2?.length);
                this.state = ERROR;
                throw new Error(tempchallenge.error);
            }
            if (!isLive(tempchallenge, this.liveliness)) {
                // console.log(this.liveliness);
                // const time = Date.now();
                // console.log(time - tempchallenge.timestamp, this.liveliness);
                // console.log(tempchallenge.timestamp > time - this.liveliness && tempchallenge.timestamp < time + this.liveliness);
                this.state = ERROR;
                throw new Error("challenge timestamp failed the liveliness");
            }
            this.version = tempchallenge.version;
            this.vaultysId.toVersion(this.version);
            if (this.state === UNINITIALISED && tempchallenge.state === INIT) {
                if (tempchallenge.metadata.pk2) {
                    this.state = ERROR;
                    throw new Error("Metadata is malformed: pk2 is already set");
                }
                this.challenge = tempchallenge;
                this.mykey = this.challenge.pk2 = this.vaultysId.id;
                this.hisKey = this.challenge.pk1;
                if (metadata)
                    this.challenge.metadata.pk2 = metadata;
                this.challenge.nonce = buffer_1.Buffer.concat([this.challenge.nonce, (0, crypto_1.randomBytes)(16)]);
                const serialized = this.getUnsignedChallenge();
                this.challenge.sign2 = await this.vaultysId.signChallenge(serialized);
                this.challenge.state = this.state = STEP1;
                return;
            }
            if (this.state === UNINITIALISED && tempchallenge.state === STEP1) {
                if (tempchallenge.pk1?.toString("base64") !== this.vaultysId.id.toString("base64")) {
                    // console.log(this.vaultysId.version, this);
                    this.state = ERROR;
                    throw new Error("challenge is not corresponding to the right id");
                }
                const serialized = serializeUnsigned(tempchallenge);
                tempchallenge.sign1 = await this.vaultysId.signChallenge(serialized);
                this.challenge = tempchallenge;
                this.mykey = this.challenge.pk1;
                this.hisKey = this.challenge.pk2;
                this.state = this.challenge.state = COMPLETE;
                return;
            }
            if (this.state === UNINITIALISED && tempchallenge.state === COMPLETE) {
                console.log("COMPLETE case?!!");
                return;
            }
            if (tempchallenge.protocol !== this.challenge.protocol || tempchallenge.service !== this.challenge.service) {
                this.state = ERROR;
                throw new Error(`The challenge was expecting protocol '${this.challenge.protocol}' and service '${this.challenge.service}', received '${tempchallenge.protocol}' and '${tempchallenge.service}'`);
            }
            if (this.state === INIT && tempchallenge.state === STEP1) {
                // @ts-ignore
                if (!tempchallenge.nonce?.subarray(0, 16).equals(this.challenge.nonce.subarray(0, 16))) {
                    this.state = ERROR;
                    throw new Error("Nonce has been tampered with");
                }
                if (tempchallenge.timestamp !== this.challenge?.timestamp) {
                    this.state = ERROR;
                    throw new Error("Timestamp has been tampered with");
                }
                if (!this.mykey?.equals(tempchallenge.pk1)) {
                    this.state = ERROR;
                    throw new Error(`The challenge has been tampered with. Received pk1 = '${tempchallenge.pk1}', expected pk1 = '${this.mykey}'`);
                }
                const serialized = serializeUnsigned(tempchallenge);
                if (!serialized) {
                    this.state = ERROR;
                    throw new Error("Error processing Challenge");
                }
                tempchallenge.sign1 = await this.vaultysId.signChallenge(serialized);
                this.challenge = tempchallenge;
                this.hisKey = tempchallenge.pk2;
                this.state = this.challenge.state = COMPLETE;
            }
            else if (this.state === STEP1 && tempchallenge.state === COMPLETE) {
                if (tempchallenge.protocol !== this.challenge.protocol || tempchallenge.service !== this.challenge.service) {
                    this.state = ERROR;
                    throw new Error(`The challenge was expecting protocol '${this.challenge.protocol}' and service '${this.challenge.service}', received '${tempchallenge.protocol}' and '${tempchallenge.service}'`);
                }
                // @ts-ignore
                if (!tempchallenge.nonce?.subarray(16, 32).equals(this.challenge.nonce.subarray(16, 32))) {
                    this.state = ERROR;
                    throw new Error("Nonce has been tampered with");
                }
                if (tempchallenge.timestamp !== this.challenge?.timestamp) {
                    this.state = ERROR;
                    throw new Error("Timestamp has been tampered with");
                }
                // INFO: no need for liveliness check since the whole certificate is complete
                // if (!isLive(tempchallenge, this.liveliness)) {
                //   this.state = ERROR;
                //   throw new Error("challenge timestamp failed the liveliness at 2nd signature");
                // }
                if (!this.mykey.equals(tempchallenge.pk2)) {
                    this.state = ERROR;
                    throw new Error(`The challenge pk2 has been tampered with`);
                }
                this.challenge = tempchallenge;
                this.state = COMPLETE;
            }
            else {
                //console.log(tempchallenge);
                const error = `The challenge is in an expected state. Received state = '${tempchallenge.state}', expected state = '${this.state + 1}'`;
                this.state = ERROR;
                throw new Error(error);
            }
        }
    }
}
Challenger.deserializeCertificate = deserialize;
Challenger.serializeCertificate_v0 = encode_v0_full;
Challenger.serializeCertificate = serializeUnsigned;
exports.default = Challenger;
