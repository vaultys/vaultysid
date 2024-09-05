import { decode, encode } from "@msgpack/msgpack";
import { randomBytes } from "./crypto";
import VaultysId from "./VaultysId";

const ERROR = -2;
const UNINITIALISED = -1;
const INIT = 0;
const STEP1 = 1;
const COMPLETE = 2;

export type ChallengeType = {
  protocol: string;
  service: string;
  timestamp: number;
  pk1?: Buffer;
  pk2?: Buffer;
  nonce?: Buffer;
  sign1?: Buffer;
  sign2?: Buffer;
  metadata?: object;
  state: number;
  error: string;
};

const writeString = (name: string, value: string) => Buffer.concat([Buffer.from([0xa0 + name.length]), Buffer.from(name, "ascii"), Buffer.from([0xa0 + value.length]), Buffer.from(value, "ascii")]);
const writeBuffer = (name: string, value: Buffer) => Buffer.concat([Buffer.from([0xa0 + name.length]), Buffer.from(name, "ascii"), Buffer.from([0xc5, value.length >> 8, value.length]), value]);
const writeInt = (name: string, value: number) => {
  // console.log(value)
  const start = Buffer.concat([Buffer.from([0xa0 + name.length]), Buffer.from(name, "ascii")]);
  let end: Buffer;
  if (value >= 0 && value <= 0x7f) {
    end = Buffer.from([value]);
  } else if (value < 0 && value >= -0x20) {
    end = Buffer.from([value]);
  } else if (value > 0 && value <= 0xff) {
    // uint8
    end = Buffer.from([0xcc, value]);
  } else if (value >= -0x80 && value <= 0x7f) {
    // int8
    end = Buffer.from([0xd0, value]);
  } else if (value > 0 && value <= 0xffff) {
    // uint16
    end = Buffer.from([0xcd, value >>> 8, value]);
  } else if (value >= -0x8000 && value <= 0x7fff) {
    // int16
    end = Buffer.from([0xd1, value >>> 8, value]);
  } else if (value > 0 && value <= 0xffffffff) {
    // uint32
    end = Buffer.from([0xce, value >>> 24, value >>> 16, value >>> 8, value]);
  } else if (value >= -0x80000000 && value <= 0x7fffffff) {
    // int32
    end = Buffer.from([0xd2, value >>> 24, value >>> 16, value >>> 8, value]);
  } else if (value > 0 && value <= 0xffffffffffffffff) {
    // uint64
    // Split 64 bit number into two 32 bit numbers because JavaScript only regards
    // 32 bits for bitwise operations.
    const hi = value / 2 ** 32;
    const lo = value % 2 ** 32;
    end = Buffer.from([0xd3, hi >>> 24, hi >>> 16, hi >>> 8, hi, lo >>> 24, lo >>> 16, lo >>> 8, lo]);
  } else {
    end = Buffer.from([0x00]);
  }
  return Buffer.concat([start, end]);
};

const encode_v0 = ({ protocol, service, timestamp, pk1, pk2, nonce, metadata }: { protocol: string; service: string; timestamp: number; pk1?: Buffer; pk2?: Buffer; nonce?: Buffer; metadata?: object }) => {
  const p = Buffer.concat([
    Buffer.from([0x87]),
    writeString("protocol", protocol),
    writeString("service", service),
    writeInt("timestamp", timestamp),
    writeBuffer("pk1", pk1!),
    writeBuffer("pk2", pk2!),
    writeBuffer("nonce", nonce!),
    Buffer.from([0xa0 + "metadata".length]),
    Buffer.from("metadata", "ascii"),
    Buffer.from([0x80]), // empty metadata
  ]);
  // console.log(p.toString("base64"));
  return p;
};

const encode_v0_full = ({ protocol, service, timestamp, pk1, pk2, nonce, sign1, sign2, metadata }: { protocol: string; service: string; timestamp: number; pk1: Buffer; pk2: Buffer; nonce: Buffer; sign1: Buffer; sign2: Buffer; metadata: object }) => {
  const p = Buffer.concat([
    Buffer.from([0x89]),
    writeString("protocol", protocol),
    writeString("service", service),
    writeInt("timestamp", timestamp),
    writeBuffer("pk1", pk1),
    writeBuffer("pk2", pk2),
    writeBuffer("nonce", nonce),
    writeBuffer("sign1", sign1),
    writeBuffer("sign2", sign2),
    Buffer.from([0xa0 + "metadata".length]),
    Buffer.from("metadata", "ascii"),
    Buffer.from([0x80]), // empty metadata
  ]);
  //console.log(p.toString("ascii"))
  return p;
};

const deserialize = (challenge: Buffer): ChallengeType => {
  const unpacked = decode(challenge) as ChallengeType;
  const state = {
    state: ERROR,
    error: "",
  };
  const result = {
    ...unpacked,
    ...state,
  };

  try {
    if (!result.timestamp || !result.protocol || !result.service) {
      result.state = ERROR;
      result.error = "[ERROR] Challenge is missing values";
    } else if (!result.pk2 && !!result.pk1 && !result.sign1 && !result.sign2 && result.nonce?.length === 16) {
      result.state = INIT;
    } else if (!result.sign1 && result.nonce?.length === 32 && !!result.pk1 && !!result.pk2 && !!result.sign2) {
      result.state = STEP1;
      const id2 = VaultysId.fromId(result.pk2);
      const challenge = serializeUnsigned(result, id2.version);
      if (!id2.verifyChallenge(challenge, result.sign2, true)) {
        result.state = ERROR;
        result.error = "[STEP1] failed the verification of pk2";
      }
    } else if (!!result.sign1 && result.nonce?.length === 32 && !!result.pk1 && !!result.pk2 && !!result.sign2) {
      result.state = COMPLETE;
      const id1 = VaultysId.fromId(result.pk1);
      const id2 = VaultysId.fromId(result.pk2);
      if (id1.version !== id2.version) {
        result.state = ERROR;
        result.error = "[COMPLETE] pk1 and pk2 are using different serialization version";
      }
      const challenge = serializeUnsigned(result, id1.version);
      if (!id2.verifyChallenge(challenge, result.sign2, true)) {
        result.state = ERROR;
        result.error = "[COMPLETE] failed the verification of pk2";
      }
      if (!id1.verifyChallenge(challenge, result.sign1, true)) {
        result.state = ERROR;
        result.error = "[COMPLETE] failed the verification of pk1";
      }
    }
  } catch (error) {
    result.error = "[" + result.state + " -> ERROR] " + error;
    result.state = ERROR;
  }
  return result;
};

const serialize = (data: ChallengeType) => {
  if (data.state == INIT) {
    const { protocol, service, timestamp, pk1, nonce, metadata } = data;
    const picked = { protocol, service, timestamp, pk1, nonce, metadata };
    const encoded = encode(picked);
    return Buffer.from(encoded);
  }
  if (data.state == STEP1) {
    const { protocol, service, timestamp, pk1, pk2, nonce, sign2, metadata } = data;
    const picked = {
      protocol,
      service,
      timestamp,
      pk1,
      pk2,
      nonce,
      sign2,
      metadata,
    };
    const encoded = encode(picked);
    return Buffer.from(encoded);
  }
  if (data.state == COMPLETE) {
    const { protocol, service, timestamp, pk1, pk2, nonce, sign1, sign2, metadata } = data;
    const picked = {
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
    const encoded = encode(picked);
    return Buffer.from(encoded);
  }
  return null;
};

const serializeUnsigned = (challenge: ChallengeType, version: 0 | 1 = 0): Buffer => {
  const { protocol, service, timestamp, pk1, pk2, nonce, metadata } = challenge;
  const picked = { protocol, service, timestamp, pk1, pk2, nonce, metadata };
  return version === 0 ? encode_v0(picked) : Buffer.from(encode(picked));
};

const isLive = (challenge: ChallengeType, liveliness: number, time = Date.now()) => {
  return challenge.timestamp > time - liveliness && challenge.timestamp < time + liveliness;
};

export default class Challenger {
  state: number;
  vaultysId: VaultysId;
  mykey: Buffer | undefined;
  hisKey: Buffer | undefined;
  liveliness: number;
  challenge: ChallengeType | undefined;
  version: number | undefined;

  constructor(vaultysId: VaultysId, liveliness = 60 * 1000) {
    this.state = UNINITIALISED;
    this.vaultysId = vaultysId;
    this.liveliness = liveliness;
  }

  static async verifyCertificate(certificate: Buffer) {
    const deser = deserialize(certificate);
    return deser.state === COMPLETE;
  }

  static async fromCertificate(certificate: Buffer, liveliness?: number) {
    const deser = deserialize(certificate);
    if (deser.state === INIT) {
      const challenger = new Challenger(VaultysId.fromId(deser.pk1!).toVersion(0), liveliness);
      challenger.challenge = deser;
      challenger.mykey = deser.pk1;
      challenger.state = INIT;
    } else if (deser.state === STEP1) {
      const challenger = new Challenger(VaultysId.fromId(deser.pk2!).toVersion(0), liveliness);
      challenger.challenge = deser;
      challenger.mykey = deser.pk2;
      challenger.hisKey = deser.pk1;
      challenger.state = STEP1;
      return challenger;
    }
  }

  static deserializeCertificate = deserialize;
  static serializeCertificate_v0 = encode_v0_full;
  static serializeCertificate = serializeUnsigned;

  async setChallenge(challengeString: Buffer) {
    if (this.state !== UNINITIALISED) {
      this.state = ERROR;
      throw new Error("Challenger already initialised, can't reset the state");
    }

    this.challenge = deserialize(challengeString);

    if (!isLive(this.challenge, this.liveliness)) {
      this.state = ERROR;
      this.challenge.error = "challenge timestamp failed the liveliness at first signature";
      throw new Error(this.challenge.error);
    }
    if (this.challenge.state === ERROR) {
      this.state = ERROR;
      throw new Error(this.challenge.error);
    } else if (this.challenge.state === INIT) {
      this.mykey = this.vaultysId.id;
      this.challenge.pk2 = this.mykey;
      this.hisKey = this.challenge.pk1;
      this.challenge.nonce = Buffer.concat([this.challenge.nonce || new Uint8Array(), randomBytes(16)]);
      const serialized = this.getUnsignedChallenge();
      if (!serialized) throw new Error("Error processing Challenge");
      this.challenge.sign2 = (await this.vaultysId.signChallenge(serialized)) || undefined;
      this.challenge.state = this.state = STEP1;
    } else if (this.challenge.state === COMPLETE) {
      this.mykey = this.vaultysId.id;
      if (!this.challenge.pk1?.equals(this.mykey) && !this.challenge.pk1?.equals(this.mykey)) {
        this.state = ERROR;
        throw new Error("Can't link the vaultys id to this challenge");
      } else {
        this.state = COMPLETE;
      }
    } else {
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

  createChallenge(protocol: string, service: string, version: 0 | 1 = 1, metadata = {}) {
    if (this.state == UNINITIALISED) {
      this.mykey = this.vaultysId.toVersion(version).id;
      // console.log(this)
      this.challenge = {
        protocol,
        service,
        metadata,
        timestamp: Date.now(),
        pk1: this.mykey,
        nonce: randomBytes(16),
        state: INIT,
      } as ChallengeType;
      this.state = INIT;
    } else {
      this.state = ERROR;
      throw new Error("Challenger already initialised, can't reset the state");
    }
  }

  getCertificate() {
    if (!this.challenge) return Buffer.from([]);
    return Buffer.from(serialize(this.challenge) || []);
  }

  getUnsignedChallenge() {
    return serializeUnsigned(this.challenge!, this.vaultysId.version);
  }

  getContactDid() {
    if (!this.hisKey) return null;
    return VaultysId.fromId(this.hisKey).did;
  }

  getContactId() {
    // to be sure this function is not misused, we get the id of the contact only once the protocol is complete
    if (this.isComplete()) {
      const contact = VaultysId.fromId(this.hisKey!, this.getCertificate() || undefined);
      return contact;
    } else throw new Error("The challenge is not COMPLETE, it is unsafe to get the Contact ID before");
  }

  static fromString(vaultysId: VaultysId, challengeString: Buffer) {
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

  isSelfAuth() {
    return this.mykey?.toString("hex") == this.hisKey?.toString("hex");
  }

  async init(challengeString: Buffer) {
    if (this.state !== UNINITIALISED) {
      throw new Error("Can't init INITIALISED challenge");
    }
    const tempchallenge = deserialize(challengeString);
    if (tempchallenge.state === INIT) {
      if (tempchallenge.pk2?.toString("base64") !== this.vaultysId.id.toString("base64")) {
        this.state = ERROR;
        throw new Error("challenge is not corresponding to the right id");
      }
      this.challenge = tempchallenge;
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
      this.mykey = this.challenge.pk2;
      this.hisKey = this.challenge.pk1;
      this.state = this.challenge.state = STEP1;
      return;
    }
  }

  async update(challengeString: Buffer, metadata = {}) {
    if (this.state === ERROR) {
      throw new Error("Can't update ERRORneous challenge");
    } else if (this.state === COMPLETE) {
      throw new Error("Can't update COMPLETE challenge");
    } else {
      const tempchallenge = deserialize(challengeString);
      // console.log(this.state, tempchallenge.state);
      if (!tempchallenge) {
        this.state = ERROR;
        throw new Error("Can't read the new incoming challenge");
      }
      if (tempchallenge.state === ERROR) {
        this.state = ERROR;
        throw new Error(tempchallenge.error);
      }
      if (!isLive(tempchallenge, this.liveliness)) {
        this.state = ERROR;
        throw new Error("challenge timestamp failed the liveliness");
      }
      if (this.state === UNINITIALISED && tempchallenge.state === INIT) {
        this.challenge = tempchallenge;
        this.mykey = this.challenge.pk2 = this.vaultysId.id;
        this.hisKey = this.challenge.pk1;
        this.challenge.nonce = Buffer.concat([this.challenge.nonce!, randomBytes(16)]);
        const serialized = this.getUnsignedChallenge();
        this.challenge.sign2 = await this.vaultysId.signChallenge(serialized);
        this.challenge.state = this.state = STEP1;
        return;
      }
      if (this.state === UNINITIALISED && tempchallenge.state === STEP1) {
        if (tempchallenge.pk1?.toString("base64") !== this.vaultysId.id.toString("base64")) {
          this.state = ERROR;
          throw new Error("challenge is not corresponding to the right id");
        }
        const serialized = serializeUnsigned(tempchallenge, this.vaultysId.version);
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
      if (tempchallenge.protocol !== this.challenge!.protocol || tempchallenge.service !== this.challenge!.service) {
        this.state = ERROR;
        throw new Error(`The challenge was expecting protocol '${this.challenge!.protocol}' and service '${this.challenge!.service}', received '${tempchallenge.protocol}' and '${tempchallenge.service}'`);
      }
      if (this.state === INIT && tempchallenge.state === STEP1) {
        if (!tempchallenge.nonce?.subarray(0, 16).equals(this.challenge!.nonce!.subarray(0, 16))) {
          this.state = ERROR;
          throw new Error("Nonce has been tampered with");
        }
        if (tempchallenge.timestamp !== this.challenge?.timestamp) {
          this.state = ERROR;
          throw new Error("Timestamp has been tampered with");
        }
        if (!this.mykey?.equals(tempchallenge.pk1!)) {
          this.state = ERROR;
          throw new Error(`The challenge has been tampered with. Received pk1 = '${tempchallenge.pk1}', expected pk1 = '${this.mykey}'`);
        }
        const serialized = serializeUnsigned(tempchallenge, this.vaultysId.version);
        if (!serialized) {
          this.state = ERROR;
          throw new Error("Error processing Challenge");
        }
        tempchallenge.sign1 = await this.vaultysId.signChallenge(serialized);
        this.challenge = tempchallenge;
        this.hisKey = tempchallenge.pk2;
        this.state = this.challenge.state = COMPLETE;
      } else if (this.state === STEP1 && tempchallenge.state === COMPLETE) {
        if (tempchallenge.protocol !== this.challenge!.protocol || tempchallenge.service !== this.challenge!.service) {
          this.state = ERROR;
          throw new Error(`The challenge was expecting protocol '${this.challenge!.protocol}' and service '${this.challenge!.service}', received '${tempchallenge.protocol}' and '${tempchallenge.service}'`);
        }
        if (!tempchallenge.nonce?.subarray(16, 32).equals(this.challenge!.nonce!.subarray(16, 32))) {
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
        if (!this.mykey!.equals(tempchallenge.pk2!)) {
          this.state = ERROR;
          throw new Error(`The challenge pk2 has been tampered with`);
        }
        this.challenge = tempchallenge;
        this.state = COMPLETE;
      } else {
        console.log(tempchallenge);
        const error = `The challenge is in an expected state. Received state = '${tempchallenge.state}', expected state = '${this.state + 1}'`;
        this.state = ERROR;
        throw new Error(error);
      }
    }
  }
}
