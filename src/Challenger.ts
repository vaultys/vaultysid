import { decode, encode } from "@msgpack/msgpack";
import { randomBytes } from "./crypto";
import VaultysId from "./VaultysId";

const ERROR = -2;
const UNITIALISED = -1;
const INIT = 0;
const STEP1 = 1;
const COMPLETE = 2;

export type ChallengeType = {
  protocol: string
  service: string
  timestamp: number
  pk1?: Buffer
  pk2?: Buffer
  nonce?: Buffer
  sign1?: Buffer
  sign2?: Buffer
  metadata?: object
  state: number
  error: string
}

const writeString = (name: string, value: string) => Buffer.concat([Buffer.from([0xa0 + name.length]), Buffer.from(name, "ascii"), Buffer.from([0xa0 + value.length]), Buffer.from(value, "ascii")])
const writeBuffer = (name: string, value: Buffer) =>  Buffer.concat([Buffer.from([0xa0 + name.length]), Buffer.from(name, "ascii"), Buffer.from([0xc5, value.length >> 8, value.length]), value])
const writeInt = (name: string, value: number) => {
  // console.log(value)
  const start = Buffer.concat([Buffer.from([0xa0 + name.length]), Buffer.from(name, "ascii")])
  let end: Buffer;
  if (value >= 0 && value <= 0x7f) {
    end = Buffer.from([value]);
  }
  else if (value < 0 && value >= -0x20) {
    end = Buffer.from([value]);
  }
  else if (value > 0 && value <= 0xff) {   // uint8
    end = Buffer.from([0xcc, value]);
  }
  else if (value >= -0x80 && value <= 0x7f) {   // int8
    end = Buffer.from([0xd0, value]);
  }
  else if (value > 0 && value <= 0xffff) {   // uint16
    end = Buffer.from([0xcd, value >>> 8, value]);
  }
  else if (value >= -0x8000 && value <= 0x7fff) {   // int16
    end = Buffer.from([0xd1, value >>> 8, value]);
  }
  else if (value > 0 && value <= 0xffffffff) {   // uint32
    end = Buffer.from([0xce, value >>> 24, value >>> 16, value >>> 8, value]);
  }
  else if (value >= -0x80000000 && value <= 0x7fffffff) {   // int32
    end = Buffer.from([0xd2, value >>> 24, value >>> 16, value >>> 8, value]);
  }
  else if (value > 0 && value <= 0xffffffffffffffff) {   // uint64
    // Split 64 bit number into two 32 bit numbers because JavaScript only regards
    // 32 bits for bitwise operations.
    let hi = value / 2 ** 32;
    let lo = value % 2 ** 32;
    end = Buffer.from([0xd3, hi >>> 24, hi >>> 16, hi >>> 8, hi, lo >>> 24, lo >>> 16, lo >>> 8, lo]);
  }
  else {
    end = Buffer.from([0x00]);
  }
  return Buffer.concat([start, end]);
}


const encode_v0 = ({ protocol, service, timestamp, pk1, pk2, nonce, metadata }: { protocol: string, service: string, timestamp: number, pk1?: Buffer, pk2?: Buffer, nonce?: Buffer, metadata?: object }) => {
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
    Buffer.from([0x80]) // empty metadata
  ])
  // console.log(p.toString("base64"));
  return p;
}

const encode_v0_full = ({ protocol, service, timestamp, pk1, pk2, nonce, sign1, sign2, metadata }: { protocol: string, service: string, timestamp: number, pk1: Buffer, pk2: Buffer, nonce: Buffer, sign1: Buffer, sign2: Buffer, metadata: object }) => {
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
    Buffer.from([0x80]) // empty metadata
  ])
  //console.log(p.toString("ascii"))
  return p;
}

const deserialize = (challenge: Buffer): ChallengeType => {
  const unpacked = decode(challenge) as ChallengeType;
  // console.log(unpacked)
  //const clean = ["pk1", "pk2", "nonce", "sign1", "sign2"];
  // clean.forEach(
  //   (k: string) => (unpacked[k] = unpacked[k] ? Buffer.from(unpacked[k]) : null),
  // );
  const state = {
    state: ERROR,
    error: ""
  };
  const result = {
    ...unpacked,
    ...state,
  };

  try {
    if (
      !result.pk2 &&
      !result.sign1 &&
      !result.sign2 &&
      result.nonce?.length == 16 &&
      result.pk1?.length &&
      result.pk1.length > 0
    ) {
      result.state = INIT;
    } else if (
      !result.sign1 &&
      result.nonce?.length == 32 &&
      result.pk1?.length &&
      result.pk2?.length &&
      result.sign2?.length &&
      result.pk1.length > 0 &&
      result.pk2.length > 0 &&
      result.sign2.length > 0
    ) {
      const id2 = VaultysId.fromId(result.pk2!);
      const challenge = serializeUnsigned(result, id2.version);
      if (id2.verifyChallenge(challenge, result.sign2, true)) {
        result.state = STEP1;
      } else {
        result.state = ERROR;
        result.error = "STEP1 failed to verification of pk2";
      }
    } else if (
      result.sign1?.length &&
      result.sign1.length > 0 &&
      result.nonce?.length == 32 &&
      result.pk1?.length &&
      result.pk2?.length &&
      result.sign2?.length &&
      result.pk1.length > 0 &&
      result.pk2.length > 0 &&
      result.sign2.length > 0
    ) {
      const id1 = VaultysId.fromId(result.pk1!);
      const id2 = VaultysId.fromId(result.pk2!);
      if(id1.version != id2.version) {
        result.state = ERROR;
        result.error = "pk1 and pk2 are using different serialization version, this is not allowed";
      } else {
        const challenge = serializeUnsigned(result, id1.version);
        if (id2.verifyChallenge(challenge, result.sign2, true)) {
          if (id1.verifyChallenge(challenge, result.sign1, true)) {
            result.state = COMPLETE;
          } else {
            result.state = ERROR;
            result.error = "challenge failed to verification of pk1";
          }
        } else {
          result.state = ERROR;
          result.error =
            "challenge failed to verification of pk2, looks like a tentative to tamper with an existing signature";
        }
      }
    }
  } catch (error) {
    result.state = ERROR;
    result.error = error as string;
  }
  return result;
};

const serialize = (data: ChallengeType) => {
  if (data.state == INIT) {
    const { protocol, service, timestamp, pk1, nonce, metadata } = data;
    const picked = { protocol, service, timestamp, pk1, nonce, metadata }
    const encoded = encode(picked);
    return Buffer.from(encoded);
  }
  if (data.state == STEP1) {
    const { protocol, service, timestamp, pk1, pk2, nonce, sign2, metadata } =
      data;
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
    const {
      protocol,
      service,
      timestamp,
      pk1,
      pk2,
      nonce,
      sign1,
      sign2,
      metadata,
    } = data;
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
  // const encoded = encode({
  //   protocol,
  //   service,
  //   timestamp,
  //   pk1,
  //   pk2,
  //   nonce,
  //   metadata,
  // });
  // return Buffer.from(encoded);

  return version === 0 ? encode_v0(picked) : Buffer.from(encode(picked));
};

const isLive = (challenge: ChallengeType, liveliness: number) => {
  const time = Date.now();
  return (
    time - challenge.timestamp < liveliness &&
    challenge.timestamp <= time + 10000
  );
};

export default class Challenger {
  state: number
  vaultysId: VaultysId
  mykey: Buffer | undefined
  hisKey: Buffer | undefined
  liveliness: number
  challenge: ChallengeType | undefined
  version: number | undefined

  constructor(vaultysId: VaultysId, liveliness = 60 * 1000) {
    this.state = UNITIALISED;
    this.vaultysId = vaultysId;
    this.liveliness = liveliness;
  }

  static async verifyCertificate(certificate: Buffer) {
    const deser = deserialize(certificate);
    return deser.state == COMPLETE;
  }

  static deserializeCertificate = deserialize;
  static serializeCertificate_v0 = encode_v0_full;
  static serializeCertificate = serializeUnsigned;

  async setChallenge(challengeString: Buffer) {
    if (this.state !== UNITIALISED)
      throw new Error("Challenger already initialised, can't reset the state");
    this.challenge = deserialize(challengeString);
    // console.log(challengeString);
    if (!isLive(this.challenge, this.liveliness)) {
      this.state = ERROR;
      this.challenge.error =
        "challenge timestamp failed the liveliness at first signature";
      throw new Error(this.challenge.error);
    }
    if (this.challenge.state == ERROR) {
      this.state = ERROR;
      console.error(this.challenge);
      throw new Error(this.challenge.error);
    } else if (this.challenge.state == INIT) {
      const context = {
        protocol: this.challenge.protocol,
        service: this.challenge.service,
      };
      this.mykey = this.vaultysId.id;
      this.challenge.pk2 = this.mykey;
      this.hisKey = this.challenge.pk1;
      this.challenge.nonce = Buffer.concat([
        this.challenge.nonce || new Uint8Array(),
        randomBytes(16),
      ]);
      const serialized = this.getUnsignedChallenge();
      if (!serialized) throw new Error("Error processing Challenge");
      this.challenge.sign2 = await this.vaultysId.signChallenge(serialized) || undefined;
      this.challenge.state = this.state = STEP1;
    } else if (this.challenge.state == COMPLETE) {
      // const context = {
      //   protocol: this.challenge.protocol,
      //   service: this.challenge.service,
      // };
      if (this.challenge.pk1 != this.mykey && this.challenge.pk2 != this.mykey) {
        this.state = ERROR;
        throw new Error("Can't link the vaultys id to this challenge");
      } else {
        this.state = COMPLETE;
      }
    } else {
      throw new Error(
        "Challenge is from a protocol already launched, this is completely unsafe",
      );
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
    if (this.state == UNITIALISED) {
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
    if (!this.challenge) return null;
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
    } else
      throw new Error(
        "The challenge is not COMPLETE, it is unsafe to get the Contact ID before",
      );
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

  async update(challengeString: Buffer, metadata = {}) {
    if (this.state == UNITIALISED) await this.setChallenge(challengeString);
    else if (this.state == INIT) {
      this.challenge = deserialize(challengeString);
      if (!isLive(this.challenge, this.liveliness)) {
        this.state = ERROR;
        this.challenge.error =
          "challenge timestamp failed the liveliness at 2nd signature";
        throw new Error(this.challenge.error);
      }
      if (this.challenge.state == STEP1) {
        this.state = STEP1;
        if (!this.mykey || !this.challenge.pk1 || Buffer.compare(this.mykey, this.challenge.pk1) != 0) {
          throw new Error(`The challenge has been tampered with. Received pk1 = '${this.challenge.pk1}', expected pk1 = '${this.mykey}'`);
        }
        this.hisKey = this.challenge.pk2;
        const serialized = this.getUnsignedChallenge()
        
        if (!serialized) throw new Error("Error processing Challenge");
        this.challenge.sign1 = await this.vaultysId.signChallenge(serialized) || undefined;
        this.state = this.challenge.state = COMPLETE;
      } else {
        this.state = ERROR;
        // console.error(this.challenge);
        throw new Error(
          `The challenge is in an expected state. Received state = '${this.challenge.state}', expected state = '${STEP1}'`,
        );
      }
    } else if (this.state == STEP1) {
      this.challenge = deserialize(challengeString);
      this.mykey = this.challenge.pk2;
      if (this.challenge.state == COMPLETE) {
        this.state = COMPLETE;
      } else {
        // console.error(this.challenge);
        this.state = ERROR;
        throw new Error(`The challenge is in an expected state. Received state = '${this.challenge.state}', expected state = '${COMPLETE}'`);
      }
    } else {
      this.state = ERROR;
      throw new Error();
    }
  }
}
