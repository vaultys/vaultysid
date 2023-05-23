import { randomBytes } from "./crypto.js";
import VaultysId from "./VaultysId.js";
import msgpack from "@ygoe/msgpack";

const ERROR = -2;
const UNITIALISED = -1;
const INIT = 0;
const STEP1 = 1;
const COMPLETE = 2;

const deserialize = (challenge) => {
  const unpacked = msgpack.deserialize(challenge);
  //console.log(unpacked)
  const clean = ["pk1", "pk2", "nonce", "sign1", "sign2"];
  clean.forEach(
    (k) => (unpacked[k] = unpacked[k] ? Buffer.from(unpacked[k]) : null),
  );
  const state = {
    state: ERROR,
  };
  const result = {
    ...unpacked,
    ...state
  };

  try {
    if (
      !result.pk2 &&
      !result.sign1 &&
      !result.sign2 &&
      result.nonce.length == 16 &&
      result.pk1.length > 0
    ) {
      result.state = INIT;
    } else if (
      !result.sign1 &&
      result.nonce.length == 32 &&
      result.pk1.length > 0 &&
      result.pk2.length > 0 &&
      result.sign2.length > 0
    ) {
      const id2 = VaultysId.fromId(result.pk2);
      const challenge = serializeUnsigned(result);
      if (id2.verifyChallenge(challenge, result.sign2)) {
        result.state = STEP1;
      } else {
        result.state = ERROR;
        result.error = "STEP1 failed to verification of pk2";
      }
    } else if (
      result.sign1.length > 0 &&
      result.nonce.length == 32 &&
      result.pk1.length > 0 &&
      result.pk2.length > 0 &&
      result.sign2.length > 0
    ) {
      const id1 = VaultysId.fromId(result.pk1);
      const id2 = VaultysId.fromId(result.pk2);
      const challenge = serializeUnsigned(result);
      if (id2.verifyChallenge(challenge, result.sign2)) {
        if (id1.verifyChallenge(challenge, result.sign1)) {
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
  } catch (error) {
    // console.log(error);
    result.state = ERROR;
    result.error = error.message;
  }
  return result;
};

const serialize = (data) => {
  if (data.state == INIT) {
    const { protocol, service, timestamp, pk1, nonce, metadata1} = data;
    const picked = { protocol, service, timestamp, pk1, nonce, metadata1};
    return msgpack.serialize(picked);
  }
  if (data.state == STEP1) {
    const { protocol, service, timestamp, pk1, pk2, nonce, sign2, metadata1, metadata2 } =
      data;
    const picked = {
      protocol,
      service,
      timestamp,
      pk1,
      pk2,
      nonce,
      sign2,
      metadata1,
      metadata2
    };
    return msgpack.serialize(picked);
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
      metadata1,
      metadata2
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
      metadata1,
      metadata2
    };
    return msgpack.serialize(picked);
  }
  return null;
};

const serializeUnsigned = (challenge) => {
  const { protocol, service, timestamp, pk1, pk2, nonce, metadata1, metadata2 } = challenge;
  return msgpack.serialize({
    protocol,
    service,
    timestamp,
    pk1,
    pk2,
    nonce,
    metadata1,
    metadata2
  });
};

const isLive = (challenge, liveliness) => {
  const time = Date.now();
  // allowing a deviation of 10 seconds in the future
  return (
    time - challenge.timestamp < liveliness &&
    challenge.timestamp <= time + 10000
  );
};

export default class Challenger {
  constructor(vaultysId, liveliness = 60 * 1000) {
    this.state = UNITIALISED;
    this.vaultysId = vaultysId;
    this.myKey = null;
    this.hisKey = null;
    this.hisMetadata = null;
    this.liveliness = liveliness;
  }

  static verifyCertificate(certificate) {
    const deser = deserialize(certificate);
    return deser.state == COMPLETE;
  }

  static deserializeCertificate = deserialize;

  async setChallenge(challengeString, requestMetadata = (keys) => {}) {
    if (this.state !== UNITIALISED)
      throw new Error("Challenger already initialised, can't reset the state");
    this.challenge = deserialize(challengeString);
    if (!isLive(this.challenge, this.liveliness)) {
      this.state == ERROR;
      this.challenge.error =
        "challenge timestamp failed the liveliness at first signature";
      throw new Error(this.challenge.error);
    }
    if (this.challenge.state == ERROR) {
      this.state == ERROR;
      // console.error(this.challenge);
      throw new Error(this.challenge.error);
    } else if (this.challenge.state == INIT) {
      const context = {
        protocol: this.challenge.protocol,
        service: this.challenge.service,
      };
      this.mykey = this.vaultysId.id;
      if (this.challenge.pk1 == this.mykey) {
        throw new Error(
          "Challenge is setup from the same vaultysId, this an unintended and unsafe use",
        );
      } else {
        this.challenge.pk2 = this.mykey;
        this.hisKey = this.challenge.pk1;
        this.hisMetadata = this.challenge.metadata1;
        this.challenge.nonce = Buffer.concat([
          this.challenge.nonce,
          randomBytes(16),
        ]);
        this.challenge.metadata2 = requestMetadata(Object.keys(this.hisMetadata)) || {};
        this.challenge.sign2 = await this.vaultysId.signChallenge(
          this.getUnsignedChallenge(),
        );
        this.challenge.state = this.state = STEP1;
      }
    } else if (this.challenge.state == COMPLETE) {
      const context = {
        protocol: this.challenge.protocol,
        service: this.challenge.service,
      };
      this.mykey = this.vaultysId.id;
      if (
        this.challenge.pk1 == this.mykey ||
        this.challenge.pk2 == this.mykey
      ) {
        this.state = COMPLETE;
      } else {
        this.state = ERROR;
        throw new Error("Can't link the vaultys id to this challenge");
      }
    } else {
      throw new Error(
        "Challenge is from a protocol already launched, this is completely unsafe",
      );
    }
  }

  getContext() {
    return {
      protocol: this.challenge.protocol,
      service: this.challenge.service,
      metadata: {
        metadata1: this.challenge.metadata1,
        metadata2: this.challenge.metadata2
      }
    };
  }

  createChallenge(protocol, service, metadata = {}) {
    if (this.state == UNITIALISED) {
      this.myKey = this.vaultysId.id;
      // console.log(this)
      this.challenge = {
        protocol,
        service,
        metadata1: metadata,
        timestamp: Date.now(),
        pk1: this.myKey,
        nonce: randomBytes(16),
        state: INIT,
      };
      this.state = INIT;
    } else {
      this.state = ERROR;
      throw new Error("Challenger already initialised, can't reset the state");
    }
  }

  getCertificate() {
    return Array.from(serialize(this.challenge));
  }

  getUnsignedChallenge() {
    const { protocol, service, timestamp, pk1, pk2, nonce, metadata1, metadata2 } =
      this.challenge;
    return msgpack.serialize({
      protocol,
      service,
      timestamp,
      pk1,
      pk2,
      nonce,
      metadata1,
      metadata2
    });
  }

  getContactId() {
    // to be sure this function is not misused, we get the id of the contact only once the protocol is complete
    if (this.isComplete()) {
      const contact = VaultysId.fromId(this.hisKey, this.getCertificate());
      return contact;
    } else
      throw new Error(
        "The challenge is not COMPLETE, it is unsafe to get the Contact ID before",
      );
  }

  getContactMetadata() {
    // console.log(this)
    // to be sure this function is not misused, we get the id of the contact only once the protocol is complete
    if (this.isComplete()) {
      return this.hisMetadata;
    } else
      throw new Error(
        "The challenge is not COMPLETE, it is unsafe to get the Contact Metadata before",
      );
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

  isSelfAuth() {
    return this.myKey == this.hisKey;
  }

  async update(challengeString, requestMetadata = (keys) => {}) {
    if (this.state == UNITIALISED) await this.setChallenge(challengeString, requestMetadata);
    else if (this.state == INIT) {
      this.challenge = deserialize(challengeString);
      if (!isLive(this.challenge, this.liveliness)) {
        this.state == ERROR;
        this.challenge.error =
          "challenge timestamp failed the liveliness at 2nd signature";
        throw new Error(this.challenge.error);
      }
      if (this.challenge.state == STEP1) {
        this.state = STEP1;
        if (Buffer.compare(this.myKey, this.challenge.pk1) != 0) {
          throw new Error(
            `The challenge has been tampered with. Received pk1 = '${this.challenge.pk1}', expected pk1 = '${this.myKey}'`,
          );
        }
        this.hisKey = this.challenge.pk2;
        this.hisMetadata = this.challenge.metadata2;
        // this.challenge.metadata1 = requestMetadata(Object.keys(this.hisMetadata));
        this.challenge.sign1 = await this.vaultysId.signChallenge(
          this.getUnsignedChallenge(),
        );
        this.state = this.challenge.state = COMPLETE;
      } else {
        this.state = ERROR;
        console.error(this.challenge);
        throw new Error(
          `The challenge is in an expected state. Received state = '${this.challenge.state}', expected state = '${STEP1}'`,
        );
      }
    } else if (this.state == STEP1) {
      this.challenge = deserialize(challengeString);
      if (this.challenge.state == COMPLETE) {
        this.state = COMPLETE;
      } else {
        this.state = ERROR;
        throw new Error(
          `The challenge is in an expected state. Received state = '${this.challenge.state}', expected state = '${COMPLETE}'`,
        );
      }
    } else {
      this.state = ERROR;
      throw new Error();
    }
  }
}
