import { decode, encode } from "@msgpack/msgpack";
import { randomBytes } from "./crypto";
import VaultysId from "./VaultysId";
import { Buffer } from "buffer/";

const ERROR = -2;
const UNINITIALISED = -1;
const INIT = 0;
const STEP1 = 1;
const COMPLETE = 2;

export const CHALLENGE_STATE = { ERROR, UNINITIALISED, INIT, STEP1, COMPLETE } as const;

/** The only supported handshake (challenge) version. Anything else is rejected. */
export const HANDSHAKE_VERSION = 1;

const NONCE_PART_LENGTH = 16;

export type ChallengeType = {
  version: 1;
  protocol: string;
  service: string;
  timestamp: number;
  pk1?: Buffer;
  pk2?: Buffer;
  nonce?: Buffer;
  sign1?: Buffer;
  sign2?: Buffer;
  metadata: {
    pk1?: Record<string, string>;
    pk2?: Record<string, string>;
  };
  state: number;
  error?: string;
};

const isBytes = (value: unknown): value is Uint8Array => value instanceof Uint8Array;

const isStringRecord = (value: unknown): value is Record<string, string> => !!value && typeof value === "object" && !Array.isArray(value) && !isBytes(value) && Object.values(value as object).every((v) => typeof v === "string");

const sameBytes = (a?: Uint8Array, b?: Uint8Array) => {
  if (!a || !b) return !a && !b;
  return Buffer.from(a).equals(Buffer.from(b));
};

const sameRecord = (a?: Record<string, string>, b?: Record<string, string>) => {
  if (!a || !b) return !a && !b;
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => Object.prototype.hasOwnProperty.call(b, k) && a[k] === b[k]);
};

/**
 * Canonical bytes covered by the handshake signatures (version 1 only):
 * msgpack of {version, protocol, service, timestamp, pk1, pk2, nonce, metadata}.
 */
const serializeUnsigned = (challenge: ChallengeType): Buffer => {
  if (challenge.version !== HANDSHAKE_VERSION) throw new Error("Unsupported challenge version");
  const { version, protocol, service, timestamp, pk1, pk2, nonce, metadata } = challenge;
  const picked = { version, protocol, service, timestamp, pk1, pk2, nonce, metadata };
  return Buffer.from(encode(picked));
};

const parseVaultysId = (pk: Buffer, name: string) => {
  const id = VaultysId.fromId(pk);
  if (id.version !== HANDSHAKE_VERSION) throw new Error(`${name} is not serialized with version ${HANDSHAKE_VERSION}`);
  return id;
};

/**
 * Parse and verify a serialized challenge. NEVER throws: any problem is
 * reported as `state === ERROR` with an `error` message. Signatures present in
 * the challenge are verified with the handshake domain.
 */
const deserialize = (challenge: Buffer | Uint8Array): ChallengeType => {
  const result = { state: ERROR, error: "", metadata: {} } as unknown as ChallengeType;
  const fail = (error: string) => {
    result.state = ERROR;
    result.error = error;
    return result;
  };
  let unpacked: Record<string, unknown>;
  try {
    const decoded = decode(Buffer.from(challenge));
    if (!decoded || typeof decoded !== "object" || Array.isArray(decoded) || isBytes(decoded)) return fail("[ERROR] Challenge is not a map");
    unpacked = decoded as Record<string, unknown>;
  } catch (error) {
    return fail("[ERROR] Challenge can't be decoded");
  }

  try {
    // copy fields, normalising binary values to Buffer
    for (const key of ["pk1", "pk2", "nonce", "sign1", "sign2"] as const) {
      const value = unpacked[key];
      if (value === undefined || value === null) continue;
      if (!isBytes(value)) return fail(`[ERROR] Challenge field ${key} is malformed`);
      result[key] = Buffer.from(value);
    }
    if (typeof unpacked.protocol === "string") result.protocol = unpacked.protocol;
    if (typeof unpacked.service === "string") result.service = unpacked.service;
    if (typeof unpacked.timestamp === "number") result.timestamp = unpacked.timestamp;
    result.version = unpacked.version as 1;

    if (unpacked.version !== HANDSHAKE_VERSION) return fail(`[ERROR] Unsupported challenge version ${String(unpacked.version)}`);
    if (!result.protocol || !result.service || !Number.isSafeInteger(result.timestamp) || result.timestamp <= 0) {
      return fail("[ERROR] Challenge is missing values");
    }
    const metadata = unpacked.metadata;
    if (!metadata || typeof metadata !== "object" || Array.isArray(metadata) || isBytes(metadata)) return fail("[ERROR] Challenge metadata is malformed");
    for (const key of Object.keys(metadata)) {
      if ((key !== "pk1" && key !== "pk2") || !isStringRecord((metadata as Record<string, unknown>)[key])) return fail("[ERROR] Challenge metadata is malformed");
    }
    result.metadata = metadata as ChallengeType["metadata"];

    const { pk1, pk2, nonce, sign1, sign2 } = result;
    if (!pk2 && !!pk1 && !sign1 && !sign2 && nonce?.length === NONCE_PART_LENGTH) {
      if (result.metadata.pk2) return fail("[INIT] Metadata is malformed: pk2 is already set");
      parseVaultysId(pk1, "pk1");
      result.state = INIT;
    } else if (!sign1 && nonce?.length === 2 * NONCE_PART_LENGTH && !!pk1 && !!pk2 && !!sign2) {
      parseVaultysId(pk1, "pk1");
      const id2 = parseVaultysId(pk2, "pk2");
      if (!id2.verifyHandshake(serializeUnsigned(result), sign2)) return fail("[STEP1] failed the verification of pk2");
      result.state = STEP1;
    } else if (!!sign1 && nonce?.length === 2 * NONCE_PART_LENGTH && !!pk1 && !!pk2 && !!sign2) {
      const id1 = parseVaultysId(pk1, "pk1");
      const id2 = parseVaultysId(pk2, "pk2");
      const unsigned = serializeUnsigned(result);
      if (!id2.verifyHandshake(unsigned, sign2)) return fail("[COMPLETE] failed the verification of pk2");
      if (!id1.verifyHandshake(unsigned, sign1)) return fail("[COMPLETE] failed the verification of pk1");
      result.state = COMPLETE;
    } else {
      return fail("[ERROR] Challenge is malformed");
    }
  } catch (error) {
    return fail("[ERROR] " + ((error as Error)?.message ?? error));
  }
  result.error = "";
  return result;
};

const serialize = (data: ChallengeType) => {
  if (data.state == INIT) {
    const { version, protocol, service, timestamp, pk1, nonce, metadata } = data;
    const picked = { version, protocol, service, timestamp, pk1, nonce, metadata };
    const encoded = encode(picked);
    return Buffer.from(encoded);
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
    const encoded = encode(picked);
    return Buffer.from(encoded);
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
    const encoded = encode(picked);
    return Buffer.from(encoded);
  }
  return null;
};

const isLive = (challenge: ChallengeType, liveliness: number, time = Date.now()) => {
  return challenge.timestamp > time - liveliness && challenge.timestamp < time + liveliness;
};

/**
 * Symmetric Proof of Relationship handshake (version 1 only).
 *
 * State machine (anything else sets ERROR and throws):
 *  - initiator: UNINITIALISED --createChallenge--> INIT --update(STEP1)--> COMPLETE
 *  - responder: UNINITIALISED --update(INIT)--> STEP1 --update(COMPLETE)--> COMPLETE
 * COMPLETE and ERROR are terminal.
 */
export default class Challenger {
  state: number;
  vaultysId: VaultysId;
  mykey: Buffer | undefined;
  hisKey: Buffer | undefined;
  liveliness: number;
  challenge: ChallengeType | undefined;
  version: 1 = HANDSHAKE_VERSION;
  // set when a certificate is loaded for inspection (setChallenge / fromCertificate):
  // such a Challenger can never sign nor become COMPLETE.
  readOnly = false;

  constructor(vaultysId: VaultysId, liveliness = 60 * 1000) {
    this.state = UNINITIALISED;
    // work on a copy of the VaultysId, serialized with the handshake version
    this.vaultysId = vaultysId.keyManager.capability === "public" ? VaultysId.fromId(vaultysId.id) : VaultysId.fromSecret(vaultysId.getSecret());
    this.vaultysId.toVersion(HANDSHAKE_VERSION);
    this.liveliness = liveliness;
  }

  /** Read-only verification of a certificate: true iff it is a valid COMPLETE v1 handshake. Never throws. */
  static async verifyCertificate(certificate: Buffer | Uint8Array) {
    return deserialize(certificate).state === COMPLETE;
  }

  /**
   * Load a certificate for inspection. The returned Challenger is read-only: it
   * never signs and never reaches COMPLETE. Returns undefined if the certificate
   * is invalid.
   */
  static async fromCertificate(certificate: Buffer | Uint8Array, liveliness?: number) {
    const deser = deserialize(certificate);
    if (deser.state === ERROR) return undefined;
    const owner = deser.state === INIT ? deser.pk1! : deser.pk2!;
    const challenger = new Challenger(VaultysId.fromId(owner), liveliness);
    challenger.readOnly = true;
    challenger.challenge = deser;
    challenger.mykey = owner;
    challenger.hisKey = deser.state === INIT ? undefined : deser.pk1;
    return challenger;
  }

  static deserializeCertificate = deserialize;
  static serializeCertificate = serializeUnsigned;

  private fail(message: string): never {
    this.state = ERROR;
    if (this.challenge) this.challenge.error = message;
    throw new Error(message);
  }

  /**
   * Load an existing certificate for inspection (READ-ONLY): it verifies the
   * certificate but never signs, never completes a session and leaves this
   * Challenger unusable for the handshake. Returns true if the certificate is a
   * valid COMPLETE handshake.
   */
  async setChallenge(challengeString: Buffer | Uint8Array) {
    if (this.state !== UNINITIALISED || this.readOnly) {
      this.state = ERROR;
      throw new Error("Challenger already initialised, can't reset the state");
    }
    const deser = deserialize(challengeString);
    if (deser.state === ERROR) {
      throw new Error(deser.error);
    }
    const own = this.vaultysId.id;
    let mykey: Buffer | undefined;
    let hisKey: Buffer | undefined;
    if (deser.pk1 && sameBytes(deser.pk1, own)) {
      mykey = deser.pk1;
      hisKey = deser.pk2;
    } else if (deser.pk2 && sameBytes(deser.pk2, own)) {
      mykey = deser.pk2;
      hisKey = deser.pk1;
    } else if (deser.state === COMPLETE) {
      throw new Error("Can't link the vaultys id to this challenge");
    }
    this.readOnly = true;
    this.challenge = deser;
    this.mykey = mykey;
    this.hisKey = hisKey;
    return deser.state === COMPLETE;
  }

  getContext() {
    return {
      protocol: this.challenge?.protocol,
      service: this.challenge?.service,
      metadata: this.challenge?.metadata,
    };
  }

  /** Initiator: UNINITIALISED -> INIT */
  createChallenge(protocol: string, service: string, metadata?: Record<string, string>) {
    if (this.readOnly || this.state !== UNINITIALISED) {
      this.state = ERROR;
      throw new Error("Challenger already initialised, can't reset the state");
    }
    if (typeof protocol !== "string" || !protocol || typeof service !== "string" || !service) {
      this.fail("protocol and service must be non empty strings");
    }
    if (metadata !== undefined && !isStringRecord(metadata)) {
      this.fail("metadata must be a map of strings");
    }
    this.mykey = this.vaultysId.id;
    this.challenge = {
      version: HANDSHAKE_VERSION,
      protocol,
      service,
      metadata: metadata ? { pk1: { ...metadata } } : {},
      timestamp: Date.now(),
      pk1: this.mykey,
      nonce: randomBytes(NONCE_PART_LENGTH),
      state: INIT,
    } as ChallengeType;
    this.state = INIT;
  }

  getCertificate() {
    if (!this.challenge) return Buffer.from([]);
    return serialize(this.challenge) || Buffer.from([]);
  }

  getUnsignedChallenge() {
    return serializeUnsigned(this.challenge!);
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

  /** Read-only inspection of a certificate (see setChallenge). */
  static async fromString(vaultysId: VaultysId, challengeString: Buffer) {
    const challenger = new Challenger(vaultysId);
    await challenger.setChallenge(challengeString);
    return challenger;
  }

  hasFailed() {
    return this.state == ERROR;
  }

  isComplete() {
    return this.state == COMPLETE;
  }

  /**
   * Stateless responder support: resume a STEP1 session from a STEP1 certificate
   * previously produced (and signed) by this very identity.
   */
  async init(challenge: Buffer | Uint8Array) {
    if (this.readOnly || this.state !== UNINITIALISED) {
      throw new Error("Can't init INITIALISED challenge");
    }
    const tempchallenge = deserialize(challenge);
    if (tempchallenge.state !== STEP1) {
      this.fail("Only a STEP1 challenge produced by this identity can be resumed" + (tempchallenge.error ? ": " + tempchallenge.error : ""));
    }
    if (!sameBytes(tempchallenge.pk2, this.vaultysId.id)) {
      this.fail("challenge is not corresponding to the right id");
    }
    if (sameBytes(tempchallenge.pk1, this.vaultysId.id)) {
      this.fail("Refusing a challenge initiated by this same identity");
    }
    if (!isLive(tempchallenge, this.liveliness)) {
      this.fail("challenge timestamp failed the liveliness");
    }
    this.challenge = tempchallenge;
    this.mykey = tempchallenge.pk2;
    this.hisKey = tempchallenge.pk1;
    this.state = this.challenge.state = STEP1;
  }

  async update(challenge: Buffer | Uint8Array, metadata?: Record<string, string>) {
    if (this.readOnly) {
      throw new Error("This Challenger is read-only (loaded from a certificate)");
    }
    if (this.state === ERROR) {
      throw new Error("Can't update errorneous challenge");
    } else if (this.state === COMPLETE) {
      throw new Error("Can't update COMPLETE challenge");
    }
    const tempchallenge = deserialize(challenge);
    if (tempchallenge.state === ERROR) {
      this.fail(tempchallenge.error || "Can't read the new incoming challenge");
    }

    if (this.state === UNINITIALISED) {
      // Responder: only an INIT can start a session. Receiving a STEP1 or a
      // COMPLETE here is an attack (signing oracle / replay) and is rejected.
      if (tempchallenge.state !== INIT) {
        this.fail(`Unexpected challenge: an UNINITIALISED challenger only accepts an INIT challenge, received state '${tempchallenge.state}'`);
      }
      if (!isLive(tempchallenge, this.liveliness)) {
        this.fail("challenge timestamp failed the liveliness");
      }
      if (tempchallenge.metadata.pk2) {
        this.fail("Metadata is malformed: pk2 is already set");
      }
      const own = this.vaultysId.id;
      if (sameBytes(tempchallenge.pk1, own)) {
        this.fail("Refusing a challenge initiated by this same identity");
      }
      if (metadata !== undefined && !isStringRecord(metadata)) {
        this.fail("metadata must be a map of strings");
      }
      this.challenge = {
        ...tempchallenge,
        metadata: { ...tempchallenge.metadata },
        pk2: own,
        nonce: Buffer.concat([tempchallenge.nonce!, randomBytes(NONCE_PART_LENGTH)]),
      };
      if (metadata) this.challenge.metadata.pk2 = { ...metadata };
      this.mykey = own;
      this.hisKey = tempchallenge.pk1;
      this.challenge.sign2 = await this.vaultysId.signHandshake(this.getUnsignedChallenge());
      this.challenge.state = this.state = STEP1;
      return;
    }

    const current = this.challenge!;
    if (this.state === INIT) {
      // Initiator: INIT + STEP1 -> COMPLETE
      if (tempchallenge.state !== STEP1) {
        this.fail(`The challenge is in an unexpected state. Received state = '${tempchallenge.state}', expected state = '${STEP1}'`);
      }
      if (!isLive(tempchallenge, this.liveliness)) {
        this.fail("challenge timestamp failed the liveliness");
      }
      if (tempchallenge.protocol !== current.protocol || tempchallenge.service !== current.service) {
        this.fail(`The challenge was expecting protocol '${current.protocol}' and service '${current.service}', received '${tempchallenge.protocol}' and '${tempchallenge.service}'`);
      }
      if (tempchallenge.version !== current.version) {
        this.fail("Version has been tampered with");
      }
      if (!sameBytes(tempchallenge.nonce!.subarray(0, NONCE_PART_LENGTH), current.nonce)) {
        this.fail("Nonce has been tampered with");
      }
      if (tempchallenge.timestamp !== current.timestamp) {
        this.fail("Timestamp has been tampered with");
      }
      if (!sameBytes(tempchallenge.pk1, this.mykey)) {
        this.fail("The challenge pk1 has been tampered with");
      }
      if (!sameRecord(tempchallenge.metadata.pk1, current.metadata.pk1)) {
        this.fail("Metadata has been tampered with");
      }
      if (sameBytes(tempchallenge.pk2, this.mykey)) {
        this.fail("Refusing a challenge answered by this same identity");
      }
      // sign2 has been verified by deserialize
      tempchallenge.sign1 = await this.vaultysId.signHandshake(serializeUnsigned(tempchallenge));
      this.challenge = tempchallenge;
      this.hisKey = tempchallenge.pk2;
      this.state = this.challenge.state = COMPLETE;
      return;
    }

    if (this.state === STEP1) {
      // Responder: STEP1 + COMPLETE -> COMPLETE. Everything must be exactly what we signed.
      if (tempchallenge.state !== COMPLETE) {
        this.fail(`The challenge is in an unexpected state. Received state = '${tempchallenge.state}', expected state = '${COMPLETE}'`);
      }
      if (tempchallenge.protocol !== current.protocol || tempchallenge.service !== current.service) {
        this.fail(`The challenge was expecting protocol '${current.protocol}' and service '${current.service}', received '${tempchallenge.protocol}' and '${tempchallenge.service}'`);
      }
      if (tempchallenge.version !== current.version) {
        this.fail("Version has been tampered with");
      }
      if (!sameBytes(tempchallenge.nonce, current.nonce)) {
        this.fail("Nonce has been tampered with");
      }
      if (tempchallenge.timestamp !== current.timestamp) {
        this.fail("Timestamp has been tampered with");
      }
      if (!sameBytes(tempchallenge.pk1, current.pk1)) {
        this.fail("The challenge pk1 has been tampered with");
      }
      if (!sameBytes(tempchallenge.pk2, this.mykey) || !sameBytes(tempchallenge.pk2, current.pk2)) {
        this.fail("The challenge pk2 has been tampered with");
      }
      if (!sameRecord(tempchallenge.metadata.pk1, current.metadata.pk1) || !sameRecord(tempchallenge.metadata.pk2, current.metadata.pk2)) {
        this.fail("Metadata has been tampered with");
      }
      if (!sameBytes(tempchallenge.sign2, current.sign2)) {
        this.fail("The challenge sign2 has been tampered with");
      }
      // sign1 has been verified by deserialize
      // INFO: no need for liveliness check since the whole certificate is complete
      this.challenge = tempchallenge;
      this.state = this.challenge.state = COMPLETE;
      return;
    }

    this.fail(`The challenge is in an unexpected state. Received state = '${tempchallenge.state}', current state = '${this.state}'`);
  }
}
