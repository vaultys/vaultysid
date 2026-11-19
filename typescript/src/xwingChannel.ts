// X-Wing secure channel and bound handshake. Specification: rfc/SECURE-CHANNEL.md.
//
//   M1 (I -> R) = 0x01 || 0x01 || ek (1216)       ephemeral X-Wing key pair of the initiator
//   M2 (R -> I) = 0x01 || 0x01 || ct (1120)
//   th    = SHA-256(lp("vaultysid/xwing-channel/v1") || lp(M1) || lp(M2))
//   prk   = HKDF-Extract(salt = th, ikm = ss)
//   k_i2r = HKDF-Expand(prk, "vaultysid/xwing-channel/v1/i2r", 32)
//   k_r2i = HKDF-Expand(prk, "vaultysid/xwing-channel/v1/r2i", 32)
//   record = 0x01 || 0x01 || u64be(seq)
//            || XChaCha20-Poly1305(k_dir, nonce = 0^16 || u64be(seq), m, aad = 0x01 || 0x01 || u64be(seq))
//   binding = SHA-256(lp("vaultysid/xwing-binding/v1") || th)

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { expand, extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ml_kem768_x25519 } from "@noble/post-quantum/hybrid.js";
import { Buffer } from "buffer/";
import Challenger, { CHALLENGE_STATE } from "./Challenger";
import { timestampedKey } from "./IdManager";
import type IdManager from "./IdManager";
import type { Channel } from "./MemoryChannel";
import VaultysId from "./VaultysId";
import { randomBytes } from "./crypto";
import { isCanonicalServiceId, type ServiceIdOptions } from "./serviceIdentity";

export const CHANNEL_LABEL = "vaultysid/xwing-channel/v1";
export const CHANNEL_LABEL_I2R = "vaultysid/xwing-channel/v1/i2r";
export const CHANNEL_LABEL_R2I = "vaultysid/xwing-channel/v1/r2i";
export const BINDING_LABEL = "vaultysid/xwing-binding/v1";
/** Handshake metadata key that carries the channel binding (base64 of 32 bytes). */
export const BINDING_METADATA_KEY = "vaultys.channel-binding";
/** Handshake metadata key that carries the canonical service id. */
export const SERVICE_METADATA_KEY = "vaultys.service";

export const XWING = { publicKeyLength: 1216, seedLength: 32, cipherTextLength: 1120, sharedSecretLength: 32, encapsulationRandomnessLength: 64 } as const;
const HEADER = Uint8Array.of(0x01, 0x01);
const HEADER_LENGTH = HEADER.length;
const SEQ_LENGTH = 8;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;
export const CHANNEL_M1_LENGTH = HEADER_LENGTH + XWING.publicKeyLength;
export const CHANNEL_M2_LENGTH = HEADER_LENGTH + XWING.cipherTextLength;
/** Bytes a record adds to its plaintext: header, sequence number, Poly1305 tag. */
export const CHANNEL_RECORD_OVERHEAD = HEADER_LENGTH + SEQ_LENGTH + TAG_LENGTH;
export const DEFAULT_RECEIVE_TIMEOUT_MS = 30_000;
export const MAX_RECEIVE_TIMEOUT_MS = 600_000;
const MAX_SEQ = Number.MAX_SAFE_INTEGER;

const PROTOCOL = "p2p";
const SERVICE = "auth";

export type ChannelErrorCode = "INVALID_ARGUMENT" | "INVALID_FORMAT" | "INVALID_KEY" | "INVALID_SEQUENCE" | "INVALID_SERVICE_ID" | "AUTH_FAILED" | "CHANNEL_CLOSED" | "TIMEOUT" | "BINDING_MISMATCH" | "SERVICE_MISMATCH" | "PEER_MISMATCH" | "HANDSHAKE_FAILED";

export class ChannelError extends Error {
  readonly code: ChannelErrorCode;
  constructor(code: ChannelErrorCode) {
    super(`xwing channel: ${code}`);
    this.name = "ChannelError";
    this.code = code;
  }
}

export const isChannelError = (error: unknown, code?: ChannelErrorCode): error is ChannelError => error instanceof ChannelError && (code === undefined || error.code === code);

type RandomSource = (length: number) => Uint8Array;
const cryptoRandom: RandomSource = (length) => Uint8Array.from(randomBytes(length));

const utf8 = (s: string) => new TextEncoder().encode(s);
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}
function lp(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}
function u64be(n: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), false);
  return out;
}
function readU64be(bytes: Uint8Array, offset: number): number {
  const value = new DataView(bytes.buffer, bytes.byteOffset + offset, 8).getBigUint64(0, false);
  if (value > BigInt(MAX_SEQ)) throw new ChannelError("INVALID_SEQUENCE");
  return Number(value);
}
const hasHeader = (bytes: Uint8Array) => bytes.length >= HEADER_LENGTH && bytes[0] === HEADER[0] && bytes[1] === HEADER[1];
const isAllZero = (bytes: Uint8Array) => bytes.every((b) => b === 0);
function wipe(...buffers: (Uint8Array | undefined)[]) {
  for (const b of buffers) b?.fill(0);
}
function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export const isValidTimeout = (ms: unknown): ms is number => typeof ms === "number" && Number.isSafeInteger(ms) && ms >= 1 && ms <= MAX_RECEIVE_TIMEOUT_MS;

/** Waits for `promise` at most `ms` milliseconds, then rejects with TIMEOUT. The caller closes the channel. */
function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new ChannelError("TIMEOUT")), ms);
  });
  return Promise.race([promise, expired]).finally(() => clearTimeout(timer));
}

/* ---------------------------------------------------------------- X-Wing */

/** X-Wing key pair from a 32-byte seed (refuses a zero seed). */
export function xwingKeyPairFromSeed(seed: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array } {
  if (!(seed instanceof Uint8Array) || seed.length !== XWING.seedLength || isAllZero(seed)) throw new ChannelError("INVALID_KEY");
  const { publicKey, secretKey } = ml_kem768_x25519.keygen(seed);
  return { publicKey, secretKey };
}

/** Encapsulation with explicit 64-byte randomness. Refuses a bad public key or a zero shared secret. */
export function xwingEncapsulateWith(publicKey: Uint8Array, randomness: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array } {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== XWING.publicKeyLength) throw new ChannelError("INVALID_KEY");
  if (randomness.length !== XWING.encapsulationRandomnessLength) throw new ChannelError("INVALID_ARGUMENT");
  let result: { cipherText: Uint8Array; sharedSecret: Uint8Array };
  try {
    result = ml_kem768_x25519.encapsulate(publicKey, randomness);
  } catch {
    throw new ChannelError("INVALID_KEY");
  }
  if (isAllZero(result.sharedSecret)) {
    wipe(result.sharedSecret);
    throw new ChannelError("INVALID_KEY");
  }
  return result;
}

/** Decapsulation. A tampered ML-KEM ciphertext does not throw (implicit rejection): it gives another secret. */
export function xwingDecapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array {
  if (secretKey.length !== XWING.seedLength) throw new ChannelError("INVALID_KEY");
  if (cipherText.length !== XWING.cipherTextLength) throw new ChannelError("INVALID_FORMAT");
  let sharedSecret: Uint8Array;
  try {
    sharedSecret = ml_kem768_x25519.decapsulate(cipherText, secretKey);
  } catch {
    throw new ChannelError("INVALID_FORMAT");
  }
  if (isAllZero(sharedSecret)) {
    wipe(sharedSecret);
    throw new ChannelError("INVALID_FORMAT");
  }
  return sharedSecret;
}

/* ---------------------------------------------------------------- channel */

export interface ChannelKeys {
  /** Transcript hash (32 bytes, public). */
  readonly th: Uint8Array;
  readonly i2r: Uint8Array;
  readonly r2i: Uint8Array;
  readonly binding: Uint8Array;
}

/** Directional keys and binding value of a session (erases prk, not the shared secret). */
export function deriveChannelKeys(sharedSecret: Uint8Array, m1: Uint8Array, m2: Uint8Array): ChannelKeys {
  const th = sha256(concat(lp(utf8(CHANNEL_LABEL)), lp(m1), lp(m2)));
  const prk = extract(sha256, sharedSecret, th);
  try {
    return {
      th,
      i2r: expand(sha256, prk, utf8(CHANNEL_LABEL_I2R), KEY_LENGTH),
      r2i: expand(sha256, prk, utf8(CHANNEL_LABEL_R2I), KEY_LENGTH),
      binding: sha256(concat(lp(utf8(BINDING_LABEL)), th)),
    };
  } finally {
    wipe(prk);
  }
}

const recordNonce = (seqBytes: Uint8Array) => concat(new Uint8Array(16), seqBytes);

/** Encrypts one record (exported for test vectors). */
export function encryptRecord(key: Uint8Array, seq: number, message: Uint8Array): Uint8Array {
  const seqBytes = u64be(seq);
  const aad = concat(HEADER, seqBytes);
  return concat(aad, xchacha20poly1305(key, recordNonce(seqBytes), aad).encrypt(message));
}

/** An established X-Wing channel: an encrypted, ordered VaultysID `Channel`. */
export interface XWingChannel extends Channel {
  /** Public binding value (32 bytes) derived from the transcript. */
  readonly binding: Uint8Array;
  /** Transcript hash (32 bytes, public): identical on both sides of one session, different for every session. */
  readonly transcriptHash: Uint8Array;
  readonly role: "initiator" | "responder";
}

class XWingSession implements XWingChannel {
  readonly binding: Uint8Array;
  readonly transcriptHash: Uint8Array;
  readonly role: "initiator" | "responder";
  readonly #channel: Channel;
  readonly #sendKey: Uint8Array;
  readonly #receiveKey: Uint8Array;
  #sendSeq = 0;
  #receiveSeq = 0;
  #closed = false;

  constructor(channel: Channel, role: "initiator" | "responder", keys: ChannelKeys) {
    this.#channel = channel;
    this.role = role;
    this.binding = Uint8Array.from(keys.binding);
    this.transcriptHash = Uint8Array.from(keys.th);
    this.#sendKey = role === "initiator" ? keys.i2r : keys.r2i;
    this.#receiveKey = role === "initiator" ? keys.r2i : keys.i2r;
  }

  start(): Promise<void> {
    return this.#channel.start();
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    wipe(this.#sendKey, this.#receiveKey);
    await this.#channel.close();
  }

  /** Encrypts and sends. Sequence numbers are assigned synchronously, in call order. */
  send(data: Buffer | Uint8Array): Promise<void> {
    if (this.#closed) return Promise.reject(new ChannelError("CHANNEL_CLOSED"));
    if (!(data instanceof Uint8Array)) return Promise.reject(new ChannelError("INVALID_ARGUMENT"));
    if (this.#sendSeq > MAX_SEQ) return Promise.reject(new ChannelError("INVALID_SEQUENCE"));
    const seq = this.#sendSeq++;
    return this.#channel.send(Buffer.from(encryptRecord(this.#sendKey, seq, data)));
  }

  /** Receives and decrypts. Any failure closes the channel. */
  async receive(): Promise<Buffer> {
    if (this.#closed) throw new ChannelError("CHANNEL_CLOSED");
    const raw = await this.#channel.receive();
    if (this.#closed) throw new ChannelError("CHANNEL_CLOSED");
    const record = Uint8Array.from(raw);
    if (record.length === 0) return this.#fail("CHANNEL_CLOSED");
    if (record.length < CHANNEL_RECORD_OVERHEAD || !hasHeader(record)) return this.#fail("INVALID_FORMAT");
    let seq: number;
    try {
      seq = readU64be(record, HEADER_LENGTH);
    } catch {
      return this.#fail("INVALID_SEQUENCE");
    }
    if (seq !== this.#receiveSeq) return this.#fail("INVALID_SEQUENCE");
    const aad = record.subarray(0, HEADER_LENGTH + SEQ_LENGTH);
    let plaintext: Uint8Array;
    try {
      plaintext = xchacha20poly1305(this.#receiveKey, recordNonce(aad.subarray(HEADER_LENGTH)), aad).decrypt(record.subarray(HEADER_LENGTH + SEQ_LENGTH));
    } catch {
      return this.#fail("AUTH_FAILED");
    }
    this.#receiveSeq++;
    return Buffer.from(plaintext);
  }

  onConnected(callback: () => void): void {
    this.#channel.onConnected(callback);
  }

  getConnectionString(): string {
    return this.#channel.getConnectionString();
  }

  /** A session cannot be rebuilt from a connection string. */
  fromConnectionString(): Channel | null {
    return null;
  }

  async #fail(code: ChannelErrorCode): Promise<never> {
    try {
      await this.close();
    } catch {
      // closing the transport must not hide the error
    }
    throw new ChannelError(code);
  }
}

export interface XWingChannelOptions {
  /** How long to wait for the peer's establishment message, in ms (default 30 000). */
  timeoutMs?: number;
}

function checkTimeout(options: unknown): number {
  if (typeof options !== "object" || options === null) throw new ChannelError("INVALID_ARGUMENT");
  const timeoutMs = (options as { timeoutMs?: unknown }).timeoutMs ?? DEFAULT_RECEIVE_TIMEOUT_MS;
  if (!isValidTimeout(timeoutMs)) throw new ChannelError("INVALID_ARGUMENT");
  return timeoutMs;
}

async function closeQuietly(channel: Channel) {
  try {
    await channel.close();
  } catch {
    // already closed
  }
}

async function receiveEstablishment(channel: Channel, timeoutMs: number): Promise<Uint8Array> {
  try {
    return Uint8Array.from(await withTimeout(channel.receive(), timeoutMs));
  } catch (error) {
    await closeQuietly(channel);
    throw isChannelError(error) ? error : new ChannelError("CHANNEL_CLOSED");
  }
}

async function failEstablishment(channel: Channel, code: ChannelErrorCode): Promise<never> {
  await closeQuietly(channel);
  throw new ChannelError(code);
}

/** Initiator side with an explicit random source (for test vectors only). */
export async function initiateXWingChannelWith(channel: Channel, rng: RandomSource, options: XWingChannelOptions = {}): Promise<XWingChannel> {
  const timeoutMs = checkTimeout(options);
  const seed = rng(XWING.seedLength);
  let secretKey: Uint8Array | undefined;
  let sharedSecret: Uint8Array | undefined;
  try {
    const keyPair = xwingKeyPairFromSeed(seed);
    secretKey = keyPair.secretKey;
    const m1 = concat(HEADER, keyPair.publicKey);
    await channel.send(Buffer.from(m1));
    const m2 = await receiveEstablishment(channel, timeoutMs);
    if (m2.length !== CHANNEL_M2_LENGTH || !hasHeader(m2)) return await failEstablishment(channel, "INVALID_FORMAT");
    try {
      sharedSecret = xwingDecapsulate(m2.subarray(HEADER_LENGTH), secretKey);
    } catch {
      return await failEstablishment(channel, "INVALID_FORMAT");
    }
    return new XWingSession(channel, "initiator", deriveChannelKeys(sharedSecret, m1, m2));
  } finally {
    wipe(seed, secretKey, sharedSecret);
  }
}

/** Responder side with an explicit random source (for test vectors only). */
export async function acceptXWingChannelWith(channel: Channel, rng: RandomSource, options: XWingChannelOptions = {}): Promise<XWingChannel> {
  const timeoutMs = checkTimeout(options);
  let sharedSecret: Uint8Array | undefined;
  let randomness: Uint8Array | undefined;
  try {
    const m1 = await receiveEstablishment(channel, timeoutMs);
    if (m1.length !== CHANNEL_M1_LENGTH || !hasHeader(m1)) return await failEstablishment(channel, "INVALID_FORMAT");
    let cipherText: Uint8Array;
    randomness = rng(XWING.encapsulationRandomnessLength);
    try {
      ({ cipherText, sharedSecret } = xwingEncapsulateWith(m1.subarray(HEADER_LENGTH), randomness));
    } catch {
      return await failEstablishment(channel, "INVALID_KEY");
    }
    const m2 = concat(HEADER, cipherText);
    await channel.send(Buffer.from(m2));
    return new XWingSession(channel, "responder", deriveChannelKeys(sharedSecret, m1, m2));
  } finally {
    wipe(sharedSecret, randomness);
  }
}

/**
 * Establishes an X-Wing channel as initiator (ephemeral key pair, erased after use).
 * WARNING: a channel alone is NOT authenticated; anyone can answer M1. Use connectOverXWing for an
 * authenticated session.
 */
export function initiateXWingChannel(channel: Channel, options: XWingChannelOptions = {}): Promise<XWingChannel> {
  return initiateXWingChannelWith(channel, cryptoRandom, options);
}

/** Establishes an X-Wing channel as responder. Not authenticated by itself: see acceptOverXWing. */
export function acceptXWingChannel(channel: Channel, options: XWingChannelOptions = {}): Promise<XWingChannel> {
  return acceptXWingChannelWith(channel, cryptoRandom, options);
}

/* ---------------------------------------------------------------- bound handshake */

/** Public fingerprint of an identity: SHA-256 of its version-1 serialized id. */
export function identityFingerprint(identity: VaultysId): Uint8Array {
  try {
    const copy = VaultysId.fromId(Buffer.from(Uint8Array.from(identity.id)));
    copy.toVersion(1);
    return sha256(Uint8Array.from(copy.id));
  } catch {
    throw new ChannelError("INVALID_KEY");
  }
}

/**
 * Storage key of a certificate in `wot`: `<timestamp>-<hex SHA-256(certificate)>`, as IdManager now does. Two
 * certificates of the same millisecond no longer overwrite each other, and keys still sort by date.
 */
export const certificateKey = timestampedKey;

export interface ConnectOverXWingOptions extends ServiceIdOptions {
  /**
   * Expected identity of the responder (an anchor the service publishes, or the identity pinned at the first
   * connection). Compared with the identity that signs STEP1 BEFORE signing COMPLETE; mismatch: PEER_MISMATCH.
   * Without it, the caller alone must check the responder's identity.
   */
  expectedPeer?: VaultysId;
  /** How long to wait for each message, in ms (default 30 000). */
  timeoutMs?: number;
}

export interface AcceptOverXWingOptions extends ServiceIdOptions {
  timeoutMs?: number;
}

export interface XWingHandshakeResult {
  /** The peer's identity, with the handshake certificate. */
  readonly contact: VaultysId;
  /** The channel, now authenticated by the handshake. */
  readonly channel: XWingChannel;
}

function checkHandshakeArguments(serviceId: string, metadata: Record<string, string>, options: ServiceIdOptions): void {
  if (typeof options !== "object" || options === null) throw new ChannelError("INVALID_ARGUMENT");
  // the service id must already be canonical: never normalized silently here
  if (!isCanonicalServiceId(serviceId, options)) throw new ChannelError("INVALID_SERVICE_ID");
  if (typeof metadata !== "object" || metadata === null || Array.isArray(metadata)) throw new ChannelError("INVALID_ARGUMENT");
  for (const [key, value] of Object.entries(metadata)) {
    if (typeof value !== "string" || key === BINDING_METADATA_KEY || key === SERVICE_METADATA_KEY) throw new ChannelError("INVALID_ARGUMENT");
  }
}

async function abort(channel: XWingChannel, code: ChannelErrorCode): Promise<never> {
  try {
    // VaultysID convention: a single 0 byte tells the peer we give up
    await channel.send(Buffer.from([0]));
  } catch {
    // the channel may already be closed
  }
  await closeQuietly(channel);
  throw new ChannelError(code);
}

async function receiveOrAbort(channel: XWingChannel, timeoutMs: number): Promise<Uint8Array> {
  try {
    return Uint8Array.from(await withTimeout(channel.receive(), timeoutMs));
  } catch (error) {
    if (isChannelError(error, "TIMEOUT")) await closeQuietly(channel);
    throw isChannelError(error) ? error : new ChannelError("HANDSHAKE_FAILED");
  }
}

function save(idManager: IdManager, challenger: Challenger): VaultysId {
  const contact = challenger.getContactId();
  const certificate = challenger.getCertificate();
  idManager.store.substore("wot").set(certificateKey(Uint8Array.from(certificate)), certificate);
  idManager.saveContact(contact);
  return contact;
}

/**
 * Initiator: establishes an X-Wing channel over `channel`, then runs the VaultysID handshake (as askContact) inside
 * it, bound to the channel and to `serviceId`. Both sides put the channel binding and the service id in their signed
 * metadata, and each checks the other's BEFORE signing. The contact is stored only once the handshake is complete.
 *
 * `serviceId` must be canonical (output of canonicalServiceId); both sides must pass the same string.
 */
export async function connectOverXWing(idManager: IdManager, channel: Channel, serviceId: string, metadata: Record<string, string> = {}, options: ConnectOverXWingOptions = {}): Promise<XWingHandshakeResult> {
  checkHandshakeArguments(serviceId, metadata, options);
  const timeoutMs = checkTimeout(options);
  let expected: Uint8Array | undefined;
  if (options.expectedPeer !== undefined) {
    try {
      expected = identityFingerprint(options.expectedPeer);
    } catch {
      throw new ChannelError("INVALID_ARGUMENT");
    }
  }
  const session = await initiateXWingChannel(channel, { timeoutMs });
  const binding = Buffer.from(session.binding).toString("base64");
  const challenger = new Challenger(idManager.vaultysId);
  try {
    challenger.createChallenge(PROTOCOL, SERVICE, { ...metadata, [BINDING_METADATA_KEY]: binding, [SERVICE_METADATA_KEY]: serviceId });
    await session.send(challenger.getCertificate());
  } catch {
    return abort(session, "HANDSHAKE_FAILED");
  }

  const step1 = await receiveOrAbort(session, timeoutMs);
  const parsed = Challenger.deserializeCertificate(Buffer.from(step1));
  if (parsed.state !== CHALLENGE_STATE.STEP1) return abort(session, "HANDSHAKE_FAILED");
  // checked BEFORE signing: the responder must have signed OUR transcript and the SAME service
  if (parsed.metadata?.pk2?.[BINDING_METADATA_KEY] !== binding) return abort(session, "BINDING_MISMATCH");
  if (parsed.metadata.pk2[SERVICE_METADATA_KEY] !== serviceId) return abort(session, "SERVICE_MISMATCH");
  try {
    await challenger.update(Buffer.from(step1));
  } catch {
    return abort(session, "HANDSHAKE_FAILED");
  }
  if (!challenger.isComplete()) return abort(session, "HANDSHAKE_FAILED");
  if (expected !== undefined) {
    let peer: Uint8Array | undefined;
    try {
      peer = identityFingerprint(challenger.getContactId());
    } catch {
      peer = undefined;
    }
    if (peer === undefined || !equalBytes(peer, expected)) return abort(session, "PEER_MISMATCH");
  }
  try {
    await session.send(challenger.getCertificate());
    return { contact: save(idManager, challenger), channel: session };
  } catch {
    return abort(session, "HANDSHAKE_FAILED");
  }
}

/** Responder: accepts an X-Wing channel, then the VaultysID handshake (as acceptContact), bound to it and to `serviceId`. */
export async function acceptOverXWing(idManager: IdManager, channel: Channel, serviceId: string, metadata: Record<string, string> = {}, options: AcceptOverXWingOptions = {}): Promise<XWingHandshakeResult> {
  checkHandshakeArguments(serviceId, metadata, options);
  const timeoutMs = checkTimeout(options);
  const session = await acceptXWingChannel(channel, { timeoutMs });
  const binding = Buffer.from(session.binding).toString("base64");

  const init = await receiveOrAbort(session, timeoutMs);
  const parsed = Challenger.deserializeCertificate(Buffer.from(init));
  if (parsed.state !== CHALLENGE_STATE.INIT || parsed.protocol !== PROTOCOL || parsed.service !== SERVICE) return abort(session, "HANDSHAKE_FAILED");
  // checked BEFORE signing STEP1
  if (parsed.metadata?.pk1?.[BINDING_METADATA_KEY] !== binding) return abort(session, "BINDING_MISMATCH");
  if (parsed.metadata.pk1[SERVICE_METADATA_KEY] !== serviceId) return abort(session, "SERVICE_MISMATCH");
  const challenger = new Challenger(idManager.vaultysId);
  try {
    await challenger.update(Buffer.from(init), { ...metadata, [BINDING_METADATA_KEY]: binding, [SERVICE_METADATA_KEY]: serviceId });
    await session.send(challenger.getCertificate());
  } catch {
    return abort(session, "HANDSHAKE_FAILED");
  }

  const complete = await receiveOrAbort(session, timeoutMs);
  try {
    // checks sign1 and that everything we signed (both bindings included) is unchanged
    await challenger.update(Buffer.from(complete));
  } catch {
    return abort(session, "HANDSHAKE_FAILED");
  }
  if (!challenger.isComplete()) return abort(session, "HANDSHAKE_FAILED");
  try {
    return { contact: save(idManager, challenger), channel: session };
  } catch {
    return abort(session, "HANDSHAKE_FAILED");
  }
}
