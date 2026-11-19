// Service anchors: a service publishes its VaultysID identity under its own web origin, so that a client can tell,
// before the handshake completes, that it is talking to that service. Specification: rfc/SERVICE-IDENTITIES.md §8.
//
//   anchor = 0x01 || 0x01 || lp(serviceId) || lp(id) || u16be(len(sig)) || sig
//   sig    = identity.sign(lp("vaultysid/service-anchor/v1") || 0x01 || 0x01 || lp(serviceId) || lp(id))   (VAULTYS_RAW)
//
// served at `<serviceId>/.well-known/vaultysid-service`, `serviceId` canonical, `id` the version-1 serialized id.

import { Buffer } from "buffer/";
import VaultysId from "./VaultysId";
import { canonicalServiceId, isCanonicalServiceId } from "./serviceIdentity";

export const SERVICE_ANCHOR_LABEL = "vaultysid/service-anchor/v1";
export const SERVICE_ANCHOR_PATH = "/.well-known/vaultysid-service";
const HEADER = Uint8Array.of(0x01, 0x01);
const MAX_SERVICE_ID = 300;
const MAX_ID = 8192;

const utf8 = (s: string) => new TextEncoder().encode(s);
function lp(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}
function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/** Public version-1 copy of an identity (one serialization per key). */
function publicCopy(identity: VaultysId): VaultysId {
  const copy = VaultysId.fromId(Buffer.from(Uint8Array.from(identity.id)));
  copy.toVersion(1);
  return copy;
}

/** Bytes signed by the service. */
export function serviceAnchorSignedData(serviceId: string, id: Uint8Array): Uint8Array {
  return concat(lp(utf8(SERVICE_ANCHOR_LABEL)), HEADER, lp(utf8(serviceId)), lp(id));
}

/** URL where the anchor of a web origin is served. Throws for an `app:` id, which has no origin. */
export function serviceAnchorUrl(serviceId: string): string {
  const canonical = canonicalServiceId(serviceId);
  if (canonical.startsWith("app:")) throw new Error("an app: service id has no web origin to publish an anchor");
  return `${canonical}${SERVICE_ANCHOR_PATH}`;
}

/** Anchor of `identity` for the canonical `serviceId`. The identity must be able to sign. */
export async function createServiceAnchor(identity: VaultysId, serviceId: string): Promise<Uint8Array> {
  if (!isCanonicalServiceId(serviceId)) throw new Error("invalid service id");
  const id = Uint8Array.from(publicCopy(identity).id);
  const signature = await identity.sign(Buffer.from(serviceAnchorSignedData(serviceId, id)));
  if (!signature || signature.length === 0 || signature.length > 0xffff) throw new Error("the identity cannot sign the anchor");
  const length = new Uint8Array(2);
  new DataView(length.buffer).setUint16(0, signature.length, false);
  return concat(HEADER, lp(utf8(serviceId)), lp(id), length, Uint8Array.from(signature));
}

function readLp(bytes: Uint8Array, offset: number, max: number): { value: Uint8Array; next: number } | null {
  if (offset + 4 > bytes.length) return null;
  const length = new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, false);
  if (length === 0 || length > max || offset + 4 + length > bytes.length) return null;
  return { value: bytes.slice(offset + 4, offset + 4 + length), next: offset + 4 + length };
}

/**
 * Verifies an anchor fetched from the canonical origin `serviceId` and returns the service's public identity, or
 * `null` on any defect: format, an anchor made for another origin, a non-canonical id, a bad signature. Never throws.
 */
export function verifyServiceAnchor(anchor: Uint8Array, serviceId: string): VaultysId | null {
  try {
    if (!(anchor instanceof Uint8Array) || anchor.length < HEADER.length || anchor[0] !== HEADER[0] || anchor[1] !== HEADER[1]) return null;
    const origin = readLp(anchor, HEADER.length, MAX_SERVICE_ID);
    if (origin === null) return null;
    const id = readLp(anchor, origin.next, MAX_ID);
    if (id === null || id.next + 2 > anchor.length) return null;
    const sigLength = new DataView(anchor.buffer, anchor.byteOffset + id.next, 2).getUint16(0, false);
    const sigStart = id.next + 2;
    if (sigLength === 0 || sigStart + sigLength !== anchor.length) return null;
    const claimed = new TextDecoder("utf-8", { fatal: true }).decode(origin.value);
    // made for THIS origin, not copied from another one
    if (claimed !== serviceId || !isCanonicalServiceId(claimed)) return null;
    const identity = publicCopy(VaultysId.fromId(Buffer.from(id.value)));
    if (!equalBytes(Uint8Array.from(identity.id), id.value)) return null;
    const signature = Buffer.from(anchor.subarray(sigStart));
    return identity.verify(Buffer.from(serviceAnchorSignedData(serviceId, id.value)), signature) ? identity : null;
  } catch {
    return null;
  }
}

export type AnchorPinResult = "pinned" | "same" | "changed";

/**
 * Trust on first use for anchors. `pins` maps a canonical service id to the DID first seen for it. Returns "pinned"
 * the first time (and records it), "same" when the anchor still names that identity, "changed" otherwise. A
 * "changed" result MUST stop the connection and warn the user: the origin's web server may have been compromised.
 */
export function checkAnchorPin(pins: Map<string, string> | { get(key: string): unknown; set(key: string, value: unknown): void }, serviceId: string, identity: VaultysId): AnchorPinResult {
  const did = publicCopy(identity).did;
  const known = pins.get(serviceId);
  if (known === undefined || known === null) {
    pins.set(serviceId, did);
    return "pinned";
  }
  return known === did ? "same" : "changed";
}
