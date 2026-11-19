// Service identities: one unlinkable VaultysId per service, derived from a master secret.
// Specification: rfc/SERVICE-IDENTITIES.md.

import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Buffer } from "buffer/";
import VaultysId from "./VaultysId";
import { secureErase } from "./crypto";

export type ServiceAlgorithm = "ed25519" | "dilithium" | "dilithium_ed25519";
export type ServiceRole = "machine" | "person" | "organization";

export interface ServiceIdOptions {
  /**
   * Accept `localhost`, `*.localhost`, IPv4 and IPv6 literals as web hosts, and the `http` scheme.
   * For development only (RFC §3.2). Default: false.
   */
  allowDevelopmentHosts?: boolean;
}

export interface ServiceIdentityOptions extends ServiceIdOptions {
  /** Signature algorithm of the derived identity. Default: "ed25519". */
  alg?: ServiceAlgorithm;
  /** Role of the derived identity. Default: "person". */
  role?: ServiceRole;
  /** Derive a post-quantum identity type (0x10 | role, rfc/PQ-ENCRYPTION.md). Requires a dilithium algorithm. Default: false. */
  postQuantum?: boolean;
}

/** Salt of the HKDF that derives a service identity (RFC §4). */
export const SERVICE_IDENTITY_SALT = "vaultysid/service-identity/v1";
/** Length of the master secret, in bytes. */
export const MASTER_SECRET_LENGTH = 32;
/** Length of the entropy handed to VaultysId.fromEntropy, as in generatePerson(). */
export const SERVICE_ENTROPY_LENGTH = 32;
/** Longest accepted service id input. */
export const MAX_SERVICE_ID_INPUT_LENGTH = 300;

const SERVICE_ALGORITHMS: readonly ServiceAlgorithm[] = ["ed25519", "dilithium", "dilithium_ed25519"];
const ROLES: Readonly<Record<ServiceRole, number>> = { machine: 0, person: 1, organization: 2 };
const TYPE_PQ_FLAG = 0x10;
const DERIVATION_VERSION = "v1";

const MAX_NAME_LENGTH = 253;
const PRINTABLE_ASCII = /^[\x21-\x7e]+$/;
const FORBIDDEN = /[%\\@?#]/;
const WEB = /^(https?):\/\/([^/:[\]]*)(?::([^/]*))?(\/?)$/i;
const WEB_IPV6 = /^(https?):\/\/(\[[0-9a-f:.]+\])(?::([^/]*))?(\/?)$/i;
const APP = /^app:(.*)$/;
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const IPV4 = /^(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3}$/;
const PORT = /^[1-9][0-9]{0,4}$/;
const DEFAULT_PORTS: Readonly<Record<string, string>> = { http: "80", https: "443" };

function invalidServiceId(): never {
  throw new Error("invalid service id");
}

/** Lowercase DNS labels; `??--` is reserved except `xn--` (RFC 5891 §4.2.3.1). */
function isDnsName(name: string): boolean {
  if (name.length === 0 || name.length > MAX_NAME_LENGTH) return false;
  const labels = name.split(".");
  if (labels.length < 2) return false;
  for (const label of labels) {
    if (!LABEL.test(label)) return false;
    if (label.length >= 4 && label.slice(2, 4) === "--" && !label.startsWith("xn--")) return false;
  }
  return true;
}

/** True if a WHATWG URL parser would read the host as an IPv4 address (numeric or `0x…` last label). */
function endsInNumber(host: string): boolean {
  const last = host.slice(host.lastIndexOf(".") + 1);
  return /^[0-9]+$/.test(last) || /^0x[0-9a-f]*$/.test(last);
}

function canonicalPort(scheme: string, port: string | undefined): string {
  if (port === undefined) return "";
  if (!PORT.test(port) || Number(port) > 65535) invalidServiceId();
  return port === DEFAULT_PORTS[scheme] ? "" : `:${port}`;
}

/** The grammar and the WHATWG parser must agree on the exact origin. */
function crossCheck(input: string, origin: string): void {
  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    return invalidServiceId();
  }
  if (parsed.origin !== origin || (parsed.pathname !== "/" && parsed.pathname !== "")) invalidServiceId();
}

function canonicalWebOrigin(scheme: string, rawHost: string, port: string | undefined, input: string, dev: boolean): string {
  const host = rawHost.toLowerCase();
  let developmentHost: boolean;
  if (IPV4.test(host) || host === "localhost") {
    developmentHost = true;
  } else if (isDnsName(host) && !endsInNumber(host)) {
    developmentHost = host.endsWith(".localhost");
  } else {
    return invalidServiceId();
  }
  if ((developmentHost || scheme === "http") && !dev) invalidServiceId();
  const origin = `${scheme}://${host}${canonicalPort(scheme, port)}`;
  crossCheck(input, origin);
  return origin;
}

function canonicalIpv6Origin(match: RegExpExecArray, input: string, dev: boolean): string {
  if (!dev) invalidServiceId();
  const scheme = (match[1] ?? "").toLowerCase();
  const host = (match[2] ?? "").toLowerCase();
  let parsedHost: string;
  try {
    parsedHost = new URL(`${scheme}://${host}`).host;
  } catch {
    return invalidServiceId();
  }
  // a non-canonical form such as [0:0::1] is refused, never normalized
  if (parsedHost !== host) invalidServiceId();
  const origin = `${scheme}://${host}${canonicalPort(scheme, match[3])}`;
  crossCheck(input, origin);
  return origin;
}

/**
 * Canonical identifier of a service (RFC §3). Accepted forms:
 * - a web origin `https://host[:port]`, optionally followed by `/`; the output equals `URL.origin`;
 * - an application id `app:<reverse-dns>`, in lowercase.
 * Anything else, or anything ambiguous, throws `Error("invalid service id")`. Two spellings of the same
 * service give the same output; nothing is ever "repaired" beyond scheme and host case and the default port.
 */
export function canonicalServiceId(input: string, options: ServiceIdOptions = {}): string {
  if (typeof input !== "string" || input.length === 0 || input.length > MAX_SERVICE_ID_INPUT_LENGTH) invalidServiceId();
  if (!PRINTABLE_ASCII.test(input) || FORBIDDEN.test(input)) invalidServiceId();
  if (typeof options !== "object" || options === null) invalidServiceId();
  const dev = options.allowDevelopmentHosts === true;

  const app = APP.exec(input);
  if (app) {
    if (!isDnsName(app[1] ?? "")) invalidServiceId();
    return input;
  }
  const ipv6 = WEB_IPV6.exec(input);
  if (ipv6) return canonicalIpv6Origin(ipv6, input, dev);
  const web = WEB.exec(input);
  if (!web) return invalidServiceId();
  return canonicalWebOrigin((web[1] ?? "").toLowerCase(), web[2] ?? "", web[3], input, dev);
}

/** True if `serviceId` is already canonical. Never throws. */
export function isCanonicalServiceId(serviceId: unknown, options: ServiceIdOptions = {}): serviceId is string {
  try {
    return typeof serviceId === "string" && canonicalServiceId(serviceId, options) === serviceId;
  } catch {
    return false;
  }
}

function lp(text: string): Uint8Array {
  const bytes = new TextEncoder().encode(text);
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function typeName(role: ServiceRole, postQuantum: boolean): string {
  return postQuantum ? `${role}-pq` : role;
}

function resolveOptions(options: ServiceIdentityOptions) {
  if (typeof options !== "object" || options === null) throw new Error("invalid options");
  const alg = options.alg ?? "ed25519";
  const role = options.role ?? "person";
  const postQuantum = options.postQuantum === true;
  if (!SERVICE_ALGORITHMS.includes(alg)) throw new Error("unsupported algorithm");
  if (!Object.prototype.hasOwnProperty.call(ROLES, role)) throw new Error("unsupported role");
  if (postQuantum && alg === "ed25519") throw new Error("post-quantum identities require a dilithium or dilithium_ed25519 key manager");
  return { alg, role, postQuantum, type: (postQuantum ? TYPE_PQ_FLAG : 0) | ROLES[role] };
}

function checkMasterSecret(masterSecret: Uint8Array): void {
  if (!(masterSecret instanceof Uint8Array) || masterSecret.length !== MASTER_SECRET_LENGTH || masterSecret.every((b) => b === 0)) {
    throw new Error("invalid master secret");
  }
}

/**
 * HKDF info of a service identity (RFC §4): lp("v1") ‖ lp(alg) ‖ lp(type name) ‖ lp(canonical service id).
 * `canonical` must already be canonical.
 */
export function serviceIdentityInfo(alg: ServiceAlgorithm, role: ServiceRole, postQuantum: boolean, canonical: string): Uint8Array {
  return concat([lp(DERIVATION_VERSION), lp(alg), lp(typeName(role, postQuantum)), lp(canonical)]);
}

/**
 * Entropy of a service identity (RFC §4). Secret: the caller must erase it. Exported for test vectors and
 * other implementations; applications should call deriveServiceIdentity.
 */
export function deriveServiceEntropy(masterSecret: Uint8Array, serviceId: string, options: ServiceIdentityOptions = {}): Uint8Array {
  checkMasterSecret(masterSecret);
  const { alg, role, postQuantum } = resolveOptions(options);
  const canonical = canonicalServiceId(serviceId, options);
  const info = serviceIdentityInfo(alg, role, postQuantum, canonical);
  return hkdf(sha256, masterSecret, new TextEncoder().encode(SERVICE_IDENTITY_SALT), info, SERVICE_ENTROPY_LENGTH);
}

/**
 * Derives the VaultysId of `serviceId` from `masterSecret` (RFC §4).
 *
 * - `masterSecret`: 32 random bytes, not all zero, kept secret by the application. It is neither modified nor kept.
 *   It MUST NOT be derived from a value an attacker could compute from public data (RFC §6).
 * - `serviceId`: canonicalized with `canonicalServiceId`; two spellings of the same service give the same identity.
 * - Deterministic: the same master secret, service and options always give the same identity. Two services give
 *   identities with no common value, so they cannot be linked from their public ids.
 */
export async function deriveServiceIdentity(masterSecret: Uint8Array, serviceId: string, options: ServiceIdentityOptions = {}): Promise<VaultysId> {
  const { alg, type } = resolveOptions(options);
  const entropy = deriveServiceEntropy(masterSecret, serviceId, options);
  // fromEntropy keeps a reference to the buffer it receives: it gets its own copy.
  const copy = Buffer.from(entropy);
  secureErase(entropy);
  return VaultysId.fromEntropy(copy, type, alg);
}
