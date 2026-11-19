// Deterministic test vectors for rfc/SERVICE-IDENTITIES.md (§7).
// Run: pnpm test:service:vectors (from typescript/). Writes service-identity-vectors.json next to this file.
//
// `info` and `entropy` are recomputed from the RFC with node:crypto, independently of src/serviceIdentity.ts,
// and the generator stops if the two disagree.

import { createHash, hkdfSync } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalServiceId, deriveServiceEntropy, deriveServiceIdentity, SERVICE_IDENTITY_SALT, type ServiceAlgorithm, type ServiceIdentityOptions, type ServiceRole } from "../../src/serviceIdentity";

type CanonicalCase = { input: string; options: { allowDevelopmentHosts?: boolean }; output: string };

const CANONICAL_INPUTS: Array<[string, boolean]> = [
  ["https://Example.com/", false],
  ["https://example.com", false],
  ["https://example.com:443", false],
  ["HTTPS://EXAMPLE.COM", false],
  ["https://sub.example.com", false],
  ["https://example.com:8443", false],
  ["https://example.com:80", false],
  ["http://example.com", false],
  ["http://example.com", true],
  ["HTTP://Example.COM:80/", true],
  ["http://example.com:80/", false],
  ["http://example.com:80/", true],
  ["http://example.com:8080", false],
  ["https://example.com:0443", false],
  ["https://example.com:", false],
  ["https://example.com:/", false],
  ["https://example.com:65536", false],
  ["https://example.com/login", false],
  ["https://example.com//", false],
  ["https://example.com?q", false],
  ["https://example.com#f", false],
  ["https://user@example.com", false],
  ["https://example.com\\", false],
  ["https://ex%61mple.com", false],
  [" https://example.com", false],
  ["https://example.com.", false],
  ["https://example..com", false],
  ["https://intranet", false],
  ["https://-example.com", false],
  ["https://ab--cd.com", false],
  ["https://exémple.com", false],
  ["https://еxample.com", false],
  ["https://xn--exmple-cva.com", false],
  ["https://XN--XAMPLE-2OF.COM/", false],
  ["https://xn--zz.com", false],
  ["https://example.123", false],
  ["http://localhost:3000", false],
  ["http://localhost:3000", true],
  ["http://app.localhost:5173/", true],
  ["https://127.0.0.1", false],
  ["http://127.0.0.1:3000", true],
  ["http://[::1]:8080", false],
  ["http://[::1]:8080", true],
  ["http://[0:0::1]", true],
  ["https://0x7f.1", true],
  ["https://127.1", true],
  ["app:com.example.myapp", false],
  ["app:Com.x", false],
  ["APP:com.example", false],
  ["app:x", false],
  ["app:com.example.my_app", false],
  ["", false],
  ["example.com", false],
  ["ftp://example.com", false],
  ["did:vaultys:01ab", false],
];

const lp = (s: string) => {
  const b = Buffer.from(s, "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(b.length);
  return Buffer.concat([len, b]);
};

export const testMaster = (name: string) => Uint8Array.from(createHash("sha256").update(`vaultysid/test/${name}`).digest());

const DERIVE_CASES: Array<{ service: string; alg: ServiceAlgorithm; role?: ServiceRole; postQuantum?: boolean }> = [];
for (const service of ["https://Service-A.test:443/", "https://service-b.test", "app:test.service.c"]) {
  for (const alg of ["ed25519", "dilithium", "dilithium_ed25519"] as const) DERIVE_CASES.push({ service, alg });
}
DERIVE_CASES.push({ service: "https://service-a.test", alg: "dilithium_ed25519", postQuantum: true });
DERIVE_CASES.push({ service: "https://service-a.test", alg: "dilithium", postQuantum: true });
DERIVE_CASES.push({ service: "https://service-a.test", alg: "ed25519", role: "organization" });
DERIVE_CASES.push({ service: "https://service-a.test", alg: "ed25519", role: "machine" });

export async function buildVectors() {
  const canonical: CanonicalCase[] = CANONICAL_INPUTS.map(([input, dev]) => {
    const options = dev ? { allowDevelopmentHosts: true } : {};
    let output: string;
    try {
      output = canonicalServiceId(input, options);
    } catch {
      output = "invalid";
    }
    return { input, options, output };
  });

  const masterName = "vectors/master";
  const master = testMaster(masterName);
  const derive = [];
  for (const c of DERIVE_CASES) {
    const options: ServiceIdentityOptions = { alg: c.alg, role: c.role, postQuantum: c.postQuantum };
    const canon = canonicalServiceId(c.service);
    const role = c.role ?? "person";
    const typeName = c.postQuantum ? `${role}-pq` : role;
    const info = Buffer.concat([lp("v1"), lp(c.alg), lp(typeName), lp(canon)]);
    const expected = Buffer.from(hkdfSync("sha256", master, Buffer.from(SERVICE_IDENTITY_SALT, "ascii"), info, 32));
    const entropy = Buffer.from(deriveServiceEntropy(master, c.service, options));
    if (!entropy.equals(expected)) throw new Error(`entropy mismatch for ${c.service} ${c.alg} ${typeName}`);
    const identity = await deriveServiceIdentity(master, c.service, options);
    const id = Buffer.from(identity.id);
    derive.push({
      service: c.service,
      canonical: canon,
      alg: c.alg,
      type: identity.type,
      typeName,
      info: info.toString("hex"),
      entropy: entropy.toString("hex"),
      did: identity.did,
      idLength: id.length,
      idSha256: createHash("sha256").update(id).digest("hex"),
      ...(c.alg === "ed25519" ? { id: id.toString("hex") } : {}),
    });
  }

  return {
    description: 'rfc/SERVICE-IDENTITIES.md §7. canonical: input, options, canonical output or "invalid". derive: master = SHA-256("vaultysid/test/" || masterName), a PUBLIC test value; info = lp("v1") || lp(alg) || lp(typeName) || lp(canonical); entropy = HKDF-SHA-256(master, "vaultysid/service-identity/v1", info, 32); identity = VaultysId.fromEntropy(entropy, type, alg); idSha256 = SHA-256(id). Fully deterministic.',
    testValuesArePublic: true,
    canonical,
    masterName,
    master: Buffer.from(master).toString("hex"),
    derive,
  };
}

export const VECTORS_PATH = join(__dirname, "service-identity-vectors.json");
/** Copies read by the Go and Rust tests. */
export const VECTOR_COPIES = [join(__dirname, "../../../go/test/compatibility/testdata/service-identity-vectors.json"), join(__dirname, "../../../rust/tests/data/service-identity-vectors.json")];

if (require.main === module) {
  buildVectors().then((vectors) => {
    const text = JSON.stringify(vectors, null, 2) + "\n";
    for (const path of [VECTORS_PATH, ...VECTOR_COPIES]) writeFileSync(path, text);
    console.log(`wrote ${VECTORS_PATH}: ${vectors.canonical.length} canonical, ${vectors.derive.length} derive`);
  });
}
