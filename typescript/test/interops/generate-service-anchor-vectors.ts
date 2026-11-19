// Deterministic test vectors for service anchors (rfc/SERVICE-IDENTITIES.md §8).
// Run: pnpm test:anchor:vectors (from typescript/). Ed25519 signatures are deterministic, so anchors are fixed bytes.

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { createServiceAnchor } from "../../src/serviceAnchor";
import { deriveServiceIdentity } from "../../src/serviceIdentity";
import { testMaster } from "./generate-service-identity-vectors";

const hex = (u: Uint8Array) => Buffer.from(u).toString("hex");

export async function buildVectors() {
  const masterName = "anchors/service";
  const master = testMaster(masterName);
  const valid = [];
  for (const serviceId of ["https://service-a.test", "https://xn--srvice-a-c8g.test"]) {
    const identity = await deriveServiceIdentity(master, serviceId, { role: "organization" });
    const anchor = await createServiceAnchor(identity, serviceId);
    valid.push({ serviceId, did: identity.did, anchor: hex(anchor) });
  }
  const a = Buffer.from(valid[0].anchor, "hex");
  const flip = (i: number) => {
    const b = Buffer.from(a);
    b[i] ^= 1;
    return hex(b);
  };
  const invalid = [
    { name: "fetched from another origin", serviceId: "https://service-b.test", anchor: valid[0].anchor },
    { name: "version byte", serviceId: valid[0].serviceId, anchor: flip(0) },
    { name: "algorithm byte", serviceId: valid[0].serviceId, anchor: flip(1) },
    { name: "signature altered", serviceId: valid[0].serviceId, anchor: flip(a.length - 1) },
    { name: "trailing byte", serviceId: valid[0].serviceId, anchor: hex(Buffer.concat([a, Buffer.from([0])])) },
    { name: "truncated", serviceId: valid[0].serviceId, anchor: hex(a.subarray(0, a.length - 1)) },
    { name: "empty", serviceId: valid[0].serviceId, anchor: "" },
  ];
  return {
    description: 'rfc/SERVICE-IDENTITIES.md §8: service anchors. Identities = deriveServiceIdentity(master, serviceId, {role: organization}), master = SHA-256("vaultysid/test/" || masterName), a PUBLIC test value. valid: verifyServiceAnchor(anchor, serviceId) returns the identity with this DID. invalid: it returns null.',
    testValuesArePublic: true,
    masterName,
    valid,
    invalid,
  };
}

export const VECTORS_PATH = join(__dirname, "service-anchor-vectors.json");

if (require.main === module) {
  buildVectors().then((vectors) => {
    writeFileSync(VECTORS_PATH, JSON.stringify(vectors, null, 2) + "\n");
    console.log(`wrote ${VECTORS_PATH}`);
  });
}
