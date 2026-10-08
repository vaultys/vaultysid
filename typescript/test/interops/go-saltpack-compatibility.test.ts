import { describe, it, before } from "mocha";
import { expect } from "chai";
import { createHash } from "crypto";
import { readFileSync } from "fs";
import { resolve } from "path";
import VaultysId from "../../src/VaultysId";

/**
 * Go → TypeScript: every ciphertext made by the Go Encrypt / Signcrypt
 * (go/test/compatibility/generate_saltpack_vectors.go) must open here, for every
 * recipient, and decrypt(message, senderId) must accept the real sender only.
 *
 *   pnpm mocha test/interops/go-saltpack-compatibility.test.ts
 */
type Vectors = {
  identities: Record<string, { secret: string; alg: string; version: 0 | 1; id: string }>;
  cases: { name: string; plaintext?: string; plaintextSha256?: string; recipients: string[]; sender: string | null; ciphertext: string }[];
};

describe("Saltpack: Go → TypeScript", function () {
  this.timeout(30000);
  let vectors: Vectors;
  const ids: Record<string, VaultysId> = {};

  before(() => {
    vectors = JSON.parse(readFileSync(resolve(__dirname, "../../../go/test/compatibility/testdata/saltpack-go-vectors.json"), "utf8"));
    for (const [name, e] of Object.entries(vectors.identities)) {
      ids[name] = VaultysId.fromSecret(e.secret, "base64").toVersion(e.version);
      // Same keys on both sides, or nothing below means anything.
      expect(ids[name].id.toString("hex"), `${name} id`).to.equal(e.id);
    }
  });

  it("opens every Go ciphertext", async () => {
    for (const c of vectors.cases) {
      for (const name of c.recipients) {
        const got = await ids[name].decrypt(c.ciphertext);
        if (c.plaintext !== undefined) expect(got, `${c.name} / ${name}`).to.equal(c.plaintext);
        else expect(createHash("sha256").update(got, "utf8").digest("hex"), `${c.name} / ${name}`).to.equal(c.plaintextSha256);

        if (c.sender) {
          expect(await ids[name].decrypt(c.ciphertext, ids[c.sender].id), `${c.name} from ${c.sender}`).to.equal(got);
        }
        for (const other of Object.keys(ids)) {
          if (other === c.sender) continue;
          let refused = false;
          try {
            await ids[name].decrypt(c.ciphertext, ids[other].id);
          } catch {
            refused = true;
          }
          expect(refused, `${c.name}: ${name} accepted ${other} as the sender`).to.equal(true);
        }
      }
      for (const [name, id] of Object.entries(ids)) {
        if (c.recipients.includes(name)) continue;
        let refused = false;
        try {
          await id.decrypt(c.ciphertext);
        } catch {
          refused = true;
        }
        expect(refused, `${c.name}: ${name} is not a recipient but decrypted it`).to.equal(true);
      }
    }
  });
});
