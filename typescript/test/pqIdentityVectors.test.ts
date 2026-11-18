import assert from "assert";
import { readFileSync } from "fs";
import { resolve } from "path";
import { Buffer } from "buffer/";
import { VaultysId } from "..";
import "./shims";
import { generatePqIdentityVectors } from "./interops/generate-pq-identity-vectors";

// rfc/PQ-ENCRYPTION.md §11: the committed vectors (also read by Go and Rust) must be
// reproducible from the TypeScript reference and valid through the public API.

const committed = JSON.parse(readFileSync(resolve(__dirname, "interops/pq-identity-vectors.json"), "utf-8"));
const fromHex = (value: string) => Buffer.from(value, "hex");

describe("Cross-language post-quantum identity vectors", () => {
  it("are reproducible", async () => {
    const regenerated = JSON.parse(JSON.stringify(await generatePqIdentityVectors()));
    assert.deepStrictEqual(regenerated, committed);
  });

  it("restore every identity from its secret and from its id", () => {
    for (const [name, vector] of Object.entries<any>(committed.identities)) {
      const id = VaultysId.fromSecret(vector.secret);
      assert.equal(id.id.toString("hex"), vector.id, name);
      assert.equal(id.did, vector.did, name);
      const contact = VaultysId.fromId(fromHex(vector.id));
      assert.equal(contact.did, vector.did, name);
      assert.equal(contact.isPostQuantum(), name.startsWith("pq_"), name);
    }
  });

  it("compute the PRF vectors", async () => {
    for (const vector of committed.prf) {
      const id = VaultysId.fromSecret(committed.identities[vector.identity].secret);
      assert.equal((await id.hmac(vector.message))?.toString("hex"), vector.hmac);
      assert.equal(id.keyManager.getSecretHash(fromHex(vector.secretHashData)).toString("hex"), vector.secretHash);
    }
  });

  it("decrypt the DHIES v3 vectors", async () => {
    for (const vector of committed.dhiesV3) {
      const recipient = VaultysId.fromSecret(committed.identities[vector.recipient].secret);
      const plaintext = await recipient.dhiesDecrypt(fromHex(vector.out), fromHex(committed.identities[vector.sender].id));
      assert.equal(plaintext?.toString("hex"), vector.plaintext, vector.name);
    }
  });

  it("reject every negative vector", async () => {
    for (const vector of committed.negative.ids) assert.throws(() => VaultysId.fromId(fromHex(vector.id)), vector.name);
    for (const vector of committed.negative.secrets) assert.throws(() => VaultysId.fromSecret(vector.secret), vector.name);
    for (const vector of committed.negative.dhies) {
      const recipient = VaultysId.fromSecret(committed.identities[vector.recipient].secret);
      assert.equal(await recipient.dhiesDecrypt(fromHex(vector.ciphertext), fromHex(committed.identities[vector.sender].id)), null, vector.name);
    }
  });
});
