import assert from "assert";
import { Buffer } from "buffer/";
import { VaultysId } from "..";
import "./shims";

describe("VaultysId.fromEntropy", () => {
  for (const alg of ["ed25519", "dilithium", "dilithium_ed25519"] as const) {
    it(`leaves the caller's buffer untouched and is deterministic (${alg})`, async () => {
      const entropy = Buffer.alloc(32, 7);
      const a = await VaultysId.fromEntropy(entropy, 1, alg);
      a.keyManager.cleanSecureData?.();
      assert.ok(entropy.equals(Buffer.alloc(32, 7)));
      const b = await VaultysId.fromEntropy(entropy, 1, alg);
      assert.strictEqual(a.did, b.did);
    });
  }

  it("refuses entropy that is not 32 bytes", async () => {
    for (const length of [0, 16, 31, 33, 64]) {
      await assert.rejects(VaultysId.fromEntropy(Buffer.alloc(length, 1), 1), /entropy must be 32 bytes/, String(length));
    }
  });

  it("accepts a plain Uint8Array", async () => {
    const id = await VaultysId.fromEntropy(new Uint8Array(32).fill(3), 0);
    assert.ok(id.isMachine());
  });
});
