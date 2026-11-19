import assert from "assert";
import { Buffer } from "buffer/";
import { VaultysId } from "..";
import "./shims";
import CypherManager from "../src/KeyManager/CypherManager";
import { DHIES_V3_MIN_LENGTH, DHIES_V3_SIGNED_TAG, DHIES_V3_TAG, dhiesV3SignedEncrypt } from "../src/KeyManager/dhies";

// PROPOSAL (rfc/PQ-ENCRYPTION.md, Appendix A): optional post-quantum sender
// authentication for DHIES v3, off unless requested on both sides.

const signedOverhead = (signatureLength: number) => DHIES_V3_MIN_LENGTH + 2 + signatureLength;

describe("Post-quantum sender authentication (proposal)", () => {
  let dilithium: VaultysId, hybrid: VaultysId, recipient: VaultysId, classical: VaultysId, classicalDilithium: VaultysId;
  before(async () => {
    [dilithium, hybrid, recipient, classical, classicalDilithium] = await Promise.all([VaultysId.generatePerson("dilithium", true), VaultysId.generatePerson("dilithium_ed25519", true), VaultysId.generateMachine("dilithium", true), VaultysId.generatePerson(), VaultysId.generatePerson("dilithium")]);
  });

  describe("default behaviour is unchanged", () => {
    it("dhiesEncrypt without options produces plain DHIES v3", async () => {
      const out = await dilithium.dhiesEncrypt("hello", recipient.id);
      assert.equal(out![0], DHIES_V3_TAG);
      assert.equal(out!.length, DHIES_V3_MIN_LENGTH + 5);
    });

    it("dhiesDecrypt without options refuses a signed message", async () => {
      const signed = await dilithium.dhiesEncrypt("hello", recipient.id, { senderSignature: true });
      assert.equal(signed![0], DHIES_V3_SIGNED_TAG);
      assert.equal(await recipient.dhiesDecrypt(signed!, dilithium.id), null);
    });
  });

  describe("signed DHIES v3", () => {
    it("round-trips for Dilithium and Hybrid senders, with the signature size as overhead", async () => {
      for (const [sender, signatureLength] of [
        [dilithium, 4627],
        [hybrid, 64 + 4627],
      ] as [VaultysId, number][]) {
        const out = await sender.dhiesEncrypt("hello", recipient.id, { senderSignature: true });
        assert.equal(out!.length, signedOverhead(signatureLength) + 5);
        assert.equal((await recipient.dhiesDecrypt(out!, sender.id, { senderSignature: "require" }))?.toString(), "hello");
        assert.equal((await recipient.dhiesDecrypt(out!, sender.id, { senderSignature: "accept" }))?.toString(), "hello");
      }
    });

    it('"accept" also opens plain v3, "require" does not', async () => {
      const plain = await classical.dhiesEncrypt("plain", recipient.id);
      assert.equal((await recipient.dhiesDecrypt(plain!, classical.id, { senderSignature: "accept" }))?.toString(), "plain");
      assert.equal(await recipient.dhiesDecrypt(plain!, classical.id, { senderSignature: "require" }), null);
    });

    it("cannot be turned into plain v3 or back", async () => {
      const signed = await dilithium.dhiesEncrypt("hello", recipient.id, { senderSignature: true });
      const asPlain = Buffer.from(signed!);
      asPlain[0] = DHIES_V3_TAG;
      assert.equal(await recipient.dhiesDecrypt(asPlain, dilithium.id), null);
      assert.equal(await recipient.dhiesDecrypt(asPlain, dilithium.id, { senderSignature: "accept" }), null);
      const plain = await dilithium.dhiesEncrypt("hello", recipient.id);
      const asSigned = Buffer.from(plain!);
      asSigned[0] = DHIES_V3_SIGNED_TAG;
      assert.equal(await recipient.dhiesDecrypt(asSigned, dilithium.id, { senderSignature: "accept" }), null);
    });

    it("rejects a wrong sender, a tampered message and a truncated message", async () => {
      const signed = await dilithium.dhiesEncrypt("hello", recipient.id, { senderSignature: true });
      assert.equal(await recipient.dhiesDecrypt(signed!, hybrid.id, { senderSignature: "require" }), null);
      for (const pos of [1, 30, 100, 1200, signed!.length - 1]) {
        const tampered = Buffer.from(signed!);
        tampered[pos] ^= 1;
        assert.equal(await recipient.dhiesDecrypt(tampered, dilithium.id, { senderSignature: "require" }), null, "byte " + pos);
      }
      assert.equal(await recipient.dhiesDecrypt(signed!.subarray(0, DHIES_V3_MIN_LENGTH + 1), dilithium.id, { senderSignature: "require" }), null);
    });

    it("rejects a signature that does not cover this transcript and plaintext", async () => {
      // the sender's key signs another plaintext: the secretbox opens, the signature fails
      const senderKm = dilithium.keyManager as CypherManager;
      const recipientKm = recipient.keyManager as CypherManager;
      const cypher = await senderKm.getCypher();
      const sign = (tbs: Buffer) => (dilithium as any).signInDomain(Buffer.from("VAULTYS_DHIES_V3S"), Buffer.concat([tbs.subarray(0, tbs.length - 32), Buffer.alloc(32)]));
      const out = await dhiesV3SignedEncrypt("hello", cypher.diffieHellman, senderKm.cypher.publicKey, recipientKm.cypher.publicKey, recipientKm.kem!.publicKey, dilithium.id, recipient.id, sign);
      assert.equal(await recipient.dhiesDecrypt(out, dilithium.id, { senderSignature: "require" }), null);
      // and a signature in another domain (VAULTYS_RAW) is refused
      const rawSign = (tbs: Buffer) => dilithium.sign(tbs);
      const raw = await dhiesV3SignedEncrypt("hello", cypher.diffieHellman, senderKm.cypher.publicKey, recipientKm.cypher.publicKey, recipientKm.kem!.publicKey, dilithium.id, recipient.id, rawSign);
      assert.equal(await recipient.dhiesDecrypt(raw, dilithium.id, { senderSignature: "require" }), null);
    });

    it("requires an ML-DSA sender and a post-quantum recipient", async () => {
      assert.equal(await classical.dhiesEncrypt("x", recipient.id, { senderSignature: true }), null);
      assert.equal(await dilithium.dhiesEncrypt("x", classicalDilithium.id, { senderSignature: true }), null);
      // a classical recipient never opens a signed message
      assert.equal(await classicalDilithium.dhiesDecrypt(Buffer.from([DHIES_V3_SIGNED_TAG, ...Buffer.alloc(1200)]), dilithium.id, { senderSignature: "accept" }), null);
    });
  });
});
