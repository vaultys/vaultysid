import { describe, it } from "mocha";
import { expect } from "chai";
import Ed25519Manager from "../../src/KeyManager/Ed25519Manager";
import VaultysId from "../../src/VaultysId";
import { readFileSync, existsSync } from "fs";
import { resolve } from "path";
import { decode } from "@msgpack/msgpack";

describe("Go Compatibility Tests", function () {
  this.timeout(10000);

  let goVectors: any;

  before(function () {
    // Try to load Go-generated test vectors
    const paths = [resolve(__dirname, "../../../go/test/compatibility/go-test-vectors.json"), resolve(__dirname, "../../../../go/test/compatibility/go-test-vectors.json")];

    let found = false;
    for (const path of paths) {
      if (existsSync(path)) {
        goVectors = JSON.parse(readFileSync(path, "utf8"));
        found = true;
        break;
      }
    }

    if (!found) {
      this.skip();
    }
  });

  describe("Key Generation", () => {
    it("should generate same keys from same entropy", async () => {
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const km = await Ed25519Manager.createFromEntropy(entropy);

      expect(km.signer.publicKey.toString("hex")).to.equal(goVectors.keyGeneration.ed25519.publicKey);
      expect(km.cypher.publicKey.toString("hex")).to.equal(goVectors.keyGeneration.x25519.publicKey);
    });
  });

  describe("Identity", () => {
    it("should generate same identity bytes and DID", async () => {
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const km = await Ed25519Manager.createFromEntropy(entropy);
      const vid = new VaultysId(km, undefined, goVectors.identity.type);

      expect(vid.id.toString("hex")).to.equal(goVectors.identity.idBytes);
      expect(vid.id.length).to.equal(goVectors.identity.idBytesLength);
      expect(vid.did).to.equal(goVectors.identity.did);
    });

    it("should deserialize Go identity", () => {
      const idBytes = Buffer.from(goVectors.identity.idBytes, "hex");
      const vid = VaultysId.fromId(idBytes);

      expect(vid.type).to.equal(goVectors.identity.type);
      expect(vid.did).to.equal(goVectors.identity.did);
    });
  });

  describe("Signing", () => {
    it("should verify Go signatures", async () => {
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const km = await Ed25519Manager.createFromEntropy(entropy);

      const message = Buffer.from(goVectors.signing.message, "hex");
      const goSignature = Buffer.from(goVectors.signing.signature, "hex");

      // Verify Go signature
      const isValid = km.verify(message, goSignature);
      expect(isValid).to.be.true;

      // Our signature should match Go's
      const ourSignature = await km.sign(message);
      expect(ourSignature.toString("hex")).to.equal(goVectors.signing.signature);
    });

    it("should verify additional signatures", async () => {
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const km = await Ed25519Manager.createFromEntropy(entropy);

      for (const testCase of goVectors.additionalSignatures) {
        let message: Buffer;
        if (testCase.message === "") {
          message = Buffer.from([]);
        } else if (testCase.message === "VaultysID") {
          message = Buffer.from("VaultysID");
        } else {
          message = Buffer.from(testCase.message, "hex");
        }

        const goSignature = Buffer.from(testCase.signature, "hex");

        // Verify Go signature
        const isValid = km.verify(message, goSignature);
        expect(isValid, `Failed to verify signature for message: ${testCase.message}`).to.be.true;

        // Our signature should match
        const ourSignature = await km.sign(message);
        expect(ourSignature.toString("hex")).to.equal(testCase.signature);
      }
    });
  });

  describe("Diffie-Hellman", () => {
    it("should compute same shared secret", async () => {
      const aliceEntropy = Buffer.from(goVectors.diffieHellman.aliceEntropy, "hex");
      const bobEntropy = Buffer.from(goVectors.diffieHellman.bobEntropy, "hex");

      const alice = await Ed25519Manager.createFromEntropy(aliceEntropy);
      const bob = await Ed25519Manager.createFromEntropy(bobEntropy);

      // Verify Bob's public key matches
      expect(bob.cypher.publicKey.toString("hex")).to.equal(goVectors.diffieHellman.bobPublicKey);

      // Compute shared secret
      const aliceCypher = await alice.getCypher();
      const sharedSecret = await aliceCypher.diffieHellman(bob.cypher.publicKey);

      expect(sharedSecret.toString("hex")).to.equal(goVectors.diffieHellman.sharedSecret);
    });
  });

  describe("HMAC", () => {
    it("should compute same HMAC", async () => {
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const km = await Ed25519Manager.createFromEntropy(entropy);
      const cypher = await km.getCypher();

      const hmac = cypher.hmac(goVectors.hmac.message);
      expect(hmac?.toString("hex")).to.equal(goVectors.hmac.result);
    });
  });

  describe("Serialization", () => {
    it("should deserialize Go secret", async () => {
      const secret = Buffer.from(goVectors.serialization.secret, "hex");
      const km = Ed25519Manager.fromSecret(secret);

      // Should have same public keys
      expect(km.signer.publicKey.toString("hex")).to.equal(goVectors.keyGeneration.ed25519.publicKey);
      expect(km.cypher.publicKey.toString("hex")).to.equal(goVectors.keyGeneration.x25519.publicKey);

      // Should be able to sign
      const message = Buffer.from("test");
      const signature = await km.sign(message);
      expect(signature).to.exist;
    });

    it("should deserialize Go public ID", () => {
      const publicId = Buffer.from(goVectors.serialization.publicId, "hex");
      const km = Ed25519Manager.fromId(publicId);

      // Should have same public keys
      expect(km.signer.publicKey.toString("hex")).to.equal(goVectors.keyGeneration.ed25519.publicKey);
      expect(km.cypher.publicKey.toString("hex")).to.equal(goVectors.keyGeneration.x25519.publicKey);

      // Should be public-only
      expect(km.capability).to.equal("public");
    });
  });

  describe("Cross-verification", () => {
    it("should create compatible identity from same entropy", async () => {
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const vid = await VaultysId.fromEntropy(entropy, goVectors.identity.type);

      // Should have same DID
      expect(vid.did).to.equal(goVectors.identity.did);

      // Should create same ID bytes
      expect(vid.id.toString("hex")).to.equal(goVectors.identity.idBytes);

      // Should be able to verify Go signatures
      const message = Buffer.from(goVectors.signing.message, "hex");
      const goSignature = Buffer.from(goVectors.signing.signature, "hex");
      const isValid = vid.keyManager.verify(message, goSignature);
      expect(isValid).to.be.true;
    });

    it("should handle Go-generated identity end-to-end", async () => {
      // Load Go identity
      const goIdBytes = Buffer.from(goVectors.identity.idBytes, "hex");
      const goVid = VaultysId.fromId(goIdBytes);

      // Create our own from same entropy
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const ourVid = await VaultysId.fromEntropy(entropy, goVectors.identity.type);

      // Sign with ours
      const message = Buffer.from("cross-check message");
      const ourSignature = await ourVid.keyManager.sign(message);

      // Go identity should verify our signature
      const canVerify = goVid.keyManager.verify(message, ourSignature);
      expect(canVerify).to.be.true;

      // Verify Go signature with our identity
      const goMessage = Buffer.from(goVectors.signing.message, "hex");
      const goSignature = Buffer.from(goVectors.signing.signature, "hex");
      const verified = ourVid.keyManager.verify(goMessage, goSignature);
      expect(verified).to.be.true;
    });
  });
});
