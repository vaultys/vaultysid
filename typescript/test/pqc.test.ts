import assert from "assert";
import { generateDilithiumKeyPair, signDilithium, verifyDilithium, createDilithiumCoseKey, getDilithiumKeyInfo, PQ_COSE_ALG, PQ_COSE_KEY_TYPE, PQ_COSE_KEY_PARAMS } from "../src/pqCrypto";
import { Buffer } from "../src/crypto";

describe("Post-Quantum Cryptography", () => {
  let keyPair: { publicKey: Buffer; secretKey: Buffer };
  const testMessage = Buffer.from("Hello, Post-Quantum World!");

  beforeEach(() => {
    keyPair = generateDilithiumKeyPair();
  });

  describe("DILITHIUM Key Generation", () => {
    it("should generate different key pairs on each call", async () => {
      const keyPair1 = generateDilithiumKeyPair();
      const keyPair2 = generateDilithiumKeyPair();

      assert.notDeepEqual(keyPair1.publicKey, keyPair2.publicKey);
      assert.notDeepEqual(keyPair1.secretKey, keyPair2.secretKey);
    });

    it("should generate keys with correct sizes", async () => {
      const keyInfo = getDilithiumKeyInfo();

      assert.equal(keyPair.publicKey.length, keyInfo.publicKeySize);
      assert.equal(keyPair.secretKey.length, keyInfo.secretKeySize);
    });
  });

  describe("DILITHIUM Signing", () => {
    it("should sign a message successfully", async () => {
      const signature = signDilithium(testMessage, keyPair.secretKey);

      assert.equal(signature.length > 0, true);
    });

    it("should produce signatures of correct size", async () => {
      const signature = signDilithium(testMessage, keyPair.secretKey);
      const keyInfo = getDilithiumKeyInfo();

      assert.equal(signature.length, keyInfo.signatureSize);
    });

    it("should produce different signatures for different messages", async () => {
      const message1 = Buffer.from("Message 1");
      const message2 = Buffer.from("Message 2");

      const signature1 = signDilithium(message1, keyPair.secretKey);
      const signature2 = signDilithium(message2, keyPair.secretKey);

      assert.notDeepEqual(signature1, signature2);
    });
  });

  describe("DILITHIUM Verification", () => {
    let signature: Buffer;

    beforeEach(async () => {
      signature = signDilithium(testMessage, keyPair.secretKey);
    });

    it("should verify a valid signature", async () => {
      const isValid = verifyDilithium(testMessage, signature, keyPair.publicKey);

      assert.equal(isValid, true);
    });

    it("should reject an invalid signature", async () => {
      const invalidSignature = Buffer.alloc(signature.length, 0);
      const isValid = verifyDilithium(testMessage, invalidSignature, keyPair.publicKey);

      assert.equal(isValid, false);
    });

    it("should reject signature with wrong message", async () => {
      const wrongMessage = Buffer.from("Wrong message");
      const isValid = verifyDilithium(wrongMessage, signature, keyPair.publicKey);

      assert.equal(isValid, false);
    });

    it("should reject signature with wrong public key", async () => {
      const wrongKeyPair = generateDilithiumKeyPair();
      const isValid = verifyDilithium(testMessage, signature, wrongKeyPair.publicKey);

      assert.equal(isValid, false);
    });

    it("should work with Uint8Array inputs", async () => {
      const messageArray = new Uint8Array(testMessage);
      const signatureArray = new Uint8Array(signature);
      const publicKeyArray = new Uint8Array(keyPair.publicKey);

      const isValid = verifyDilithium(messageArray, signatureArray, publicKeyArray);

      assert.equal(isValid, true);
    });

    it("should handle corrupted signature gracefully", async () => {
      const corruptedSignature = Buffer.from(signature);
      corruptedSignature[0] = corruptedSignature[0] ^ 0xff; // Flip bits

      const isValid = verifyDilithium(testMessage, corruptedSignature, keyPair.publicKey);

      assert.equal(isValid, false);
    });
  });

  describe("COSE Key Creation", () => {
    it("should create a valid COSE key", () => {
      const coseKey = createDilithiumCoseKey(keyPair.publicKey);

      assert.equal(coseKey.get(1), PQ_COSE_KEY_TYPE.DILITHIUM);
      assert.equal(coseKey.get(3), PQ_COSE_ALG.DILITHIUM2);
      assert.equal(coseKey.get(PQ_COSE_KEY_PARAMS.DILITHIUM_MODE), 2);
      assert.deepEqual(coseKey.get(PQ_COSE_KEY_PARAMS.DILITHIUM_PK), keyPair.publicKey);
    });

    it("should work with Uint8Array input", () => {
      const publicKeyArray = new Uint8Array(keyPair.publicKey);
      const coseKey = createDilithiumCoseKey(publicKeyArray);

      assert.equal(coseKey.get(1), PQ_COSE_KEY_TYPE.DILITHIUM);
    });
  });

  describe("Key Info", () => {
    it("should return correct key size information", () => {
      const keyInfo = getDilithiumKeyInfo();

      assert.equal(keyInfo.publicKeySize, 1952);
      assert.equal(keyInfo.secretKeySize, 4032);
      assert.equal(keyInfo.signatureSize, 3309);
    });

    it("should match actual generated key sizes", async () => {
      const keyInfo = getDilithiumKeyInfo();
      const testKeyPair = generateDilithiumKeyPair();

      assert.equal(testKeyPair.publicKey.length, keyInfo.publicKeySize);
      assert.equal(testKeyPair.secretKey.length, keyInfo.secretKeySize);
    });
  });

  describe("Constants", () => {
    it("should have correct COSE algorithm identifiers", () => {
      assert.equal(PQ_COSE_ALG.DILITHIUM2, -46);
      assert.equal(PQ_COSE_ALG.DILITHIUM3, -47);
      assert.equal(PQ_COSE_ALG.DILITHIUM5, -48);
    });

    it("should have correct COSE key type", () => {
      assert.equal(PQ_COSE_KEY_TYPE.DILITHIUM, 4);
    });

    it("should have correct COSE key parameters", () => {
      assert.equal(PQ_COSE_KEY_PARAMS.DILITHIUM_MODE, -100);
      assert.equal(PQ_COSE_KEY_PARAMS.DILITHIUM_PK, -101);
      assert.equal(PQ_COSE_KEY_PARAMS.DILITHIUM_SK, -102);
    });
  });

  describe("End-to-End Workflow", () => {
    it("should complete full sign-verify cycle", async () => {
      // Generate keys
      const testKeyPair = generateDilithiumKeyPair();

      // Sign message
      const message = Buffer.from("End-to-end test message");
      const signature = signDilithium(message, testKeyPair.secretKey);

      // Verify signature
      const isValid = verifyDilithium(message, signature, testKeyPair.publicKey);

      // Create COSE key
      const coseKey = createDilithiumCoseKey(testKeyPair.publicKey);

      assert.equal(isValid, true);
      assert.equal(coseKey.get(PQ_COSE_KEY_PARAMS.DILITHIUM_PK), testKeyPair.publicKey);
    });

    it("should handle multiple signatures with same key pair", async () => {
      const messages = [Buffer.from("Message 1"), Buffer.from("Message 2"), Buffer.from("Message 3")];

      const signatures: Buffer[] = [];

      // Sign all messages
      for (const message of messages) {
        const signature = signDilithium(message, keyPair.secretKey);
        signatures.push(signature);
      }

      // Verify all signatures
      for (let i = 0; i < messages.length; i++) {
        const isValid = verifyDilithium(messages[i], signatures[i], keyPair.publicKey);
        assert.equal(isValid, true);
      }
    });
  });
});
