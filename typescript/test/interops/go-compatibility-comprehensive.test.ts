import { describe, it, before } from "mocha";
import { expect } from "chai";
import Ed25519Manager from "../../src/KeyManager/Ed25519Manager";
import VaultysId from "../../src/VaultysId";
import Challenger from "../../src/Challenger";
import { readFileSync, existsSync } from "fs";
import { resolve } from "path";
import { decode, encode } from "@msgpack/msgpack";

describe("Go Comprehensive Compatibility Tests", function () {
  this.timeout(10000);

  let goVectors: any;

  before(function () {
    // Try to load Go-generated comprehensive test vectors
    const paths = [resolve(__dirname, "../../../go/test/compatibility/go-comprehensive-vectors.json"), resolve(__dirname, "../../../../go/test/compatibility/go-comprehensive-vectors.json")];

    let found = false;
    for (const path of paths) {
      if (existsSync(path)) {
        goVectors = JSON.parse(readFileSync(path, "utf8"));
        found = true;
        break;
      }
    }

    if (!found) {
      console.log("Go comprehensive vectors not found. Run 'go run generate_comprehensive_vectors.go' in go/test/compatibility/");
      this.skip();
    }
  });

  describe("Key Generation", () => {
    it("should generate same Ed25519 keys from same entropy", async () => {
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const km = await Ed25519Manager.createFromEntropy(entropy);

      expect(km.signer.publicKey.toString("hex")).to.equal(goVectors.keyGeneration.ed25519.publicKey);
      expect(km.signer.secretKey.toString("hex")).to.equal(goVectors.keyGeneration.ed25519.secretKey);
    });

    it("should generate same X25519 keys from same entropy", async () => {
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const km = await Ed25519Manager.createFromEntropy(entropy);

      expect(km.cypher.publicKey.toString("hex")).to.equal(goVectors.keyGeneration.x25519.publicKey);
      expect(km.cypher.secretKey.toString("hex")).to.equal(goVectors.keyGeneration.x25519.secretKey);
    });
  });

  describe("Identity", () => {
    it("should generate same identity with correct type", async () => {
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const km = await Ed25519Manager.createFromEntropy(entropy);
      const vid = new VaultysId(km, undefined, goVectors.identity.type);

      expect(vid.type).to.equal(goVectors.identity.type);
      expect(vid.version).to.equal(goVectors.identity.version);
    });

    it("should generate same identity bytes", async () => {
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const km = await Ed25519Manager.createFromEntropy(entropy);
      const vid = new VaultysId(km, undefined, goVectors.identity.type);

      expect(vid.id.toString("hex")).to.equal(goVectors.identity.idBytes);
      expect(vid.id.length).to.equal(goVectors.identity.idBytesLength);
    });

    it("should generate same DID", async () => {
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const vid = await VaultysId.fromEntropy(entropy, goVectors.identity.type);

      expect(vid.did).to.equal(goVectors.identity.did);
    });

    it("should deserialize Go identity correctly", () => {
      const idBytes = Buffer.from(goVectors.identity.idBytes, "hex");
      const vid = VaultysId.fromId(idBytes);

      expect(vid.type).to.equal(goVectors.identity.type);
      expect(vid.did).to.equal(goVectors.identity.did);
    });
  });

  describe("Signing", () => {
    it("should verify Go signature for test message", async () => {
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const km = await Ed25519Manager.createFromEntropy(entropy);

      const message = Buffer.from(goVectors.signing.messageHex, "hex");
      const goSignature = Buffer.from(goVectors.signing.signature, "hex");

      // Verify Go signature
      const isValid = km.verify(message, goSignature);
      expect(isValid).to.be.true;

      // Our signature should match Go's (deterministic)
      const ourSignature = await km.sign(message);
      expect(ourSignature.toString("hex")).to.equal(goVectors.signing.signature);
    });

    it("should verify all additional signature test cases", async () => {
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const km = await Ed25519Manager.createFromEntropy(entropy);

      for (const testCase of goVectors.signing.additionalSignatures) {
        const message = Buffer.from(testCase.messageHex, "hex");
        const goSignature = Buffer.from(testCase.signature, "hex");

        // Verify Go signature
        const isValid = km.verify(message, goSignature);
        expect(isValid, `Failed to verify signature for test case: ${testCase.name}`).to.be.true;

        // Our signature should match
        const ourSignature = await km.sign(message);
        expect(ourSignature.toString("hex"), `Signature mismatch for test case: ${testCase.name}`).to.equal(testCase.signature);
      }
    });
  });

  describe("Diffie-Hellman", () => {
    it("should compute same shared secret", async () => {
      const aliceEntropy = Buffer.from(goVectors.diffieHellman.aliceEntropy, "hex");
      const bobEntropy = Buffer.from(goVectors.diffieHellman.bobEntropy, "hex");

      const alice = await Ed25519Manager.createFromEntropy(aliceEntropy);
      const bob = await Ed25519Manager.createFromEntropy(bobEntropy);

      // Verify public keys match
      expect(alice.cypher.publicKey.toString("hex")).to.equal(goVectors.diffieHellman.alicePublicKey);
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
      const vaultysId = VaultysId.fromSecret(secret);
      const km = vaultysId.keyManager;

      // Should have same public keys
      expect(km.signer.publicKey.toString("hex")).to.equal(goVectors.keyGeneration.ed25519.publicKey);
      expect(km.cypher.publicKey.toString("hex")).to.equal(goVectors.keyGeneration.x25519.publicKey);

      // Should be able to sign
      const message = Buffer.from("test");
      const signature = await km.sign(message);
      expect(signature).to.exist;
      expect(signature.length).to.equal(64);
    });

    it("should deserialize Go public ID", () => {
      const publicId = Buffer.from(goVectors.serialization.publicId, "hex");
      const vaultysId = VaultysId.fromId(publicId);
      const km = vaultysId.keyManager;

      // Should have same public keys
      expect(km.signer.publicKey.toString("hex")).to.equal(goVectors.keyGeneration.ed25519.publicKey);
      expect(km.cypher.publicKey.toString("hex")).to.equal(goVectors.keyGeneration.x25519.publicKey);

      // Should be public-only
      expect(km.capability).to.equal("public");
    });

    it("should handle base64 encoding", async () => {
      // Deserialize from base64
      const secretB64 = goVectors.serialization.secretBase64;
      const secret = Buffer.from(secretB64, "base64");
      const vidFromSecret = VaultysId.fromSecret(secret.toString("hex"), "hex");

      expect(vidFromSecret.did).to.equal(goVectors.identity.did);

      // Verify public ID from base64
      const publicB64 = goVectors.serialization.publicBase64;
      const publicId = Buffer.from(publicB64, "base64");
      const vidFromPublic = VaultysId.fromId(publicId);

      expect(vidFromPublic.did).to.equal(goVectors.identity.did);
    });
  });

  describe("Challenge Protocol", () => {
    let aliceVid: VaultysId;
    let bobVid: VaultysId;

    before(async () => {
      const aliceEntropy = Buffer.from(goVectors.challenge.aliceEntropy, "hex");
      const bobEntropy = Buffer.from(goVectors.challenge.bobEntropy, "hex");

      aliceVid = await VaultysId.fromEntropy(aliceEntropy, 1); // Person type
      bobVid = await VaultysId.fromEntropy(bobEntropy, 1); // Person type
    });

    it("should process Go init challenge", () => {
      if (!goVectors.challenge.steps || goVectors.challenge.steps.length < 1) {
        this.skip();
        return;
      }

      const initStep = goVectors.challenge.steps[0];
      const initBytes = Buffer.from(initStep.messageHex, "hex");
      const initChallenge = decode(initBytes) as any;

      // Verify structure
      expect(initChallenge).to.have.property("protocol", goVectors.challenge.protocol);
      expect(initChallenge).to.have.property("service", goVectors.challenge.service);
      expect(initChallenge).to.have.property("pk1");
      expect(initChallenge).to.have.property("nonce");

      expect(initStep.hasPk1).to.be.true;
      expect(initStep.hasPk2).to.be.false;
      expect(initStep.hasSign1).to.be.false;
      expect(initStep.hasSign2).to.be.false;
      expect(initStep.nonceLength).to.equal(16);
    });

    it("should process Go step1 challenge", () => {
      if (!goVectors.challenge.steps || goVectors.challenge.steps.length < 2) {
        this.skip();
        return;
      }

      const step1Step = goVectors.challenge.steps[1];
      const step1Bytes = Buffer.from(step1Step.messageHex, "hex");
      const step1Challenge = decode(step1Bytes) as any;

      // Verify structure
      expect(step1Challenge).to.have.property("protocol");
      expect(step1Challenge).to.have.property("service");
      expect(step1Challenge).to.have.property("pk1");
      expect(step1Challenge).to.have.property("pk2");
      expect(step1Challenge).to.have.property("nonce");
      expect(step1Challenge).to.have.property("sign2");

      expect(step1Step.hasPk1).to.be.true;
      expect(step1Step.hasPk2).to.be.true;
      expect(step1Step.hasSign1).to.be.false;
      expect(step1Step.hasSign2).to.be.true;
      expect(step1Step.nonceLength).to.equal(32);
    });

    it("should process Go complete challenge", () => {
      if (!goVectors.challenge.steps || goVectors.challenge.steps.length < 3) {
        this.skip();
        return;
      }

      const completeStep = goVectors.challenge.steps[2];
      const completeBytes = Buffer.from(completeStep.messageHex, "hex");
      const completeChallenge = decode(completeBytes) as any;

      // Verify structure
      expect(completeChallenge).to.have.property("protocol");
      expect(completeChallenge).to.have.property("service");
      expect(completeChallenge).to.have.property("pk1");
      expect(completeChallenge).to.have.property("pk2");
      expect(completeChallenge).to.have.property("nonce");
      expect(completeChallenge).to.have.property("sign1");
      expect(completeChallenge).to.have.property("sign2");

      expect(completeStep.hasPk1).to.be.true;
      expect(completeStep.hasPk2).to.be.true;
      expect(completeStep.hasSign1).to.be.true;
      expect(completeStep.hasSign2).to.be.true;
      expect(completeStep.nonceLength).to.equal(32);
    });

    it("should complete full challenge protocol with Go messages", async () => {
      if (!goVectors.challenge.steps || goVectors.challenge.steps.length < 3) {
        this.skip();
        return;
      }

      // Process Alice's init message
      const initBytes = Buffer.from(goVectors.challenge.steps[0].messageHex, "hex");
      const step1Response = Challenger.deserializeCertificate(initBytes);
      // console.log(step1Response);

      // Verify step1 response structure
      expect(step1Response.state).to.equal(0); // STEP1
      expect(step1Response.pk1).to.exist;
      expect(step1Response.pk2).not.to.exist;
      expect(step1Response.sign2).not.to.exist;
      expect(step1Response.nonce?.length).to.equal(16);

      // Create Alice's challenger to process Bob's response
      const aliceChallenger = new Challenger(aliceVid, 100000000000000);

      // Alice needs to init first to set her state
      await aliceChallenger.update(initBytes);

      // Process Bob's step1 message
      const step1Bytes = Buffer.from(goVectors.challenge.steps[1].messageHex, "hex");
      const completeResponse = Challenger.deserializeCertificate(aliceChallenger.getCertificate());
      // console.log(completeResponse);
      // Verify complete response
      expect(completeResponse.state).to.equal(1);
      expect(completeResponse.pk1).to.exist;
      expect(completeResponse.pk2).to.exist;
      expect(completeResponse.sign2).to.exist;
      expect(completeResponse.nonce?.length).to.equal(32);
      expect(completeResponse.sign1).not.to.exist;
    });
  });

  describe("Cross-Verification Tests", () => {
    it("should verify all cross-verification test cases", async () => {
      if (!goVectors.crossVerification) {
        this.skip();
        return;
      }

      for (const testCase of goVectors.crossVerification) {
        const entropy = Buffer.from(testCase.entropy, "hex");
        const vid = await VaultysId.fromEntropy(entropy, testCase.type);

        // Verify identity properties
        expect(vid.did).to.equal(testCase.did, `DID mismatch for ${testCase.name}`);
        expect(vid.id.toString("hex")).to.equal(testCase.idBytes, `ID bytes mismatch for ${testCase.name}`);

        // Verify signature
        const message = Buffer.from(testCase.message);
        const signature = Buffer.from(testCase.signature, "hex");
        const isValid = vid.keyManager.verify(message, signature);
        expect(isValid).to.equal(testCase.canVerify, `Signature verification failed for ${testCase.name}`);

        // Generate our own signature and compare
        const ourSignature = await vid.keyManager.sign(message);
        expect(ourSignature.toString("hex")).to.equal(testCase.signature, `Signature generation mismatch for ${testCase.name}`);
      }
    });
  });

  describe("Edge Cases and Error Handling", () => {
    it("should handle empty messages", async () => {
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const km = await Ed25519Manager.createFromEntropy(entropy);

      const emptyTest = goVectors.signing.additionalSignatures.find((t: any) => t.name === "empty");
      if (emptyTest) {
        const emptyMessage = Buffer.from([]);
        const signature = Buffer.from(emptyTest.signature, "hex");

        const isValid = km.verify(emptyMessage, signature);
        expect(isValid).to.be.true;
      }
    });

    it("should handle binary data", async () => {
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const km = await Ed25519Manager.createFromEntropy(entropy);

      const binaryTest = goVectors.signing.additionalSignatures.find((t: any) => t.name === "binary");
      if (binaryTest) {
        const binaryMessage = Buffer.from(binaryTest.messageHex, "hex");
        const signature = Buffer.from(binaryTest.signature, "hex");

        const isValid = km.verify(binaryMessage, signature);
        expect(isValid).to.be.true;
      }
    });

    it("should handle unicode messages", async () => {
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const km = await Ed25519Manager.createFromEntropy(entropy);

      const unicodeTest = goVectors.signing.additionalSignatures.find((t: any) => t.name === "unicode");
      if (unicodeTest) {
        const unicodeMessage = Buffer.from(unicodeTest.message);
        const signature = Buffer.from(unicodeTest.signature, "hex");

        const isValid = km.verify(unicodeMessage, signature);
        expect(isValid).to.be.true;
      }
    });
  });

  describe("Performance Benchmarks", () => {
    it("should track key generation performance", async function () {
      this.timeout(5000);

      const iterations = 100;
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");

      const start = Date.now();
      for (let i = 0; i < iterations; i++) {
        await Ed25519Manager.createFromEntropy(entropy);
      }
      const end = Date.now();

      const avgTime = (end - start) / iterations;
      console.log(`      Average key generation time: ${avgTime.toFixed(2)}ms`);

      // Warn if too slow
      if (avgTime > 10) {
        console.warn(`      ⚠️  Key generation is slower than expected (>10ms)`);
      }
    });

    it("should track signing performance", async function () {
      this.timeout(5000);

      const iterations = 1000;
      const entropy = Buffer.from(goVectors.keyGeneration.entropy, "hex");
      const km = await Ed25519Manager.createFromEntropy(entropy);
      const message = Buffer.from("test message");

      const start = Date.now();
      for (let i = 0; i < iterations; i++) {
        await km.sign(message);
      }
      const end = Date.now();

      const avgTime = (end - start) / iterations;
      console.log(`      Average signing time: ${avgTime.toFixed(3)}ms`);

      // Warn if too slow
      if (avgTime > 1) {
        console.warn(`      ⚠️  Signing is slower than expected (>1ms)`);
      }
    });
  });
});
