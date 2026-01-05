import { Buffer } from "buffer/";
import VaultysId from "../src/VaultysId";
import Fido2Manager from "../src/KeyManager/Fido2Manager";
import SoftCredentials from "../src/platform/SoftCredentials";
import { encode } from "@msgpack/msgpack";
import cbor from "cbor";
import nacl from "tweetnacl";
import fs from "fs";
import path from "path";

// Initialize mock WebAuthn environment
import "./shims";

interface TestVector {
  name: string;
  description: string;
  data: any;
}

class FIDO2TestVectorGenerator {
  private vectors: TestVector[] = [];

  async generateAll() {
    console.log("Generating FIDO2 test vectors...\n");

    // Test 1: Ed25519 FIDO2Manager serialization
    await this.generateEd25519Serialization();

    // Test 2: P-256 FIDO2Manager serialization
    await this.generateP256Serialization();

    // Test 3: VaultysId with FIDO2 backend
    await this.generateVaultysIdFIDO2();

    // Test 4: FIDO2 signature verification
    await this.generateSignatureVerification();

    // Test 5: Diffie-Hellman key exchange
    await this.generateDiffieHellman();

    // Test 6: Transport encoding
    this.generateTransportEncoding();

    // Test 7: COSE key formats
    this.generateCOSEKeyFormats();

    // Save vectors to file
    this.saveVectors();
  }

  private async generateEd25519Serialization() {
    console.log("1. Generating Ed25519 FIDO2Manager serialization vectors...");

    // Create an Ed25519 FIDO2 authenticator
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    const f2m = await Fido2Manager.createFromAttestation(attestation as any);

    // Get secret and ID
    const secret = f2m.getSecret();
    const id = f2m.id;

    // Create public-only version
    const publicF2m = Fido2Manager.fromId(id);

    this.vectors.push({
      name: "ed25519_serialization",
      description: "Ed25519 FIDO2Manager secret and ID serialization",
      data: {
        algorithm: "EdDSA",
        coseAlg: -8,
        keyType: "OKP",
        secret: {
          hex: secret.toString("hex"),
          base64: secret.toString("base64"),
          structure: {
            version: f2m.version,
            fid: f2m.fid.toString("base64"),
            transports: f2m._transports,
            ckey: f2m.ckey.toString("hex"),
            cypherSecret: f2m.cypher.secretKey?.toString("hex"),
          },
        },
        id: {
          hex: id.toString("hex"),
          base64: id.toString("base64"),
          structure: {
            version: publicF2m.version,
            ckey: publicF2m.ckey.toString("hex"),
            cypherPublic: publicF2m.cypher.publicKey.toString("hex"),
          },
        },
        authType: f2m.authType,
        encType: f2m.encType,
        publicKey: f2m.signer.publicKey.toString("hex"),
        cypherPublicKey: f2m.cypher.publicKey.toString("hex"),
      },
    });
  }

  private async generateP256Serialization() {
    console.log("2. Generating P-256 FIDO2Manager serialization vectors...");

    // Create a P-256 FIDO2 authenticator
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    const f2m = await Fido2Manager.createFromAttestation(attestation as any);

    const secret = f2m.getSecret();
    const id = f2m.id;

    this.vectors.push({
      name: "p256_serialization",
      description: "P-256 FIDO2Manager secret and ID serialization",
      data: {
        algorithm: "ES256",
        coseAlg: -7,
        keyType: "EC2",
        secret: {
          hex: secret.toString("hex"),
          base64: secret.toString("base64"),
          structure: {
            version: f2m.version,
            fid: f2m.fid.toString("base64"),
            transports: f2m._transports,
            ckey: f2m.ckey.toString("hex"),
            cypherSecret: f2m.cypher.secretKey?.toString("hex"),
          },
        },
        id: {
          hex: id.toString("hex"),
          base64: id.toString("base64"),
        },
        authType: f2m.authType,
        encType: f2m.encType,
        publicKey: f2m.signer.publicKey.toString("hex"),
        cypherPublicKey: f2m.cypher.publicKey.toString("hex"),
      },
    });
  }

  private async generateVaultysIdFIDO2() {
    console.log("3. Generating VaultysId FIDO2 vectors...");

    // Create Ed25519 FIDO2 VaultysId
    const attestationEd = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    const vidEd = await VaultysId.fido2FromAttestation(attestationEd as any);

    // Create P-256 FIDO2 VaultysId
    const attestationP256 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    const vidP256 = await VaultysId.fido2FromAttestation(attestationP256 as any);

    this.vectors.push({
      name: "vaultysid_fido2",
      description: "VaultysId with FIDO2 backend",
      data: {
        ed25519: {
          type: "fido2",
          typeValue: 3,
          id: {
            hex: vidEd.id.toString("hex"),
            base64: vidEd.id.toString("base64"),
          },
          secret: {
            hex: vidEd.getSecret("hex"),
            base64: vidEd.getSecret("base64"),
          },
          did: vidEd.did,
          fingerprint: vidEd.fingerprint,
          didDocument: vidEd.didDocument,
        },
        p256: {
          type: "fido2",
          typeValue: 3,
          id: {
            hex: vidP256.id.toString("hex"),
            base64: vidP256.id.toString("base64"),
          },
          secret: {
            hex: vidP256.getSecret("hex"),
            base64: vidP256.getSecret("base64"),
          },
          did: vidP256.did,
          fingerprint: vidP256.fingerprint,
          didDocument: vidP256.didDocument,
        },
      },
    });
  }

  private async generateSignatureVerification() {
    console.log("4. Generating signature verification vectors...");

    // Create a FIDO2 manager for signing
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    const signer = await Fido2Manager.createFromAttestation(attestation as any);

    // Test data
    const testData = Buffer.from("Test message for FIDO2 signature verification", "utf-8");

    // Sign the data
    const signature = await signer.sign(testData);

    if (signature) {
      // Decode the signature structure
      const decoded = encode({
        s: signature,
        c: Buffer.from([]), // Will be filled by actual signature
        a: Buffer.from([]), // Will be filled by actual signature
      });

      this.vectors.push({
        name: "signature_verification",
        description: "FIDO2 signature and verification data",
        data: {
          message: {
            utf8: testData.toString("utf-8"),
            hex: testData.toString("hex"),
            base64: testData.toString("base64"),
          },
          signature: {
            hex: signature.toString("hex"),
            base64: signature.toString("base64"),
            length: signature.length,
          },
          publicKey: signer.signer.publicKey.toString("hex"),
          coseKey: signer.ckey.toString("hex"),
          algorithm: signer.authType,
          verificationResult: signer.verify(testData, signature),
        },
      });
    }
  }

  private async generateDiffieHellman() {
    console.log("5. Generating Diffie-Hellman vectors...");

    // Create two FIDO2 managers
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    const alice = await Fido2Manager.createFromAttestation(attestation1 as any);

    const attestation2 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    const bob = await Fido2Manager.createFromAttestation(attestation2 as any);

    // Perform DH using VaultysId
    const vidAlice = await VaultysId.fido2FromAttestation(attestation1 as any);
    const vidBob = await VaultysId.fido2FromAttestation(attestation2 as any);

    const sharedSecret = await vidAlice.performDiffieHellman(vidBob);

    this.vectors.push({
      name: "diffie_hellman",
      description: "Diffie-Hellman key exchange between FIDO2 identities",
      data: {
        alice: {
          cypherPublic: alice.cypher.publicKey.toString("hex"),
          cypherSecret: alice.cypher.secretKey?.toString("hex"),
          did: vidAlice.did,
        },
        bob: {
          cypherPublic: bob.cypher.publicKey.toString("hex"),
          cypherSecret: bob.cypher.secretKey?.toString("hex"),
          did: vidBob.did,
        },
        sharedSecret: sharedSecret
          ? {
              hex: sharedSecret.toString("hex"),
              base64: sharedSecret.toString("base64"),
              length: sharedSecret.length,
            }
          : null,
      },
    });
  }

  private generateTransportEncoding() {
    console.log("6. Generating transport encoding vectors...");

    const transportTests = [
      { transports: ["usb"], value: 1 },
      { transports: ["nfc"], value: 2 },
      { transports: ["ble"], value: 4 },
      { transports: ["internal"], value: 8 },
      { transports: ["hybrid"], value: 16 },
      { transports: ["smart-card"], value: 32 },
      { transports: ["usb", "nfc"], value: 3 },
      { transports: ["usb", "nfc", "ble", "internal"], value: 15 },
      { transports: ["usb", "nfc", "ble", "internal", "hybrid"], value: 31 },
    ];

    this.vectors.push({
      name: "transport_encoding",
      description: "FIDO2 transport bitmask encoding",
      data: transportTests,
    });
  }

  private generateCOSEKeyFormats() {
    console.log("7. Generating COSE key format vectors...");

    // Ed25519 COSE key
    const ed25519PubKey = Buffer.from(
      Array(32)
        .fill(0)
        .map((_, i) => i),
    );
    const ed25519CoseKey = cbor.encode({
      1: 1, // kty: OKP
      3: -8, // alg: EdDSA
      [-2]: ed25519PubKey, // x: public key
    });

    // P-256 COSE key
    const p256X = Buffer.from(
      Array(32)
        .fill(0)
        .map((_, i) => i * 2),
    );
    const p256Y = Buffer.from(
      Array(32)
        .fill(0)
        .map((_, i) => i * 2 + 1),
    );
    const p256CoseKey = cbor.encode({
      1: 2, // kty: EC2
      3: -7, // alg: ES256
      [-1]: 1, // crv: P-256
      [-2]: p256X, // x coordinate
      [-3]: p256Y, // y coordinate
    });

    this.vectors.push({
      name: "cose_key_formats",
      description: "COSE key encodings for different algorithms",
      data: {
        ed25519: {
          raw: {
            kty: 1,
            alg: -8,
            x: ed25519PubKey.toString("hex"),
          },
          encoded: ed25519CoseKey.toString("hex"),
          decoded: cbor.decode(ed25519CoseKey),
        },
        p256: {
          raw: {
            kty: 2,
            alg: -7,
            crv: 1,
            x: p256X.toString("hex"),
            y: p256Y.toString("hex"),
          },
          encoded: p256CoseKey.toString("hex"),
          decoded: cbor.decode(p256CoseKey),
        },
      },
    });
  }

  private saveVectors() {
    const outputPath = path.join(__dirname, "fido2_test_vectors.json");
    const output = {
      generated: new Date().toISOString(),
      description: "FIDO2 interoperability test vectors for TypeScript <-> Go",
      vectors: this.vectors,
    };

    fs.writeFileSync(outputPath, JSON.stringify(output, null, 2));
    console.log(`\nTest vectors saved to: ${outputPath}`);

    // Also create a minified version for easier embedding in Go tests
    const minifiedPath = path.join(__dirname, "fido2_test_vectors.min.json");
    fs.writeFileSync(minifiedPath, JSON.stringify(output));
    console.log(`Minified vectors saved to: ${minifiedPath}`);
  }
}

// Run the generator
async function main() {
  const generator = new FIDO2TestVectorGenerator();
  await generator.generateAll();

  console.log("\n✅ Test vector generation complete!");
  console.log("You can now use these vectors in the Go implementation tests.");
}

main().catch(console.error);
