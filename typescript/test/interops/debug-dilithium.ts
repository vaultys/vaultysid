import DilithiumManager from "../../src/KeyManager/DilithiumManager";
import { decode } from "@msgpack/msgpack";
import { Buffer } from "buffer/";

async function debugDilithium() {
  console.log("=== Debugging Dilithium Manager Format ===\n");

  // Generate a Dilithium manager
  const manager = await DilithiumManager.generate();

  // Check ID format
  console.log("1. ID Analysis:");
  const idBuffer = manager.id;
  console.log(`   - ID length: ${idBuffer.length} bytes`);
  console.log(`   - ID (hex, first 100): ${idBuffer.toString("hex").substring(0, 100)}...`);

  try {
    const idDecoded = decode(idBuffer) as any;
    console.log(`   - ID decoded keys: ${Object.keys(idDecoded).join(", ")}`);
    console.log(`   - ID.v (version): ${idDecoded.v}`);
    console.log(`   - ID.x (signer public key) length: ${idDecoded.x ? idDecoded.x.length : "missing"} bytes`);
    console.log(`   - ID.e (cypher public key) length: ${idDecoded.e ? idDecoded.e.length : "missing"} bytes`);
  } catch (e: any) {
    console.log(`   - Error decoding ID: ${e.message}`);
  }

  // Check Secret format
  console.log("\n2. Secret Analysis:");
  const secretBuffer = manager.getSecret();
  console.log(`   - Secret length: ${secretBuffer.length} bytes`);
  console.log(`   - Secret (hex, first 100): ${secretBuffer.toString("hex").substring(0, 100)}...`);

  try {
    const secretDecoded = decode(secretBuffer) as any;
    console.log(`   - Secret decoded keys: ${Object.keys(secretDecoded).join(", ")}`);
    console.log(`   - Secret.v (version): ${secretDecoded.v}`);
    console.log(`   - Secret.s (seed) length: ${secretDecoded.s ? secretDecoded.s.length : "missing"} bytes`);
    console.log(`   - Secret.sk (secret key) length: ${secretDecoded.sk ? secretDecoded.sk.length : "missing"} bytes`);
    console.log(`   - Secret.pk (public key) length: ${secretDecoded.pk ? secretDecoded.pk.length : "missing"} bytes`);
  } catch (e: any) {
    console.log(`   - Error decoding secret: ${e.message}`);
  }

  // Check raw properties
  console.log("\n3. Raw Manager Properties:");
  console.log(`   - manager.signer.publicKey length: ${manager.signer.publicKey ? manager.signer.publicKey.length : "missing"}`);
  console.log(`   - manager.signer.secretKey exists: ${manager.signer.secretKey ? "yes" : "no"}`);
  if (manager.signer.secretKey) {
    console.log(`   - manager.signer.secretKey length: ${manager.signer.secretKey.length}`);
  }
  console.log(`   - manager.cypher.publicKey length: ${manager.cypher.publicKey ? manager.cypher.publicKey.length : "missing"}`);
  console.log(`   - manager.cypher.secretKey exists: ${manager.cypher.secretKey ? "yes" : "no"}`);
  console.log(`   - manager.seed exists: ${(manager as any).seed ? "yes" : "no"}`);
  if ((manager as any).seed) {
    console.log(`   - manager.seed length: ${(manager as any).seed.length}`);
  }
  console.log(`   - manager.version: ${manager.version}`);

  // Test signature
  console.log("\n4. Signature Test:");
  const message = Buffer.from("Test message");
  const signature = await manager.getSigner().then(s => s.sign(message));
  console.log(`   - Message: "${message.toString()}"`);
  console.log(`   - Signature length: ${signature ? signature.length : "null"} bytes`);
  const isValid = manager.verify(message, signature!, false);
  console.log(`   - Verification: ${isValid ? "✓ Valid" : "✗ Invalid"}`);

  // Create from secret and verify
  console.log("\n5. Secret Round-trip Test:");
  const secret = manager.getSecret();
  const restored = DilithiumManager.fromSecret(secret);
  console.log(`   - Restored manager created: yes`);
  console.log(`   - Restored ID matches: ${Buffer.compare(restored.id, manager.id) === 0 ? "✓ Yes" : "✗ No"}`);
  console.log(`   - Restored public key matches: ${Buffer.compare(restored.signer.publicKey, manager.signer.publicKey) === 0 ? "✓ Yes" : "✗ No"}`);

  // Create from ID and verify
  console.log("\n6. ID Round-trip Test:");
  const id = manager.id;
  const publicOnly = DilithiumManager.fromId(id);
  console.log(`   - Public-only manager created: yes`);
  console.log(`   - Public key matches: ${Buffer.compare(publicOnly.signer.publicKey, manager.signer.publicKey) === 0 ? "✓ Yes" : "✗ No"}`);
  console.log(`   - Has secret key: ${publicOnly.signer.secretKey ? "✗ Yes (should be no)" : "✓ No"}`);

  // Can verify signature with public-only
  const canVerify = publicOnly.verify(message, signature!, false);
  console.log(`   - Can verify signature: ${canVerify ? "✓ Yes" : "✗ No"}`);
}

debugDilithium().catch(console.error);
