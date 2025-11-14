import VaultysId from "../../src/VaultysId";
import Ed25519Manager from "../../src/KeyManager/Ed25519Manager";
import DeprecatedKeyManager from "../../src/KeyManager/DeprecatedKeyManager";
import IdManager from "../../src/IdManager";
import { MemoryChannel } from "../../src/MemoryChannel";
import { hash } from "../../src/crypto";
import { Buffer } from "buffer/";
import * as fs from "fs";
import * as path from "path";
import { MemoryStorage } from "../../src/MemoryStorage";

async function exportTestData() {
  console.log("Generating TypeScript test data for Rust compatibility...\n");

  // Create output directory
  const outputDir = path.join(__dirname, "compatibility-data");
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  // Test 1: Generate Person ID with Ed25519Manager
  console.log("1. Generating Person ID with Ed25519Manager...");
  const personId = await VaultysId.generatePerson();
  const personData = {
    type: "person",
    idType: personId.type,
    id: personId.id,
    idHex: personId.id.toString("hex"),
    did: personId.did,
    fingerprint: personId.fingerprint,
    secret: personId.getSecret(),
  };
  fs.writeFileSync(path.join(outputDir, "person-ed25519.json"), JSON.stringify(personData, null, 2));
  console.log(`  ID (hex): ${personData.idHex}`);
  console.log(`  DID: ${personData.did}`);
  console.log(`  Fingerprint: ${personData.fingerprint}`);

  // Test 2: Generate Machine ID with Ed25519Manager
  console.log("\n2. Generating Machine ID with Ed25519Manager...");
  const machineId = await VaultysId.generateMachine();
  const machineData = {
    type: "machine",
    idType: machineId.type,
    id: machineId.id,
    idHex: machineId.id.toString("hex"),
    did: machineId.did,
    fingerprint: machineId.fingerprint,
    secret: machineId.getSecret(),
  };
  fs.writeFileSync(path.join(outputDir, "machine-ed25519.json"), JSON.stringify(machineData, null, 2));
  console.log(`  ID (hex): ${machineData.idHex}`);
  console.log(`  DID: ${machineData.did}`);

  // Test 3: Generate Organization ID
  console.log("\n3. Generating Organization ID with Ed25519Manager...");
  const orgId = await VaultysId.generateOrganization();
  const orgData = {
    type: "organization",
    idType: orgId.type,
    id: orgId.id,
    idHex: orgId.id.toString("hex"),
    did: orgId.did,
    fingerprint: orgId.fingerprint,
    secret: orgId.getSecret(),
  };
  fs.writeFileSync(path.join(outputDir, "organization-ed25519.json"), JSON.stringify(orgData, null, 2));
  console.log(`  ID (hex): ${orgData.idHex}`);
  console.log(`  DID: ${orgData.did}`);

  // Test 4: Create ID from specific entropy
  console.log("\n4. Creating ID from specific entropy...");
  const entropy = Buffer.from("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "hex");
  const customId = await VaultysId.machineFromEntropy(entropy);
  const customData = {
    type: "machine",
    idType: customId.type,
    entropy: entropy.toString("hex"),
    id: customId.id,
    idHex: customId.id.toString("hex"),
    did: customId.did,
    fingerprint: customId.fingerprint,
    secret: customId.getSecret(),
  };
  fs.writeFileSync(path.join(outputDir, "custom-entropy.json"), JSON.stringify(customData, null, 2));
  console.log(`  Entropy: ${customData.entropy}`);
  console.log(`  ID (hex): ${customData.idHex}`);
  console.log(`  DID: ${customData.did}`);

  // Test 5: Sign and verify a challenge
  console.log("\n5. Testing challenge signing...");
  const challenge = Buffer.from("Hello, VaultysId Compatibility Test!");
  const signature = await personId.signChallenge(challenge);
  const result = hash("sha256", Buffer.concat([Buffer.from("VAULTYS_SIGN", "utf8"), challenge]));
  const challengeData = {
    challenge: challenge.toString("hex"),
    challengeText: challenge.toString("utf8"),
    result: result.toString("hex"),
    signature: signature.toString("hex"),
    idUsed: personData.idHex,
  };
  fs.writeFileSync(path.join(outputDir, "challenge-signature.json"), JSON.stringify(challengeData, null, 2));
  console.log(`  Challenge: ${challengeData.challengeText}`);
  console.log(`  Signature: ${challengeData.signature}`);

  // Test 6: Direct Ed25519Manager test
  console.log("\n6. Testing Ed25519Manager directly...");
  const ed25519Manager = await Ed25519Manager.generate();
  const ed25519Data = {
    id: ed25519Manager.id.toString("hex"),
    secret: ed25519Manager.getSecret().toString("hex"),
    signerPublicKey: ed25519Manager.signer.publicKey.toString("hex"),
    cypherPublicKey: ed25519Manager.cypher.publicKey.toString("hex"),
    version: ed25519Manager.version,
  };
  fs.writeFileSync(path.join(outputDir, "ed25519-manager.json"), JSON.stringify(ed25519Data, null, 2));
  console.log(`  Manager ID: ${ed25519Data.id}`);
  console.log(`  Signer Public Key: ${ed25519Data.signerPublicKey}`);

  // Test 7: DeprecatedKeyManager test
  console.log("\n7. Testing DeprecatedKeyManager...");
  const deprecatedManager = await DeprecatedKeyManager.generate_Id25519();
  const deprecatedData = {
    id: deprecatedManager.id.toString("hex"),
    secret: deprecatedManager.getSecret().toString("hex"),
    signerPublicKey: deprecatedManager.signer.publicKey.toString("hex"),
    cypherPublicKey: deprecatedManager.cypher.publicKey.toString("hex"),
    proof: deprecatedManager.proof?.toString("hex"),
    version: deprecatedManager.version,
  };
  fs.writeFileSync(path.join(outputDir, "deprecated-manager.json"), JSON.stringify(deprecatedData, null, 2));
  console.log(`  Manager ID: ${deprecatedData.id}`);
  console.log(`  Proof: ${deprecatedData.proof}`);

  // Test 8: Diffie-Hellman key exchange
  console.log("\n8. Testing Diffie-Hellman key exchange...");
  const alice = await Ed25519Manager.generate();
  const bob = await Ed25519Manager.generate();
  const sharedSecretAlice = await alice.performDiffieHellman(bob);
  const dhData = {
    aliceId: alice.id.toString("hex"),
    aliceSecret: alice.getSecret().toString("hex"),
    bobId: bob.id.toString("hex"),
    bobSecret: bob.getSecret().toString("hex"),
    sharedSecret: sharedSecretAlice?.toString("hex"),
  };
  fs.writeFileSync(path.join(outputDir, "diffie-hellman.json"), JSON.stringify(dhData, null, 2));
  console.log(`  Shared Secret: ${dhData.sharedSecret}`);

  // Test 9: IdManager creation and basic operations
  console.log("\n9. Testing IdManager basic operations...");
  const idManager1 = new IdManager(personId, MemoryStorage());
  idManager1.name = "Alice";
  idManager1.email = "alice@example.com";
  idManager1.phone = "+1234567890";

  const idManagerData = {
    id: idManager1.vaultysId.id.toString("hex"),
    secret: idManager1.vaultysId.getSecret(),
    did: idManager1.vaultysId.did,
    name: idManager1.name,
    email: idManager1.email,
    phone: idManager1.phone,
    displayName: idManager1.displayName,
    protocolVersion: idManager1.protocol_version,
  };
  fs.writeFileSync(path.join(outputDir, "idmanager-basic.json"), JSON.stringify(idManagerData, null, 2));
  console.log(`  Manager DID: ${idManagerData.did}`);
  console.log(`  Display Name: ${idManagerData.displayName}`);

  // Test 10: IdManager SRP Protocol Messages
  console.log("\n10. Generating SRP protocol test messages...");
  const manager1 = new IdManager(await VaultysId.generatePerson(), MemoryStorage());
  const manager2 = new IdManager(await VaultysId.generatePerson(), MemoryStorage());

  manager1.name = "Alice";
  manager2.name = "Bob";

  const channel = new MemoryChannel();

  // Capture the initial SRP message
  const srpMessages = {
    manager1: {
      id: manager1.vaultysId.id.toString("hex"),
      did: manager1.vaultysId.did,
      name: manager1.name,
      secret: manager1.vaultysId.getSecret(),
    },
    manager2: {
      id: manager2.vaultysId.id.toString("hex"),
      did: manager2.vaultysId.did,
      name: manager2.name,
      secret: manager2.vaultysId.getSecret(),
    },
    protocol: "SRP",
    service: "authentication",
    version: 1,
  };
  fs.writeFileSync(path.join(outputDir, "srp-protocol.json"), JSON.stringify(srpMessages, null, 2));
  console.log(`  Alice DID: ${srpMessages.manager1.did}`);
  console.log(`  Bob DID: ${srpMessages.manager2.did}`);

  // Test 11: File encryption/decryption test data
  console.log("\n11. Testing file encryption...");
  const testFile = {
    name: "test.txt",
    type: "text/plain",
    arrayBuffer: Buffer.from("Hello, this is a test file for encryption!"),
  };

  const encryptedFile = await idManager1.encryptFile(testFile);
  const fileEncryptionData = {
    original: {
      name: testFile.name,
      type: testFile.type,
      content: testFile.arrayBuffer.toString("hex"),
      contentText: testFile.arrayBuffer.toString("utf8"),
    },
    encrypted: encryptedFile?.arrayBuffer.toString("hex"),
    encryptedLength: encryptedFile?.arrayBuffer.length,
    managerId: idManager1.vaultysId.id.toString("hex"),
    managerSecret: idManager1.vaultysId.getSecret(),
  };
  fs.writeFileSync(path.join(outputDir, "file-encryption.json"), JSON.stringify(fileEncryptionData, null, 2));
  console.log(`  Original size: ${testFile.arrayBuffer.length} bytes`);
  console.log(`  Encrypted size: ${encryptedFile?.arrayBuffer.length} bytes`);

  // Test 12: Contact storage format
  console.log("\n12. Testing contact storage...");
  const contact = await VaultysId.generatePerson();

  idManager1.saveContact(contact);
  const contacts = idManager1.contacts;

  const contactData = {
    saved: contact,
    retrieved:
      contacts.length > 0
        ? {
            did: contacts[0].did,
          }
        : null,
  };
  fs.writeFileSync(path.join(outputDir, "contact-storage.json"), JSON.stringify(contactData, null, 2));
  console.log(`  Contact DID: ${contact.did}`);
  console.log(`  Contacts count: ${contacts.length}`);

  // Create a summary file
  const summary = {
    generatedAt: new Date().toISOString(),
    description: "Test data for TypeScript-Rust compatibility testing",
    files: ["person-ed25519.json", "machine-ed25519.json", "organization-ed25519.json", "custom-entropy.json", "challenge-signature.json", "ed25519-manager.json", "deprecated-manager.json", "diffie-hellman.json", "idmanager-basic.json", "srp-protocol.json", "file-encryption.json", "contact-storage.json"],
  };
  fs.writeFileSync(path.join(outputDir, "summary.json"), JSON.stringify(summary, null, 2));

  console.log(`\n✅ Test data exported to: ${outputDir}`);
  console.log("   Run the Rust compatibility test to verify interoperability.");
}

// Run the export
exportTestData().catch((error) => {
  console.error("Error generating test data:", error);
  process.exit(1);
});
