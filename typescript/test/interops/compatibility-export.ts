import VaultysId from "../../src/VaultysId";
import Ed25519Manager from "../../src/KeyManager/Ed25519Manager";
import DilithiumManager from "../../src/KeyManager/DilithiumManager";
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
  const machineId = await VaultysId.generateMachine("ed25519");
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
  const manager1 = new IdManager(await VaultysId.generatePerson("dilithium"), MemoryStorage());
  const manager2 = new IdManager(await VaultysId.generatePerson("ed25519"), MemoryStorage());

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

  // Test 13: Dilithium Person ID
  console.log("\n13. Generating Person ID with DilithiumManager...");
  const dilithiumPerson = await VaultysId.generatePerson("dilithium");
  const dilithiumPersonData = {
    type: "person",
    idType: dilithiumPerson.type,
    id: dilithiumPerson.id,
    idHex: dilithiumPerson.id.toString("hex"),
    did: dilithiumPerson.did,
    fingerprint: dilithiumPerson.fingerprint,
    secret: dilithiumPerson.getSecret(),
  };
  fs.writeFileSync(path.join(outputDir, "person-dilithium.json"), JSON.stringify(dilithiumPersonData, null, 2));
  console.log(`  ID length: ${dilithiumPerson.id.length} bytes (Dilithium has larger keys)`);
  console.log(`  DID: ${dilithiumPersonData.did}`);

  // Test 14: Dilithium Machine ID
  console.log("\n14. Generating Machine ID with DilithiumManager...");
  const dilithiumMachine = await VaultysId.generateMachine("dilithium");
  const dilithiumMachineData = {
    type: "machine",
    idType: dilithiumMachine.type,
    id: dilithiumMachine.id,
    idHex: dilithiumMachine.id.toString("hex"),
    did: dilithiumMachine.did,
    fingerprint: dilithiumMachine.fingerprint,
    secret: dilithiumMachine.getSecret(),
  };
  fs.writeFileSync(path.join(outputDir, "machine-dilithium.json"), JSON.stringify(dilithiumMachineData, null, 2));
  console.log(`  ID length: ${dilithiumMachine.id.length} bytes`);
  console.log(`  DID: ${dilithiumMachineData.did}`);

  // Test 15: Dilithium Organization ID
  console.log("\n15. Generating Organization ID with DilithiumManager...");
  const dilithiumOrg = await VaultysId.generateOrganization("dilithium");
  const dilithiumOrgData = {
    type: "organization",
    idType: dilithiumOrg.type,
    id: dilithiumOrg.id,
    idHex: dilithiumOrg.id.toString("hex"),
    did: dilithiumOrg.did,
    fingerprint: dilithiumOrg.fingerprint,
    secret: dilithiumOrg.getSecret(),
  };
  fs.writeFileSync(path.join(outputDir, "organization-dilithium.json"), JSON.stringify(dilithiumOrgData, null, 2));
  console.log(`  ID length: ${dilithiumOrg.id.length} bytes`);
  console.log(`  DID: ${dilithiumOrgData.did}`);

  // Test 16: Dilithium signature
  console.log("\n16. Testing Dilithium signature...");
  const dilithiumChallenge = Buffer.from("Quantum-resistant signature test!");
  const dilithiumSignature = await dilithiumPerson.signChallenge(dilithiumChallenge);
  const dilithiumResult = hash("sha256", Buffer.concat([Buffer.from("VAULTYS_SIGN", "utf8"), dilithiumChallenge]));
  const dilithiumChallengeData = {
    challenge: dilithiumChallenge.toString("hex"),
    challengeText: dilithiumChallenge.toString("utf8"),
    result: dilithiumResult.toString("hex"),
    signature: dilithiumSignature.toString("hex"),
    signatureLength: dilithiumSignature.length,
    idUsed: dilithiumPersonData.idHex,
  };
  fs.writeFileSync(path.join(outputDir, "challenge-signature-dilithium.json"), JSON.stringify(dilithiumChallengeData, null, 2));
  console.log(`  Challenge: ${dilithiumChallengeData.challengeText}`);
  console.log(`  Signature length: ${dilithiumChallengeData.signatureLength} bytes (Dilithium ~2420 bytes)`);

  // Test 17: Direct DilithiumManager test
  console.log("\n17. Testing DilithiumManager directly...");
  const dilithiumManager = await DilithiumManager.generate();
  const dilithiumManagerData = {
    id: dilithiumManager.id.toString("hex"),
    secret: dilithiumManager.getSecret().toString("hex"),
    signerPublicKey: dilithiumManager.signer.publicKey.toString("hex"),
    signerPublicKeyLength: dilithiumManager.signer.publicKey.length,
    cypherPublicKey: dilithiumManager.cypher.publicKey.toString("hex"),
    version: dilithiumManager.version,
  };
  fs.writeFileSync(path.join(outputDir, "dilithium-manager.json"), JSON.stringify(dilithiumManagerData, null, 2));
  console.log(`  Manager ID length: ${dilithiumManager.id.length} bytes`);
  console.log(`  Signer Public Key length: ${dilithiumManagerData.signerPublicKeyLength} bytes`);

  // Test 18: Cross-algorithm interoperability (Ed25519 <-> Dilithium)
  console.log("\n18. Testing Ed25519 <-> Dilithium interoperability...");
  const ed25519Alice = await Ed25519Manager.generate();
  const dilithiumBob = await DilithiumManager.generate();

  // Both use X25519 for encryption, so DH should work
  const sharedSecretEd25519ToDilithium = await ed25519Alice.performDiffieHellman(dilithiumBob);
  const sharedSecretDilithiumToEd25519 = await dilithiumBob.performDiffieHellman(ed25519Alice);

  const crossAlgorithmData = {
    ed25519Id: ed25519Alice.id.toString("hex"),
    ed25519Secret: ed25519Alice.getSecret().toString("hex"),
    dilithiumId: dilithiumBob.id.toString("hex"),
    dilithiumSecret: dilithiumBob.getSecret().toString("hex"),
    sharedSecretEd25519ToDilithium: sharedSecretEd25519ToDilithium?.toString("hex"),
    sharedSecretDilithiumToEd25519: sharedSecretDilithiumToEd25519?.toString("hex"),
    secretsMatch: sharedSecretEd25519ToDilithium?.toString("hex") === sharedSecretDilithiumToEd25519?.toString("hex"),
  };
  fs.writeFileSync(path.join(outputDir, "cross-algorithm-dh.json"), JSON.stringify(crossAlgorithmData, null, 2));
  console.log(`  Ed25519 ID length: ${ed25519Alice.id.length} bytes`);
  console.log(`  Dilithium ID length: ${dilithiumBob.id.length} bytes`);
  console.log(`  Shared secrets match: ${crossAlgorithmData.secretsMatch}`);

  // Test 19: IdManager with Dilithium
  console.log("\n19. Testing IdManager with Dilithium...");
  const dilithiumIdManager = new IdManager(dilithiumPerson, MemoryStorage());
  dilithiumIdManager.name = "Charlie (Quantum-Resistant)";
  dilithiumIdManager.email = "charlie@quantum.example";

  const dilithiumIdManagerData = {
    id: dilithiumIdManager.vaultysId.id.toString("hex"),
    idLength: dilithiumIdManager.vaultysId.id.length,
    secret: dilithiumIdManager.vaultysId.getSecret(),
    secretLength: dilithiumIdManager.vaultysId.getSecret().length,
    did: dilithiumIdManager.vaultysId.did,
    name: dilithiumIdManager.name,
    email: dilithiumIdManager.email,
    displayName: dilithiumIdManager.displayName,
  };
  fs.writeFileSync(path.join(outputDir, "idmanager-dilithium.json"), JSON.stringify(dilithiumIdManagerData, null, 2));
  console.log(`  Manager DID: ${dilithiumIdManagerData.did}`);
  console.log(`  ID length: ${dilithiumIdManagerData.idLength} bytes`);
  console.log(`  Secret length: ${dilithiumIdManagerData.secretLength} bytes`);

  // Create a summary file
  const summary = {
    generatedAt: new Date().toISOString(),
    description: "Test data for TypeScript-Rust compatibility testing with Ed25519 and Dilithium",
    files: ["person-ed25519.json", "machine-ed25519.json", "organization-ed25519.json", "person-dilithium.json", "machine-dilithium.json", "organization-dilithium.json", "custom-entropy.json", "challenge-signature.json", "challenge-signature-dilithium.json", "ed25519-manager.json", "dilithium-manager.json", "deprecated-manager.json", "diffie-hellman.json", "cross-algorithm-dh.json", "idmanager-basic.json", "idmanager-dilithium.json", "srp-protocol.json", "file-encryption.json", "contact-storage.json"],
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
