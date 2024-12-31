import assert from "assert";
import { randomBytes } from "crypto";
import KeyManager, { publicDerivePath, privateDerivePath, HISCP } from "../src/KeyManager";
import * as bip32 from "@stricahq/bip32ed25519";
import { VaultysId } from "../dist";

// @ts-expect-error weird import for @stricahq/bip32ed25519
const bip32fix = bip32.default ?? bip32;

const writeVector = (km: KeyManager) => {
  return;

  console.log("## NOT Published");
  console.log("### proof sk:\n", new bip32fix.Bip32PrivateKey(km.proofKey.secretKey!).toPrivateKey().toBytes().toString("hex"));
  console.log("### proof pk:\n", new bip32fix.Bip32PrivateKey(km.proofKey.publicKey).toBip32PublicKey().toPublicKey().toBytes().toString("hex"));
  console.log("### sk = derive(proof sk, m/0'):\n", new bip32fix.Bip32PrivateKey(km.signer.secretKey!).toPrivateKey().toBytes().toString("hex"));

  console.log("## Published");
  console.log("### proof = sha256(proof pk):\n", km.proof.toString("hex"));
  console.log("### pk:", km.signer.publicKey.toString("hex"));
};

const writeCertificate = (hiscp: HISCP) => {
  return;
  const hiscpDisplay = {
    newId: hiscp.newId.toString("hex"),
    proofKey: hiscp.proofKey.toString("hex"),
    timestamp: hiscp.timestamp,
  };
  console.log("## HISCP Certificate");
  console.log("### hiscp data:\n", JSON.stringify(hiscpDisplay, null, 2));
  console.log("### Signature of hiscp = [newID || proofKey || timestamp] by proof sk\n", hiscp.signature.toString("hex"));
};

describe("KeyManager tests", () => {
  it("derive correctly keys (strica)", async () => {
    const node = await bip32fix.Bip32PrivateKey.fromEntropy(randomBytes(32));
    const publicNode = node.toBip32PublicKey();
    const derivedNode = privateDerivePath(node, "m/1/2/3");
    const publicDerivedNode = publicDerivePath(publicNode, "m/1/2/3");
    assert.equal(derivedNode.toBip32PublicKey().toBytes().toString("hex"), publicDerivedNode.toBytes().toString("hex"));
  });

  // it("derive correctly keys (noble)", async () => {
  //   const privateKey = ed.utils.randomPrivateKey();
  //   const node = await Bip32PrivateKey.fromEntropy(randomBytes(32));
  //   const publicNode = node.toBip32PublicKey();
  //   const derivedNode = derivePath(node, "1/2/3");
  //   const publicDerivedNode = derivePath(publicNode, "m/1/2/3");
  //   assert.equal(derivedNode.toBip32PublicKey().toBytes().toString("hex"), publicDerivedNode.toBytes().toString("hex"));
  // });

  it("serder a KeyManager losing entropy", async () => {
    const km = await KeyManager.generate_Id25519();
    const secret = km.getSecret();
    const km2 = KeyManager.fromSecret(secret);
    assert.equal(km.id.toString("hex"), km2.id.toString("hex"));
  });

  it("serder a private KeyManager to a public KeyManager", async () => {
    const km = await KeyManager.generate_Id25519();
    const id = km.id;
    const publicKM = KeyManager.fromId(id);
    assert.equal(id.toString("hex"), publicKM.id.toString("hex"));
  });

  it("sign and verify a message", async () => {
    const signer = await KeyManager.generate_Id25519();
    const id = signer.id;
    const verifier = KeyManager.fromId(id);
    const message = Buffer.from("this is a message to be verified man", "utf-8");
    const signature = await signer.sign(message);
    if (!signature) assert.fail();
    assert.notEqual(signature, null);
    assert.ok(verifier.verify(message, signature));
  });

  it("create and verify a HISCP Certificate", async () => {
    const km = await KeyManager.generate_Id25519();
    const hiscp = await km.createSwapingCertificate();
    if (!hiscp) assert.fail();
    const publicKM = KeyManager.fromId(km.id);
    publicKM.verifySwapingCertificate(hiscp);
    assert.ok(publicKM.verifySwapingCertificate(hiscp));
  });

  it("create vector for HISCP", async () => {
    const km = await KeyManager.generate_Id25519();
    writeVector(km);
    const hiscp = await km.createSwapingCertificate();
    if (!hiscp) assert.fail();
    writeCertificate(hiscp);
    const publicKM = KeyManager.fromId(km.id);
    publicKM.verifySwapingCertificate(hiscp);
    assert.ok(publicKM.verifySwapingCertificate(hiscp));
  });

  it("create vector for HISCP Certificate Chaining", async () => {
    const km = await KeyManager.generate_Id25519();
    writeVector(km);
    const hiscp = await km.createSwapingCertificate();
    if (!hiscp) assert.fail();
    writeCertificate(hiscp);
    const publicKM = KeyManager.fromId(km.id);
    publicKM.verifySwapingCertificate(hiscp);
    assert.ok(publicKM.verifySwapingCertificate(hiscp));

    // create the new Keymanager iterating on the index
    if (!km.entropy) assert.fail();
    const newkm = await KeyManager.create_Id25519_fromEntropy(km.entropy, 1);
    assert.equal(newkm.id.toString("hex"), hiscp?.newId.toString("hex"));
  });

  it("signcrypt and decrypt messages", async () => {
    const alice = await KeyManager.generate_Id25519();
    const bob = await KeyManager.generate_Id25519();
    const eve = await KeyManager.generate_Id25519();
    const plaintext = "This message is authentic!";
    const recipients = [bob.id, eve.id, alice.id];
    const ENCRYPTED = await alice.signcrypt(plaintext, recipients);
    if (!ENCRYPTED) assert.fail();
    assert.equal(ENCRYPTED.substring(0, 33), "BEGIN SALTPACK ENCRYPTED MESSAGE.");
    if (!ENCRYPTED) assert.fail();
    const decryptedBob = await bob.decrypt(ENCRYPTED, alice.id);
    const decryptedEve = await eve.decrypt(ENCRYPTED, alice.id);
    const decryptedAlice = await alice.decrypt(ENCRYPTED, alice.id);
    assert.equal(decryptedEve, plaintext);
    assert.equal(decryptedEve, decryptedBob);
    assert.equal(decryptedEve, decryptedAlice);
  });

  it("encrypt and decrypt messages", async () => {
    const alice = await KeyManager.generate_Id25519();
    const bob = await KeyManager.generate_Id25519();
    const eve = await KeyManager.generate_Id25519();
    const plaintext = "This message is authentic!";
    const recipients = [bob.id, eve.id, alice.id];
    const ENCRYPTED = await KeyManager.encrypt(plaintext, recipients);
    if (!ENCRYPTED) assert.fail();
    assert.equal(ENCRYPTED.substring(0, 33), "BEGIN SALTPACK ENCRYPTED MESSAGE.");
    if (!ENCRYPTED) assert.fail();
    const decryptedBob = await bob.decrypt(ENCRYPTED);
    const decryptedEve = await eve.decrypt(ENCRYPTED);
    const decryptedAlice = await alice.decrypt(ENCRYPTED);
    assert.equal(decryptedEve, plaintext);
    assert.equal(decryptedEve, decryptedBob);
    assert.equal(decryptedEve, decryptedAlice);
  });

  it("signcrypt and blind decrypt messages", async () => {
    const alice = await KeyManager.generate_Id25519();
    const bob = await KeyManager.generate_Id25519();
    const eve = await KeyManager.generate_Id25519();
    const plaintext = "This message is authentic!";
    const recipients = [bob.id, eve.id, alice.id];
    const ENCRYPTED = await alice.signcrypt(plaintext, recipients);
    if (!ENCRYPTED) assert.fail();
    assert.equal(ENCRYPTED.substring(0, 33), "BEGIN SALTPACK ENCRYPTED MESSAGE.");
    const decryptedBob = await bob.decrypt(ENCRYPTED);
    const decryptedEve = await eve.decrypt(ENCRYPTED);
    const decryptedAlice = await alice.decrypt(ENCRYPTED);
    assert.equal(decryptedEve, plaintext);
    assert.equal(decryptedEve, decryptedBob);
    assert.equal(decryptedEve, decryptedAlice);
  });

  it("VaultysId: signcrypt and decrypt messages", async () => {
    const alice = await VaultysId.generatePerson();
    const bob = await VaultysId.generateMachine();
    const eve = await VaultysId.generateOrganization();
    const plaintext = "This message is authentic!";
    const recipients = [bob.id, eve.id, alice.id];
    const ENCRYPTED = await alice.signcrypt(plaintext, recipients);
    if (!ENCRYPTED) assert.fail();
    assert.equal(ENCRYPTED.substring(0, 33), "BEGIN SALTPACK ENCRYPTED MESSAGE.");
    if (!ENCRYPTED) assert.fail();
    const decryptedBob = await bob.decrypt(ENCRYPTED, alice.id);
    const decryptedEve = await eve.decrypt(ENCRYPTED, alice.id);
    const decryptedAlice = await alice.decrypt(ENCRYPTED, alice.id);
    assert.equal(decryptedEve, plaintext);
    assert.equal(decryptedEve, decryptedBob);
    assert.equal(decryptedEve, decryptedAlice);
  });

  it("VaultysId: encrypt and decrypt messages", async () => {
    const alice = await VaultysId.generatePerson();
    const bob = await VaultysId.generateMachine();
    const eve = await VaultysId.generateOrganization();
    const plaintext = "This message is authentic!";
    const recipients = [bob.id, eve.id, alice.id];
    const ENCRYPTED = await VaultysId.encrypt(plaintext, recipients);
    if (!ENCRYPTED) assert.fail();
    assert.equal(ENCRYPTED.substring(0, 33), "BEGIN SALTPACK ENCRYPTED MESSAGE.");
    if (!ENCRYPTED) assert.fail();
    const decryptedBob = await bob.decrypt(ENCRYPTED);
    const decryptedEve = await eve.decrypt(ENCRYPTED);
    const decryptedAlice = await alice.decrypt(ENCRYPTED);
    assert.equal(decryptedEve, plaintext);
    assert.equal(decryptedEve, decryptedBob);
    assert.equal(decryptedEve, decryptedAlice);
  });

  it("VaultysId: signcrypt and blind decrypt messages", async () => {
    const alice = await VaultysId.generatePerson();
    const bob = await VaultysId.generateMachine();
    const eve = await VaultysId.generateOrganization();
    const plaintext = "This message is authentic!";
    const recipients = [bob.id, eve.id, alice.id];
    const ENCRYPTED = await alice.signcrypt(plaintext, recipients);
    if (!ENCRYPTED) assert.fail();
    assert.equal(ENCRYPTED.substring(0, 33), "BEGIN SALTPACK ENCRYPTED MESSAGE.");
    const decryptedBob = await bob.decrypt(ENCRYPTED);
    const decryptedEve = await eve.decrypt(ENCRYPTED);
    const decryptedAlice = await alice.decrypt(ENCRYPTED);
    assert.equal(decryptedEve, plaintext);
    assert.equal(decryptedEve, decryptedBob);
    assert.equal(decryptedEve, decryptedAlice);
  });

  it("Decrypt a sample encrypted message", async () => {
    const message = "BEGIN SALTPACK ENCRYPTED MESSAGE. keDIDMQWYvVR58B FTfTeD305lGzPUD Z8BRVEgGXzcjJWB UefZGlwlo9LZtuR Q1KxD1dDReRrFIb 0E0SQdmaBQYHx9R oCVcbFhChzVlNdn 82WpOddWUOChb8I 1R9N6WJJ0wDzdtf 5eNbHvEmWyMd2xw 7NbmAq4nmhxIUxJ Wf2EVXbNNQcpQtu brSHcdqzRPtlNhz 3o7Gi8tCV3y0FZ2I61ads82FMhOe7M 8VAZIEKeeigWrUu bvZLjmHB0jlkqz2 6Pm6HMpawR38XCP vLBbB9phSyb7ShU hgyimdfO6shNe01 sCkCKfeXh99M8lC F8yR49B33BhV547 rEI2MYR2wepXPm3 Poo1Xa8UMEZufGC JiOpRBmYgOPz3h. END SALTPACK ENCRYPTED MESSAGE.";
    const id = VaultysId.fromSecret("", "base64");
    const decrypted = await id.decrypt(message);
    assert.equal(decrypted, "test");
  });
});
