import assert from "assert";
import { Buffer } from "buffer/";
import { randomBytes } from "crypto";
import { publicDerivePath, privateDerivePath, HISCP } from "../src/KeyManager";
import * as bip32 from "@stricahq/bip32ed25519";
import { VaultysId, KeyManager } from "../";
import { createRandomVaultysId } from "./utils";
import { encryptAndArmor } from "@samuelthomas2774/saltpack";
import nacl from "tweetnacl";

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
    const alice = await createRandomVaultysId();
    const bob = await createRandomVaultysId();
    const eve = await createRandomVaultysId();
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
    const alice = await createRandomVaultysId();
    const bob = await createRandomVaultysId();
    const eve = await createRandomVaultysId();
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
    const alice = await createRandomVaultysId();
    const bob = await createRandomVaultysId();
    const eve = await createRandomVaultysId();
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
    // const bob = await createRandomVaultysId();
    // console.log(await VaultysId.encrypt("test", [bob.id]));
    // console.log(bob.getSecret("base64"));
    const message = "BEGIN SALTPACK ENCRYPTED MESSAGE. keDIDMQWYvVR58B FTfTeD305hcoHcr Wi4X4pWBmPExHwE WaBDIrIPJ7pgJVE 2Yaxiu3jYK3Osf2 uhjKjQeNaUshMjT QrZdWGFObOEKXZS u5ZF9IyxzRQiBF8 vtIJhLH1kKcDJj4 IQGkhxNTmUljHeo ulEUOyGRt0K3CrR gVkJxxehI8H0GJy 0iJTgCMM7DEX4Jk qmUWofh3hNbfZcs G171PLnJVJ484sS ozpRNJIRMYpHD4g lEdwwVM3NfIoSW3 Cg6FKTrtiNoDgtN gvXoqM96taPvEal dAjNjMgXFcuPT2b U0CFssYXxGKzAnJ gevNrFwrZGLd78h. END SALTPACK ENCRYPTED MESSAGE.";
    const id = VaultysId.fromSecret("AIShdgGhcMQg3KBa7NhKclRHgvQL/51gDBKkVt9ndZurKDM+wDY4uBSheMRgIEM+lQwxORCD8hOul7keOXea5fMYYghYYL2inBxdB1Uop0p+SGS0ju18I7OOTiMDGGKo7wzTR0xj5xxE9qpTHqHAbWi6fPFaYOXNTK1t6NwVTiNkJDrvqK1OvVrzHnOGoWXEIJRd5AQLlhofk5h7yIGMHzJt5kWUX/J+sTH4gQhGtW1S", "base64");
    const decrypted = await id.decrypt(message);
    assert.equal(decrypted, "test");
  });

  it("should perform Diffie-Hellman key exchange between two KeyManager instances", async () => {
    // Create two key managers
    const alice = await KeyManager.generate_Id25519();
    const bob = await KeyManager.generate_Id25519();

    // Alice performs DH with Bob
    const aliceSharedSecret = await alice.performDiffieHellman(bob);

    // Bob performs DH with Alice
    const bobSharedSecret = await bob.performDiffieHellman(alice);

    // Verify that they derived the same shared secret
    assert.notEqual(aliceSharedSecret, null);
    assert.notEqual(bobSharedSecret, null);
    assert.equal(aliceSharedSecret?.toString("hex"), bobSharedSecret?.toString("hex"));
  });

  it("should perform Diffie-Hellman key exchange using static method", async () => {
    // Create two key managers
    const alice = await KeyManager.generate_Id25519();
    const bob = await KeyManager.generate_Id25519();

    // Perform DH using static method
    const sharedSecret1 = await KeyManager.diffieHellman(alice, bob);
    const sharedSecret2 = await KeyManager.diffieHellman(bob, alice);

    // Verify that the static method derives the same shared secret regardless of order
    assert.notEqual(sharedSecret1, null);
    assert.notEqual(sharedSecret2, null);
    assert.equal(sharedSecret1?.toString("hex"), sharedSecret2?.toString("hex"));
  });

  it("should fail Diffie-Hellman key exchange with a public KeyManager", async () => {
    // Create two key managers
    const alice = await KeyManager.generate_Id25519();
    const bobPrivate = await KeyManager.generate_Id25519();

    // Create a public-only version of Bob's KeyManager
    const bobPublic = KeyManager.fromId(bobPrivate.id);

    // Alice attempts DH with Bob's public KeyManager (should fail)
    const aliceSharedSecret = await alice.performDiffieHellman(bobPublic);

    // Bob's public KeyManager attempts DH with Alice (should fail)
    const bobSharedSecret = await bobPublic.performDiffieHellman(alice);

    // Verify that the operations failed
    // assert.equal(aliceSharedSecret, null);
    assert.equal(bobSharedSecret, null);
  });

  it("should be able to use DH shared secret for encryption and decryption", async () => {
    // Create two key managers
    const alice = await KeyManager.generate_Id25519();
    const bob = await KeyManager.generate_Id25519();

    // Perform DH to get shared secret
    const aliceSharedSecret = await alice.performDiffieHellman(bob);
    assert.notEqual(aliceSharedSecret, null);

    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    // Use the shared secret for encryption (using a simple XOR for demonstration)
    const plaintext = Buffer.from("Secret message for testing", "utf-8");

    const encryptedMessage = nacl.secretbox(plaintext, nonce, aliceSharedSecret!);

    // Bob also derives the shared secret
    const bobSharedSecret = await bob.performDiffieHellman(alice);
    assert.notEqual(bobSharedSecret, null);

    // Bob decrypts the message
    const decryptedMessage = Buffer.from(nacl.secretbox.open(encryptedMessage, nonce, bobSharedSecret!)!);

    // Verify the decrypted message matches the original
    assert.equal(decryptedMessage.toString("utf-8"), plaintext.toString("utf-8"));
  });

  it("should generate different shared secrets with different key pairs", async () => {
    // Create three key managers
    const alice = await KeyManager.generate_Id25519();
    const bob = await KeyManager.generate_Id25519();
    const charlie = await KeyManager.generate_Id25519();

    // Alice-Bob shared secret
    const secretAB = await alice.performDiffieHellman(bob);

    // Alice-Charlie shared secret
    const secretAC = await alice.performDiffieHellman(charlie);

    // Bob-Charlie shared secret
    const secretBC = await bob.performDiffieHellman(charlie);

    // Verify all shared secrets are different
    assert.notEqual(secretAB?.toString("hex"), secretAC?.toString("hex"));
    assert.notEqual(secretAB?.toString("hex"), secretBC?.toString("hex"));
    assert.notEqual(secretAC?.toString("hex"), secretBC?.toString("hex"));
  });
});
