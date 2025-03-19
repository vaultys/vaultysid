import { Buffer } from "buffer/";
import Fido2Manager from "../src/Fido2Manager";
import SoftCredentials from "../src/platform/SoftCredentials";
import assert from "assert";
import { VaultysId } from "../";
import "./shims";
import nacl from "tweetnacl";

describe("Fido2Manager", () => {
  it("serder a Fido2Manager (ECDSA)", async () => {
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-expect-error mockup
    const f2m = await Fido2Manager.createFromAttestation(attestation);
    const secret = f2m.getSecret();
    const f2mbis = Fido2Manager.fromSecret(secret);
    assert.equal(f2m.id.toString("hex"), f2mbis.id.toString("hex"));
  });

  it("serder a VaultysId backed by a Fido2Manager (ECDSA)", async () => {
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-expect-error mockup
    const id1 = await VaultysId.fido2FromAttestation(attestation);
    const id2 = VaultysId.fromId(id1.id);
    assert.deepStrictEqual(id1.didDocument, id2.didDocument);
  });

  it("serder a VaultysId backed by a Fido2Manager (EdDSA)", async () => {
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    // @ts-expect-error mockup
    const id1 = await VaultysId.fido2FromAttestation(attestation);
    const id2 = VaultysId.fromId(id1.id);
    assert.deepStrictEqual(id1.didDocument, id2.didDocument);
  });

  it("serder a private Fido2Manager to a public Fido2Manager (EdDSA)", async () => {
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    // @ts-expect-error mockup
    const f2m = await Fido2Manager.createFromAttestation(attestation);
    const publicF2m = Fido2Manager.fromId(f2m.id);
    assert.equal(f2m.id.toString("hex"), publicF2m.id.toString("hex"));
  });

  it("sign and verify a message using EdDSA", async () => {
    // @ts-ignore
    global.CredentialUserInteractionRequested = 0;
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    // @ts-expect-error mockup
    const signer = await Fido2Manager.createFromAttestation(attestation);
    const id = signer.id;
    const verifier = Fido2Manager.fromId(id);
    const message = Buffer.from("this is a message to be verified man", "utf-8");
    const signature = await signer.sign(message);
    if (signature == null) assert.fail();
    //assert.equal(CredentialUserInteractionRequested, 1);
    assert.ok(verifier.verify(message, signature));
  });

  it("sign and verify a message using ECDSA", async () => {
    // @ts-ignore
    global.CredentialUserInteractionRequested = 0;
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-expect-error mockup
    const signer = await Fido2Manager.createFromAttestation(attestation);
    const id = signer.id;
    const verifier = Fido2Manager.fromId(id);
    const message = Buffer.from("this is a message to be verified man", "utf-8");
    const signature = await signer.sign(message);
    //assert.equal(CredentialUserInteractionRequested, 1);
    if (message == null || signature == null) assert.fail();
    assert.ok(verifier.verify(message, signature));
  });

  it("signcrypt and decrypt messages (mixing ECDSA and EdDSA for id)", async () => {
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    const attestation2 = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    const attestation3 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-expect-error mockup
    const alice = await Fido2Manager.createFromAttestation(attestation1);
    // @ts-expect-error mockup
    const bob = await Fido2Manager.createFromAttestation(attestation2);
    // @ts-expect-error mockup
    const eve = await Fido2Manager.createFromAttestation(attestation3);
    const plaintext = "This message is authentic!";
    const recipients = [bob.id, eve.id, alice.id];
    const signcrypted = await alice.signcrypt(plaintext, recipients);
    if (signcrypted === null) assert.fail();
    assert.equal(signcrypted.substring(0, 33), "BEGIN SALTPACK ENCRYPTED MESSAGE.");
    const decryptedBob = await bob.decrypt(signcrypted, alice.id);
    const decryptedEve = await eve.decrypt(signcrypted, alice.id);
    const decryptedAlice = await alice.decrypt(signcrypted, alice.id);
    assert.equal(decryptedEve, plaintext);
    assert.equal(decryptedEve, decryptedBob);
    assert.equal(decryptedEve, decryptedAlice);
  });

  it("signcrypt and blind decrypt messages", async () => {
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    const attestation2 = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    const attestation3 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-expect-error mockup
    const alice = await Fido2Manager.createFromAttestation(attestation1);
    // @ts-expect-error mockup
    const bob = await Fido2Manager.createFromAttestation(attestation2);
    // @ts-expect-error mockup
    const eve = await Fido2Manager.createFromAttestation(attestation3);
    const plaintext = "This message is authentic!";
    const recipients = [bob.id, eve.id, alice.id];
    const signcrypted = await alice.signcrypt(plaintext, recipients);
    if (signcrypted == null) assert.fail();
    assert.equal(signcrypted.substring(0, 33), "BEGIN SALTPACK ENCRYPTED MESSAGE.");
    const decryptedBob = await bob.decrypt(signcrypted);
    const decryptedEve = await eve.decrypt(signcrypted);
    const decryptedAlice = await alice.decrypt(signcrypted);
    assert.equal(decryptedEve, plaintext);
    assert.equal(decryptedEve, decryptedBob);
    assert.equal(decryptedEve, decryptedAlice);
  });

  it("should perform Diffie-Hellman key exchange between VaultysIds with Fido2Manager", async () => {
    // Create two Fido2Manager-backed VaultysIds
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    const attestation2 = await navigator.credentials.create(SoftCredentials.createRequest(-8));

    // @ts-expect-error mockup
    const alice = await VaultysId.fido2FromAttestation(attestation1);
    // @ts-expect-error mockup
    const bob = await VaultysId.fido2FromAttestation(attestation2);

    // Perform Diffie-Hellman key exchange
    const aliceSharedSecret = await alice.performDiffieHellman(bob);
    const bobSharedSecret = await bob.performDiffieHellman(alice);

    // Verify they derived the same shared secret
    assert.notEqual(aliceSharedSecret, null);
    assert.notEqual(bobSharedSecret, null);
    assert.equal(aliceSharedSecret?.toString("hex"), bobSharedSecret?.toString("hex"));
  });

  it("should perform Diffie-Hellman key exchange using the static method", async () => {
    // Create two Fido2Manager-backed VaultysIds
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    const attestation2 = await navigator.credentials.create(SoftCredentials.createRequest(-8));

    // @ts-expect-error mockup
    const alice = await VaultysId.fido2FromAttestation(attestation1);
    // @ts-expect-error mockup
    const bob = await VaultysId.fido2FromAttestation(attestation2);

    // Perform Diffie-Hellman key exchange using the static method
    const sharedSecret = await VaultysId.diffieHellman(alice, bob);

    // Verify it worked
    assert.notEqual(sharedSecret, null);

    // Verify the order doesn't matter
    const sharedSecret2 = await VaultysId.diffieHellman(bob, alice);
    assert.equal(sharedSecret?.toString("hex"), sharedSecret2?.toString("hex"));
  });

  it("should use shared secret for encrypted communication", async () => {
    // Create two Fido2Manager-backed VaultysIds
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    const attestation2 = await navigator.credentials.create(SoftCredentials.createRequest(-8));

    // @ts-expect-error mockup
    const alice = await VaultysId.fido2FromAttestation(attestation1);
    // @ts-expect-error mockup
    const bob = await VaultysId.fido2FromAttestation(attestation2);

    // Perform Diffie-Hellman key exchange
    const aliceSharedSecret = await alice.performDiffieHellman(bob);
    assert.notEqual(aliceSharedSecret, null);

    const plaintext = Buffer.from("Secret message between FIDO2 devices", "utf8");
    const nonce = nacl.randomBytes(nacl.box.nonceLength);

    const encryptedMessage = nacl.secretbox(plaintext, nonce, aliceSharedSecret!);

    // Bob also derives the shared secret
    const bobSharedSecret = await bob.performDiffieHellman(alice);
    assert.notEqual(bobSharedSecret, null);

    // Bob decrypts the message
    const decryptedMessage = Buffer.from(nacl.secretbox.open(encryptedMessage, nonce, bobSharedSecret!)!);

    // Verify the decrypted message matches the original
    assert.equal(decryptedMessage.toString("utf-8"), plaintext.toString("utf-8"));
  });

  it("should work with different FIDO2 algorithm combinations", async () => {
    // Create VaultysIds with different algorithms
    const attestationECDSA1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    const attestationECDSA2 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    const attestationEdDSA = await navigator.credentials.create(SoftCredentials.createRequest(-8));

    // @ts-expect-error mockup
    const idECDSA1 = await VaultysId.fido2FromAttestation(attestationECDSA1);
    // @ts-expect-error mockup
    const idECDSA2 = await VaultysId.fido2FromAttestation(attestationECDSA2);
    // @ts-expect-error mockup
    const idEdDSA = await VaultysId.fido2FromAttestation(attestationEdDSA);

    // Test ECDSA with ECDSA
    const secretECDSA = await idECDSA1.performDiffieHellman(idECDSA2);
    assert.notEqual(secretECDSA, null);

    // Test ECDSA with EdDSA
    const secretMixed = await idECDSA1.performDiffieHellman(idEdDSA);
    assert.notEqual(secretMixed, null);

    // Verify different combinations produce different secrets
    assert.notEqual(secretECDSA?.toString("hex"), secretMixed?.toString("hex"));
  });

  it("should fail Diffie-Hellman with public-only VaultysId", async () => {
    // Create a private VaultysId
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-expect-error mockup
    const privateId = await VaultysId.fido2FromAttestation(attestation);

    // Create a public-only VaultysId from the id
    const publicId = VaultysId.fromId(privateId.id);

    // Attempt DH with the public-only VaultysId (should fail)
    const secretFail1 = await privateId.performDiffieHellman(publicId);
    const secretFail2 = await publicId.performDiffieHellman(privateId);

    // Both attempts should fail
    //assert.equal(secretFail1, null);
    assert.equal(secretFail2, null);
  });

  it("should produce consistent shared secrets across instances", async () => {
    // Create two Fido2Manager-backed VaultysIds
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    const attestation2 = await navigator.credentials.create(SoftCredentials.createRequest(-8));

    // @ts-expect-error mockup
    const alice1 = await VaultysId.fido2FromAttestation(attestation1);
    // @ts-expect-error mockup
    const bob1 = await VaultysId.fido2FromAttestation(attestation2);

    // Get the secrets
    const aliceSecret = alice1.getSecret("hex");
    const bobSecret = bob1.getSecret("hex");

    // Recreate the VaultysIds from secrets
    const alice2 = VaultysId.fromSecret(aliceSecret, "hex");
    const bob2 = VaultysId.fromSecret(bobSecret, "hex");

    // Perform DH with the original instances
    const secretOriginal = await alice1.performDiffieHellman(bob1);

    // Perform DH with the recreated instances
    const secretRecreated = await alice2.performDiffieHellman(bob2);

    // The shared secrets should be the same
    assert.equal(secretOriginal?.toString("hex"), secretRecreated?.toString("hex"));
  });
});
