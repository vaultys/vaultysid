import Fido2Manager from "../src/Fido2Manager";
import SoftCredentials from "../src/SoftCredentials";
import assert from "assert";
import VaultysId from "../src/VaultysId";
import "./utils";

describe("Fido2Manager", () => {
  it("serder a Fido2Manager (ECDSA)", async () => {
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-ignore
    const f2m = await Fido2Manager.createFromAttestation(attestation);
    const secret = f2m.getSecret();
    const f2mbis = Fido2Manager.fromSecret(secret);
    assert.equal(f2m.id.toString("hex"), f2mbis.id.toString("hex"));
  });

  it("serder a VaultysId backed by a Fido2Manager (ECDSA)", async () => {
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-ignore
    const id1 = await VaultysId.fido2FromAttestation(attestation);
    const id2 = VaultysId.fromId(id1.id);
    assert.deepStrictEqual(id1.didDocument, id2.didDocument);
  });

  it("serder a VaultysId backed by a Fido2Manager (EdDSA)", async () => {
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    // @ts-ignore
    const id1 = await VaultysId.fido2FromAttestation(attestation);
    const id2 = VaultysId.fromId(id1.id);
    assert.deepStrictEqual(id1.didDocument, id2.didDocument);
  });

  it("serder a private Fido2Manager to a public Fido2Manager (EdDSA)", async () => {
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    // @ts-ignore
    const f2m = await Fido2Manager.createFromAttestation(attestation);
    const publicF2m = Fido2Manager.fromId(f2m.id);
    assert.equal(f2m.id.toString("hex"), publicF2m.id.toString("hex"));
  });

  it("sign and verify a message using EdDSA", async () => {
    // @ts-ignore
    global.CredentialUserInteractionRequested = 0;
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    // @ts-ignore
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
    // @ts-ignore
    const signer = await Fido2Manager.createFromAttestation(attestation);
    const id = signer.id;
    const verifier = Fido2Manager.fromId(id);
    const message = Buffer.from("this is a message to be verified man", "utf-8");
    const signature = await signer.sign(message);
    //assert.equal(CredentialUserInteractionRequested, 1);
    if (message == null || signature == null) assert.fail();
    assert.ok(verifier.verify(message, signature));
  });

  it("encrypt and decrypt messages (mixing ECDSA and EdDSA for id)", async () => {
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    const attestation2 = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    const attestation3 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-ignore
    const alice = await Fido2Manager.createFromAttestation(attestation1);
    // @ts-ignore
    const bob = await Fido2Manager.createFromAttestation(attestation2);
    // @ts-ignore
    const eve = await Fido2Manager.createFromAttestation(attestation3);
    const plaintext = "This message is authentic!";
    const recipients = [bob.id, eve.id, alice.id];
    const encrypted = await alice.encrypt(plaintext, recipients);
    if (encrypted == null) assert.fail();
    assert.equal(encrypted.substring(0, 33), "BEGIN SALTPACK ENCRYPTED MESSAGE.");
    const decryptedBob = await bob.decrypt(encrypted, alice.id);
    const decryptedEve = await eve.decrypt(encrypted, alice.id);
    const decryptedAlice = await alice.decrypt(encrypted, alice.id);
    assert.equal(decryptedEve, plaintext);
    assert.equal(decryptedEve, decryptedBob);
    assert.equal(decryptedEve, decryptedAlice);
  });

  it("encrypt and blind decrypt messages", async () => {
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    const attestation2 = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    const attestation3 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-ignore
    const alice = await Fido2Manager.createFromAttestation(attestation1);
    // @ts-ignore
    const bob = await Fido2Manager.createFromAttestation(attestation2);
    // @ts-ignore
    const eve = await Fido2Manager.createFromAttestation(attestation3);
    const plaintext = "This message is authentic!";
    const recipients = [bob.id, eve.id, alice.id];
    const encrypted = await alice.encrypt(plaintext, recipients);
    if (encrypted == null) assert.fail();
    assert.equal(encrypted.substring(0, 33), "BEGIN SALTPACK ENCRYPTED MESSAGE.");
    const decryptedBob = await bob.decrypt(encrypted);
    const decryptedEve = await eve.decrypt(encrypted);
    const decryptedAlice = await alice.decrypt(encrypted);
    assert.equal(decryptedEve, plaintext);
    assert.equal(decryptedEve, decryptedBob);
    assert.equal(decryptedEve, decryptedAlice);
  });
});
