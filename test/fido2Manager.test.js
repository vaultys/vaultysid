import Fido2Manager from "../src/Fido2Manager.js";
import SoftCredentials from "../src/SoftCredentials.js";
import assert from "assert";
import VaultysId from "../src/VaultysId.js";

// nodejs polyfill
global.navigator = {
  credentials: SoftCredentials,
};
global.atob = (str) => Buffer.from(str, "base64").toString("latin1");
global.btoa = (str) => Buffer.from(str, "latin1").toString("base64");

global.CredentialUserInteractionRequest = () => global.CredentialUserInteractionRequested++

describe("Fido2Manager", () => {
  it("serder a Fido2Manager (ECDSA)", async () => {
    const attestation = await navigator.credentials.create(
      SoftCredentials.createRequest(-7),
    );
    const f2m = await Fido2Manager.createFromAttestation(attestation);
    const secret = f2m.getSecret();
    const f2mbis = Fido2Manager.fromSecret(secret);
    assert.equal(f2m.id.toString("hex"), f2mbis.id.toString("hex"));
  });

  it("serder a VaultysId backed by a Fido2Manager (EdDSA)", async () => {
    const attestation = await navigator.credentials.create(
      SoftCredentials.createRequest(-7),
    );
    const id1 = await VaultysId.fido2FromAttestation(attestation);
    const id2 = VaultysId.fromId(id1.id);
    assert.deepStrictEqual(id1.didDocument, id2.didDocument);
  });

  it("serder a VaultysId backed by a Fido2Manager (EcDSA)", async () => {
    const attestation = await navigator.credentials.create(
      SoftCredentials.createRequest(-8),
    );
    const id1 = await VaultysId.fido2FromAttestation(attestation);
    const id2 = VaultysId.fromId(id1.id);
    assert.deepStrictEqual(id1.didDocument, id2.didDocument);
  });

  it("serder a private Fido2Manager to a public Fido2Manager (EdDSA)", async () => {
    const attestation = await navigator.credentials.create(
      SoftCredentials.createRequest(-8),
    );
    const f2m = await Fido2Manager.createFromAttestation(attestation);
    const publicF2m = Fido2Manager.fromId(f2m.id);
    assert.equal(f2m.id.toString("hex"), publicF2m.id.toString("hex"));
  });

  it("sign and verify a message using EdDSA", async () => {
    global.CredentialUserInteractionRequested = 0
    const attestation = await navigator.credentials.create(
      SoftCredentials.createRequest(-8),
    );
    const signer = await Fido2Manager.createFromAttestation(attestation);
    const id = signer.id;
    const verifier = Fido2Manager.fromId(id);
    const message = Buffer.from(
      "this is a message to be verified man",
      "utf-8",
    );
    const signature = await signer.sign(message);
    assert.equal(CredentialUserInteractionRequested, 1);
    assert.ok(verifier.verify(message, signature));
  });

  it("sign and verify a message using ECDSA", async () => {
    global.CredentialUserInteractionRequested = 0
    const attestation = await navigator.credentials.create(
      SoftCredentials.createRequest(-7),
    );
    const signer = await Fido2Manager.createFromAttestation(attestation);
    const id = signer.id;
    const verifier = Fido2Manager.fromId(id);
    const message = Buffer.from(
      "this is a message to be verified man",
      "utf-8",
    );
    const signature = await signer.sign(message);
    assert.equal(CredentialUserInteractionRequested, 1);
    assert.ok(await verifier.verify(message, signature));
  });

  it("encrypt and decrypt messages (mixing ECDSA and EdDSA for id)", async () => {
    const attestation1 = await navigator.credentials.create(
      SoftCredentials.createRequest(-7),
    );
    const attestation2 = await navigator.credentials.create(
      SoftCredentials.createRequest(-8),
    );
    const attestation3 = await navigator.credentials.create(
      SoftCredentials.createRequest(-7),
    );
    const alice = await Fido2Manager.createFromAttestation(attestation1);
    const bob = await Fido2Manager.createFromAttestation(attestation2);
    const eve = await Fido2Manager.createFromAttestation(attestation3);
    const plaintext = "This message is authentic!";
    const recipients = [bob.id, eve.id, alice.id];
    const encrypted = await alice.encrypt(plaintext, recipients);
    assert.equal(
      encrypted.substring(0, 33),
      "BEGIN SALTPACK ENCRYPTED MESSAGE.",
    );
    const decryptedBob = await bob.decrypt(encrypted, alice.id);
    const decryptedEve = await eve.decrypt(encrypted, alice.id);
    const decryptedAlice = await alice.decrypt(encrypted, alice.id);
    assert.equal(decryptedEve, plaintext);
    assert.equal(decryptedEve, decryptedBob);
    assert.equal(decryptedEve, decryptedAlice);
  });

  it("encrypt and blind decrypt messages", async () => {
    const attestation1 = await navigator.credentials.create(
      SoftCredentials.createRequest(-7),
    );
    const attestation2 = await navigator.credentials.create(
      SoftCredentials.createRequest(-8),
    );
    const attestation3 = await navigator.credentials.create(
      SoftCredentials.createRequest(-7),
    );
    const alice = await Fido2Manager.createFromAttestation(attestation1);
    const bob = await Fido2Manager.createFromAttestation(attestation2);
    const eve = await Fido2Manager.createFromAttestation(attestation3);
    const plaintext = "This message is authentic!";
    const recipients = [bob.id, eve.id, alice.id];
    const encrypted = await alice.encrypt(plaintext, recipients);
    assert.equal(
      encrypted.substring(0, 33),
      "BEGIN SALTPACK ENCRYPTED MESSAGE.",
    );
    const decryptedBob = await bob.decrypt(encrypted);
    const decryptedEve = await eve.decrypt(encrypted);
    const decryptedAlice = await alice.decrypt(encrypted);
    assert.equal(decryptedEve, plaintext);
    assert.equal(decryptedEve, decryptedBob);
    assert.equal(decryptedEve, decryptedAlice);
  });
});
