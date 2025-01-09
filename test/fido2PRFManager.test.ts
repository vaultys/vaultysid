import Fido2PRFManager from "../src/Fido2PRFManager";
import SoftCredentials from "../src/SoftCredentials";
import assert from "assert";
import { VaultysId } from "../";
import "./utils";

describe("Fido2PRFManager", () => {
  it("serder a Fido2PRFManager (ECDSA)", async () => {
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-7, true));
    // @ts-expect-error mockup
    const f2m = await Fido2PRFManager.createFromAttestation(attestation);
    const secret = f2m.getSecret();
    const f2mbis = Fido2PRFManager.fromSecret(secret);
    assert.equal(f2m.id.toString("hex"), f2mbis.id.toString("hex"));
  });

  it("serder a VaultysId backed by a Fido2PRFManager (ECDSA)", async () => {
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-7, true));
    // @ts-expect-error mockup
    const id1 = await VaultysId.fido2FromAttestation(attestation);
    assert.equal(id1.type, 4);
    const id2 = VaultysId.fromId(id1.id);
    assert.deepStrictEqual(id1.didDocument, id2.didDocument);
  });

  it("serder a VaultysId backed by a Fido2PRFManager (EdDSA)", async () => {
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-8, true));
    // @ts-expect-error mockup
    const id1 = await VaultysId.fido2FromAttestation(attestation);
    const id2 = VaultysId.fromId(id1.id);
    assert.deepStrictEqual(id1.didDocument, id2.didDocument);
  });

  it("serder a private Fido2PRFManager to a public Fido2PRFManager (EdDSA)", async () => {
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-8, true));
    // @ts-expect-error mockup
    const f2m = await Fido2PRFManager.createFromAttestation(attestation);
    const publicF2m = Fido2PRFManager.fromId(f2m.id);
    assert.equal(f2m.id.toString("hex"), publicF2m.id.toString("hex"));
  });

  it("sign and verify a message using EdDSA", async () => {
    global.CredentialUserInteractionRequested = 0;
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-8, true));
    // @ts-expect-error mockup
    const signer = await Fido2PRFManager.createFromAttestation(attestation);
    const id = signer.id;
    const verifier = Fido2PRFManager.fromId(id);
    const message = Buffer.from("this is a message to be verified man", "utf-8");
    const signature = await signer.sign(message);
    if (signature == null) assert.fail();
    //assert.equal(CredentialUserInteractionRequested, 1);
    assert.ok(verifier.verify(message, signature));
  });

  it("sign and verify a message using ECDSA", async () => {
    global.CredentialUserInteractionRequested = 0;
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-7, true));
    // @ts-expect-error mockup
    const signer = await Fido2PRFManager.createFromAttestation(attestation);
    const id = signer.id;
    const verifier = Fido2PRFManager.fromId(id);
    const message = Buffer.from("this is a message to be verified man", "utf-8");
    const signature = await signer.sign(message);
    //assert.equal(CredentialUserInteractionRequested, 1);
    if (message == null || signature == null) assert.fail();
    assert.ok(verifier.verify(message, signature));
  });

  it("signcrypt and decrypt messages (mixing ECDSA and EdDSA for id)", async () => {
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7, true));
    const attestation2 = await navigator.credentials.create(SoftCredentials.createRequest(-8, true));
    const attestation3 = await navigator.credentials.create(SoftCredentials.createRequest(-7, true));
    // @ts-expect-error mockup
    const alice = await Fido2PRFManager.createFromAttestation(attestation1);
    // @ts-expect-error mockup
    const bob = await Fido2PRFManager.createFromAttestation(attestation2);
    // @ts-expect-error mockup
    const eve = await Fido2PRFManager.createFromAttestation(attestation3);
    const plaintext = "This message is authentic!";
    const recipients = [bob.id, eve.id, alice.id];
    // console.log(recipients);
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

  it("signcrypt and blind decrypt messages", async () => {
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7, true));
    const attestation2 = await navigator.credentials.create(SoftCredentials.createRequest(-8, true));
    const attestation3 = await navigator.credentials.create(SoftCredentials.createRequest(-7, true));
    // @ts-expect-error mockup
    const alice = await Fido2PRFManager.createFromAttestation(attestation1);
    // @ts-expect-error mockup
    const bob = await Fido2PRFManager.createFromAttestation(attestation2);
    // @ts-expect-error mockup
    const eve = await Fido2PRFManager.createFromAttestation(attestation3);
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
});
