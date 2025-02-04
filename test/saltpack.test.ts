import VaultysId from "../src/VaultysId";
import assert from "assert";

describe("Saltpack", () => {
  it("Saltpack working with ID", async () => {
    const alice = await VaultysId.generatePerson();
    const bob = await VaultysId.generatePerson();
    const eve = await VaultysId.generatePerson();
    const plaintext = "This message is authentic!";
    const recipients = [bob.id, eve.id, alice.id.toString("hex")];
    const encrypted = await alice.encrypt(plaintext, recipients);
    if (!encrypted) assert.fail();
    assert.equal(encrypted.substring(0, 33), "BEGIN SALTPACK ENCRYPTED MESSAGE.");
    const decryptedBob = await bob.decrypt(encrypted, alice.id);
    const decryptedEve = await eve.decrypt(encrypted);
    const decryptedAlice = await alice.decrypt(encrypted, alice.id);
    assert.equal(decryptedEve, plaintext);
    assert.equal(decryptedEve, decryptedBob);
    assert.equal(decryptedEve, decryptedAlice);
  });
});
