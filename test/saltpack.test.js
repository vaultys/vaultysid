import VaultysId from "../src/VaultysId.js";
import assert from "assert";

describe("Saltpack", () => {
  it("Saltpack working with ID", async () => {
    const alice = await VaultysId.generatePerson();
    const bob = await VaultysId.generatePerson();
    const eve = await VaultysId.generatePerson();
    const plaintext = "This message is authentic!";
    const recipients = [bob.id, JSON.parse(JSON.stringify(eve.id)), alice.id.toString("hex")];
    const encrypted = await alice.encrypt(plaintext, recipients);
    assert.equal(
      encrypted.substring(0, 33),
      "BEGIN SALTPACK ENCRYPTED MESSAGE.",
    );
    const decryptedBob = await bob.decrypt(encrypted, alice.id);
    const decryptedEve = await eve.decrypt(encrypted, alice.id);
    const decryptedAlice = await alice.decrypt(encrypted, JSON.parse(JSON.stringify(alice.id)));
    assert.equal(decryptedEve, plaintext);
    assert.equal(decryptedEve, decryptedBob);
    assert.equal(decryptedEve, decryptedAlice);
  });
});
