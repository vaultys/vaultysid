import assert from "assert";
import VaultysId from "../src/VaultysId";
import { Buffer } from "buffer/";

describe("Test Vectors", () => {
  it("should generate and deserialize v3.x IDs", async () => {
    // Test Ed25519Manager format (77 bytes)
    const person = await VaultysId.generatePerson();
    const verifyID = VaultysId.fromId(person.id);
    assert(verifyID);
    assert.equal(verifyID.id.toString("base64"), person.id.toString("base64"));
  });

  it("should sign and verify with v3.x format", async () => {
    const person = await VaultysId.generatePerson();
    const message = "test message";

    const signature = await person.signChallenge(message);
    assert(signature);

    const verifyID = VaultysId.fromId(person.id);
    const verified = verifyID.verifyChallenge(message, signature, false);
    assert.equal(verified, true);
  });

  it("should handle different identity types", async () => {
    const person = await VaultysId.generatePerson();
    const org = await VaultysId.generateOrganization();
    const machine = await VaultysId.generateMachine();

    assert(VaultysId.fromId(person.id));
    assert(VaultysId.fromId(org.id));
    assert(VaultysId.fromId(machine.id));
  });
});
