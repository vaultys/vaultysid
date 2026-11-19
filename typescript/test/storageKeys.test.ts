import assert from "assert";
import { Buffer } from "buffer/";
import { IdManager, MemoryChannel, MemoryStorage, VaultysId } from "..";
import "./shims";
import { timestampedKey } from "../src/IdManager";

// Two certificates or two signatures stored in the same millisecond used to overwrite each other.

describe("IdManager storage keys", () => {
  it("keeps two certificates received in the same millisecond", async () => {
    const server = new IdManager(
      await VaultysId.generateMachine(),
      MemoryStorage(() => ""),
    );
    const realNow = Date.now;
    const now = realNow();
    Date.now = () => now;
    try {
      for (let i = 0; i < 2; i++) {
        const client = new IdManager(
          await VaultysId.generatePerson(),
          MemoryStorage(() => ""),
        );
        const channel = MemoryChannel.createBidirectionnal();
        await Promise.all([client.askContact(channel, {}), server.acceptContact(channel.otherend!, {})]);
      }
    } finally {
      Date.now = realNow;
    }
    assert.strictEqual(server.contacts.length, 2);
    assert.strictEqual(server.store.substore("wot").list().length, 2);
    assert.strictEqual(server.listCertificates().length, 2);
  });

  it("keeps two signatures made in the same millisecond", async () => {
    const manager = new IdManager(
      await VaultysId.generatePerson(),
      MemoryStorage(() => ""),
    );
    const realNow = Date.now;
    const now = realNow();
    Date.now = () => now;
    try {
      await manager.signChallenge(Buffer.from("one"));
      await manager.signChallenge(Buffer.from("two"));
    } finally {
      Date.now = realNow;
    }
    assert.strictEqual(manager.store.substore("signatures").list().length, 2);
  });

  it("starts with the timestamp, so keys still sort by date", () => {
    assert.match(timestampedKey(Buffer.from("x"), 1700000000000), /^1700000000000-[0-9a-f]{64}$/);
  });
});
