import assert from "assert";
import { Buffer } from "buffer/";
import { MemoryChannel, StreamChannel } from "../src/MemoryChannel";
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe("Channel tests", () => {
  it("send/receive", async () => {
    const channel = MemoryChannel.createEncryptedBidirectionnal();
    channel.send(Buffer.from("hello world", "utf-8"));
    const message = await channel.otherend?.receive();
    assert.equal("hello world", message?.toString("utf-8"));
  });
});
