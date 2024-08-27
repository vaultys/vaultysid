import fs from "fs";
import crypto from "crypto";
import assert from "assert";
import { MemoryChannel, StreamChannel } from "../src/MemoryChannel";
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const hashFile = (name: string) => {
  const fileBuffer = fs.readFileSync(name);
  const hashSum = crypto.createHash("sha256");
  hashSum.update(fileBuffer);
  return hashSum.digest("hex");
};

describe("Channel tests", () => {
  it("send/receive", async () => {
    const channel = MemoryChannel.createEncryptedBidirectionnal();
    channel.send(Buffer.from("hello world", "utf-8"));
    const message = await channel.otherend?.receive();
    assert.equal("hello world", message?.toString("utf-8"));
  });

  it("stream file", async () => {
    const channel = MemoryChannel.createBidirectionnal();
    // channel.setLogger((data) => console.log(data, "->"));
    // channel.otherend!.setLogger((data) => console.log(data, "<-"));
    const { download } = StreamChannel(channel);
    const { upload } = StreamChannel(channel.otherend!);
    const input = fs.createReadStream("./test/assets/testfile.png", {
      highWaterMark: 1 * 1024,
    });
    const output = fs.createWriteStream("./test/assets/streamed_file.png", {
      highWaterMark: 1 * 1024,
    });
    await Promise.all([download(output), upload(input)]);
    const hash1 = hashFile("./test/assets/testfile.png");
    const hash2 = hashFile("./test/assets/streamed_file.png");
    assert.equal(hash1, hash2);
    fs.rmSync("./test/assets/streamed_file.png");
  });

  it("stream file over encrypted channel", async () => {
    const channel = MemoryChannel.createEncryptedBidirectionnal();
    const { download } = StreamChannel(channel);
    const { upload } = StreamChannel(channel.otherend!);
    const input = fs.createReadStream("./test/assets/testfile.png", {
      highWaterMark: 1 * 1024,
    });
    const output = fs.createWriteStream("./test/assets/streamed_file_encrypted.png", {
      highWaterMark: 1 * 1024,
    });
    await Promise.all([download(output), upload(input)]);
    const hash1 = hashFile("./test/assets/testfile.png");
    const hash2 = hashFile("./test/assets/streamed_file_encrypted.png");
    assert.equal(hash1, hash2);
    fs.rmSync("./test/assets/streamed_file_encrypted.png");
  });
});
