import { Buffer } from "buffer/";
import assert from "assert";
import { IdManager } from "../";
import { createRandomVaultysId } from "./utils";
import { convertWebReadableStreamToNodeReadable, convertWebWritableStreamToNodeWritable, MemoryChannel, StreamChannel } from "../src/MemoryChannel";
import { MemoryStorage, MessagePackStorage } from "../src/MemoryStorage";
import "./shims";
import { hash } from "../src/crypto";

const fetchFile = async (url: string) => {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch file: ${response.statusText}`);
  }
  return await response.arrayBuffer();
};

describe("IdManager with files in browser", () => {
  it("Transfer data over encrypted Channel", async () => {
    for (let i = 0; i < 10; i++) {
      const id1 = await createRandomVaultysId();
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      if (!channel.otherend) assert.fail();
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);
      const manager2 = new IdManager(await createRandomVaultysId(), s2);

      const inputBuffer = await fetchFile("assets/testfile.png");
      const input = new Blob([inputBuffer], { type: "image/png" });

      const outputChunks: Uint8Array[] = [];
      const outputStream = new WritableStream({
        write(chunk) {
          outputChunks.push(new Uint8Array(chunk));
        },
      });

      const promise = manager2.download(channel, convertWebWritableStreamToNodeWritable(outputStream));
      await manager1.upload(channel.otherend, convertWebReadableStreamToNodeReadable(input.stream()));
      await promise;

      const outputBuffer = Buffer.concat(outputChunks);
      const hash1 = hash("sha256", Buffer.from(inputBuffer));
      const hash2 = hash("sha256", outputBuffer);
      assert.equal(hash1.toString("hex"), hash2.toString("hex"));
    }
  });

  // it("Transfer data over encrypted Channel using MessagePackStorage", async () => {
  //   for (let i = 0; i < 10; i++) {
  //     const id1 = await createRandomVaultysId();
  //     const channel = MemoryChannel.createEncryptedBidirectionnal();
  //     if (!channel.otherend) assert.fail();
  //     const s1 = MessagePackStorage();
  //     const s2 = MessagePackStorage();
  //     const manager1 = new IdManager(id1, s1);
  //     const manager2 = new IdManager(await createRandomVaultysId(), s2);

  //     const inputBuffer = await fetchFile("assets/testfile.png");
  //     const input = new Blob([inputBuffer], { type: "image/png" });

  //     const outputChunks: Uint8Array[] = [];
  //     const outputStream = new WritableStream({
  //       write(chunk) {
  //         outputChunks.push(new Uint8Array(chunk));
  //       },
  //     });

  //     const promise = manager2.download(channel, convertWebWritableStreamToNodeWritable(outputStream));
  //     await manager1.upload(channel.otherend, convertWebReadableStreamToNodeReadable(input.stream()));
  //     await promise;

  //     const outputBuffer = Buffer.concat(outputChunks);
  //     const hash1 = hash("sha256", Buffer.from(inputBuffer));
  //     const hash2 = hash("sha256", outputBuffer);
  //     assert.equal(hash1.toString("hex"), hash2.toString("hex"));
  //   }
  // });

  it("sign a File over Channel", async () => {
    for (let i = 0; i < 10; i++) {
      const id1 = await createRandomVaultysId();
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      if (!channel.otherend) assert.fail();
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);
      const manager2 = new IdManager(await createRandomVaultysId(), s2);

      const inputBuffer = await fetchFile("assets/testfile.png");
      const file = { arrayBuffer: Buffer.from(inputBuffer), type: "image/png" };

      manager1.acceptSignFile(channel);
      const result = await manager2.requestSignFile(channel.otherend, file);

      if (!result) return assert.fail("no result of the sign file request");
      const challenge = new URL(result.challenge.toString("utf8"));
      assert.equal(challenge.protocol, "vaultys:");
      assert.equal(challenge.host, "signfile");
      assert.equal(challenge.searchParams.get("hash"), "a73d53246950a93ee956e413f50ed326e36f9a052dcd6fc5388ae19290931f32");
      assert.notEqual(challenge.searchParams.get("timestamp"), null);
      assert.ok(manager2.verifyFile(file, result, manager1.vaultysId));
    }
  });
});

describe("Channel tests for browser", () => {
  it("stream file", async () => {
    const channel = MemoryChannel.createBidirectionnal();
    const { upload } = StreamChannel(channel.otherend!);
    const { download } = StreamChannel(channel);

    const inputBuffer = await fetchFile("assets/testfile.png");
    const input = new Blob([inputBuffer], { type: "image/png" });

    const outputChunks: Uint8Array[] = [];
    const outputStream = new WritableStream({
      write(chunk) {
        outputChunks.push(new Uint8Array(chunk));
      },
    });

    const promise = download(convertWebWritableStreamToNodeWritable(outputStream));
    await upload(convertWebReadableStreamToNodeReadable(input.stream()));
    await promise;

    const outputBuffer = Buffer.concat(outputChunks);
    const hash1 = hash("sha256", Buffer.from(inputBuffer));
    const hash2 = hash("sha256", outputBuffer);
    assert.equal(hash1.toString("hex"), hash2.toString("hex"));
  });

  it("stream file over encrypted channel", async () => {
    const channel = MemoryChannel.createEncryptedBidirectionnal();
    const { download } = StreamChannel(channel);
    const { upload } = StreamChannel(channel.otherend!);

    const inputBuffer = await fetchFile("assets/testfile.png");
    const input = new Blob([inputBuffer], { type: "image/png" });

    const outputChunks: Buffer[] = [];
    const outputStream = new WritableStream({
      write(chunk) {
        outputChunks.push(new Buffer(chunk));
      },
    });

    const promise = download(convertWebWritableStreamToNodeWritable(outputStream));
    await upload(convertWebReadableStreamToNodeReadable(input.stream()));
    await promise;

    const outputBuffer = Buffer.concat(outputChunks);
    const hash1 = hash("sha256", Buffer.from(inputBuffer));
    const hash2 = hash("sha256", outputBuffer);
    assert.equal(hash1.toString("hex"), hash2.toString("hex"));
  });
});
