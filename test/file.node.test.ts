import { Buffer } from "buffer/";
import { createReadStream, createWriteStream, readFileSync, rmSync } from "fs";
import { createHash } from "crypto";
import assert from "assert";
import { IdManager } from "../";
import { createRandomVaultysId } from "./utils";
import { MemoryChannel, StreamChannel } from "../src/MemoryChannel";
import { MemoryStorage } from "../src/MemoryStorage";
import "./shims";

const hashFile = (name: string) => {
  const fileBuffer = readFileSync(name);
  const hashSum = createHash("sha256");
  hashSum.update(fileBuffer);
  return hashSum.digest("hex");
};

describe("IdManagerwith files on nodejs", () => {
  it("Transfer data over encrypted Channel", async () => {
    for (let i = 0; i < 10; i++) {
      const id1 = await createRandomVaultysId();
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      // channel.setLogger((data) => console.log("<"));
      // channel.otherend?.setLogger((data) => console.log(">"));
      if (!channel.otherend) assert.fail();
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);
      const manager2 = new IdManager(await createRandomVaultysId(), s2);

      const input = createReadStream("./test/assets/testfile.png", {
        highWaterMark: 1 * 1024,
      });

      const output = createWriteStream("./test/assets/streamed_file_encrypted.png");
      const promise = manager2.download(channel, output);
      await manager1.upload(channel.otherend, input);
      await promise;
      const hash1 = hashFile("./test/assets/testfile.png");
      await new Promise((r) => setTimeout(r, 1));
      const hash2 = hashFile("./test/assets/streamed_file_encrypted.png");
      rmSync("./test/assets/streamed_file_encrypted.png");
      assert.equal(hash1, hash2);
    }
  });

  it("sign a File over Channel", async () => {
    for (let i = 0; i < 10; i++) {
      const id1 = await createRandomVaultysId();
      const channel = MemoryChannel.createEncryptedBidirectionnal();
      if (!channel.otherend) assert.fail();
      // channel.setLogger((data) => console.log(data.toString("utf-8")));
      const s1 = MemoryStorage(() => "");
      const s2 = MemoryStorage(() => "");
      const manager1 = new IdManager(id1, s1);
      const manager2 = new IdManager(await createRandomVaultysId(), s2);

      const input = readFileSync("./test/assets/testfile.png");
      const file = { arrayBuffer: Buffer.from(input), type: "image/png" };

      manager1.acceptSignFile(channel);
      const result = await manager2.requestSignFile(channel.otherend, file);

      if (!result) return assert.fail("no result of the sign file request");
      const challenge = new URL(result.challenge.toString("utf8"));
      //console.log(challenge);
      assert.equal(challenge.protocol, "vaultys:");
      assert.equal(challenge.host, "signfile");
      assert.equal(challenge.searchParams.get("hash"), "a73d53246950a93ee956e413f50ed326e36f9a052dcd6fc5388ae19290931f32");
      assert.notEqual(challenge.searchParams.get("timestamp"), null);
      assert.ok(manager2.verifyFile(file, result, manager1.vaultysId));
    }
  });
});

describe("Channel tests for nodejs", () => {
  it("stream file", async () => {
    const channel = MemoryChannel.createBidirectionnal();
    // channel.setLogger((data) => console.log(data, "->"));
    // channel.otherend!.setLogger((data) => console.log(data, "<-"));
    const { upload } = StreamChannel(channel.otherend!);
    const { download } = StreamChannel(channel);
    const input = createReadStream("./test/assets/testfile.png", {
      highWaterMark: 1 * 1024,
    });
    const output = createWriteStream("./test/assets/streamed_file.png");

    const promise = download(output);
    await upload(input);
    await promise;
    const hash1 = hashFile("./test/assets/testfile.png");
    await new Promise((r) => setTimeout(r, 1));
    const hash2 = hashFile("./test/assets/streamed_file.png");
    assert.equal(hash1, hash2);
    rmSync("./test/assets/streamed_file.png");
  });

  it("stream file over encrypted channel", async () => {
    const channel = MemoryChannel.createEncryptedBidirectionnal();
    const { download } = StreamChannel(channel);
    const { upload } = StreamChannel(channel.otherend!);
    const input = createReadStream("./test/assets/testfile.png", {
      highWaterMark: 1 * 1024,
    });
    const output = createWriteStream("./test/assets/streamed_file_encrypted.png");
    const promise = download(output);
    await upload(input);
    await promise;
    const hash1 = hashFile("./test/assets/testfile.png");
    const hash2 = hashFile("./test/assets/streamed_file_encrypted.png");
    assert.equal(hash1, hash2);
    rmSync("./test/assets/streamed_file_encrypted.png");
  });
});
