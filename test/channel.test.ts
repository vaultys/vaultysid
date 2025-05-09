import assert from "assert";
import { Buffer } from "buffer/";
import { MemoryChannel, pipeChannels, StreamChannel, unpipeChannels } from "../src/MemoryChannel";
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe("Channel tests", () => {
  it("send/receive", async () => {
    const channel = MemoryChannel.createEncryptedBidirectionnal();
    channel.send(Buffer.from("hello world", "utf-8"));
    const message = await channel.otherend?.receive();
    assert.equal("hello world", message?.toString("utf-8"));
  });
});

// describe("Channel pipe tests", () => {
//   it("should pipe data between two memory channels", async () => {
//     // Create endpoints for A and B
//     const channelA = MemoryChannel.createBidirectionnal();
//     const channelB = MemoryChannel.createBidirectionnal();

//     console.log("started");

//     // Connect channels to receive endpoints
//     const receiverA = channelA.otherend!;
//     const receiverB = channelB.otherend!;

//     channelA.setLogger(console.log);
//     channelB.setLogger(console.log);

//     // Start piping between the two channels
//     const unpipe = pipeChannels(channelA, channelB);

//     await delay(10);

//     const messageAtB = receiverB.receive();

//     // Send data from A to B
//     channelA.send(Buffer.from("hello from A", "utf-8"));

//     // Receive on B's side
//     console.log(await messageAtB);
//     console.log("Data sent from A to B");

//     // Send data from B to A
//     await channelB.send(Buffer.from("hello from B", "utf-8"));

//     // Receive on A's side
//     const messageAtA = await receiverA.receive();

//     // Clean up
//     await unpipe();

//     // Verify the data was correctly transmitted
//     assert.equal(messageAtB.toString("utf-8"), "hello from A");
//     assert.equal(messageAtA.toString("utf-8"), "hello from B");
//   });

//   it("should pipe data between encrypted memory channels", async () => {
//     // Create encrypted endpoints
//     const channelA = MemoryChannel.createEncryptedBidirectionnal();
//     const channelB = MemoryChannel.createEncryptedBidirectionnal();

//     // Connect channels to receive endpoints
//     const receiverA = channelA.otherend!;
//     const receiverB = channelB.otherend!;

//     // Start piping
//     const unpipe = pipeChannels(channelA, channelB);

//     // Send multiple messages from A to B
//     await channelA.send(Buffer.from("message 1", "utf-8"));
//     await channelA.send(Buffer.from("message 2", "utf-8"));

//     // Receive on B
//     const message1AtB = await receiverB.receive();
//     const message2AtB = await receiverB.receive();

//     // Clean up
//     await unpipe();

//     // Verify the data was correctly transmitted
//     assert.equal(message1AtB.toString("utf-8"), "message 1");
//     assert.equal(message2AtB.toString("utf-8"), "message 2");
//   });

//   it("should handle large data transfers", async () => {
//     // Create endpoints
//     const channelA = MemoryChannel.createBidirectionnal();
//     const channelB = MemoryChannel.createBidirectionnal();

//     // Connect channels to receive endpoints
//     const receiverB = channelB.otherend!;

//     // Start piping
//     const unpipe = pipeChannels(channelA, channelB);

//     // Create a large buffer (1MB)
//     const largeData = Buffer.alloc(1024 * 1024);
//     largeData.fill(42);

//     // Send large data from A to B
//     await channelA.send(largeData);

//     // Receive on B
//     const receivedData = await receiverB.receive();

//     // Clean up
//     await unpipe();

//     // Verify the data was correctly transmitted
//     assert.equal(receivedData.length, largeData.length);
//     assert.ok(receivedData.equals(largeData));
//   });

//   it("should handle bidirectional communication simultaneously", async () => {
//     // Create endpoints
//     const channelA = MemoryChannel.createBidirectionnal();
//     const channelB = MemoryChannel.createBidirectionnal();

//     // Connect channels to receive endpoints
//     const receiverA = channelA.otherend!;
//     const receiverB = channelB.otherend!;

//     // Start piping
//     const unpipe = pipeChannels(channelA, channelB);

//     // Send messages in both directions
//     await Promise.all([channelA.send(Buffer.from("from A to B", "utf-8")), channelB.send(Buffer.from("from B to A", "utf-8"))]);

//     // Receive in both directions
//     const [messageAtB, messageAtA] = await Promise.all([receiverB.receive(), receiverA.receive()]);

//     // Clean up
//     await unpipe();

//     // Verify bidirectional data transmission
//     assert.equal(messageAtB.toString("utf-8"), "from A to B");
//     assert.equal(messageAtA.toString("utf-8"), "from B to A");
//   });
// });
