#!/usr/bin/env ts-node

import * as fs from "fs";
import * as path from "path";
import { Buffer } from "buffer/";

// Simple test to verify the protocol communication

async function testProtocol() {
  console.log("\n=== Testing Cross-Language Protocol ===\n");

  const channelName = process.argv[2] || "test-protocol";
  const role = process.argv[3] || "sender"; // sender or receiver

  // Use same path structure as Rust expects
  const channelDir = path.join(__dirname, "tmp", "channels", channelName);

  console.log(`Role: ${role}`);
  console.log(`Channel directory: ${channelDir}`);
  console.log(`Current working directory: ${process.cwd()}`);
  console.log(`__dirname: ${__dirname}`);

  // Ensure directory exists
  if (!fs.existsSync(channelDir)) {
    fs.mkdirSync(channelDir, { recursive: true });
    console.log("Created channel directory");
  }

  if (role === "sender") {
    // Send a simple message and wait for response
    const messageId = `${Date.now()}_0`;
    const testData = {
      type: "test",
      message: "Hello from TypeScript",
      timestamp: Date.now()
    };

    const message = {
      id: messageId,
      timestamp: Date.now(),
      data: Buffer.from(JSON.stringify(testData)).toString("base64"),
      length: JSON.stringify(testData).length
    };

    const filename = path.join(channelDir, `ts_to_rust_${messageId}.msg`);
    fs.writeFileSync(filename, JSON.stringify(message, null, 2));

    console.log(`\nSent test message to: ${filename}`);
    console.log(`Message ID: ${messageId}`);
    console.log(`Data length: ${message.length} bytes`);

    // Wait for response
    console.log("\nWaiting for response from Rust...");
    let attempts = 0;
    const checkInterval = setInterval(() => {
      attempts++;

      const files = fs.readdirSync(channelDir);
      const rustFiles = files.filter(f => f.startsWith("rust_to_ts_"));

      if (rustFiles.length > 0) {
        console.log(`\n✅ Received response: ${rustFiles[0]}`);
        const content = fs.readFileSync(path.join(channelDir, rustFiles[0]), 'utf-8');
        const response = JSON.parse(content);
        console.log("Response data length:", response.length);

        // Decode and display
        const decoded = Buffer.from(response.data, "base64").toString();
        console.log("Decoded response:", decoded);

        clearInterval(checkInterval);
        process.exit(0);
      }

      if (attempts > 30) {
        console.log("\n❌ Timeout waiting for response");
        clearInterval(checkInterval);
        process.exit(1);
      }

      if (attempts % 5 === 0) {
        console.log(`Still waiting... (${attempts}s) - Files in dir: ${files.join(", ") || "(empty)"}`);
      }
    }, 1000);

  } else if (role === "receiver") {
    // Wait for message and send response
    console.log("\nWaiting for message from Rust...");
    let attempts = 0;
    const checkInterval = setInterval(() => {
      attempts++;

      const files = fs.readdirSync(channelDir);
      const rustFiles = files.filter(f => f.startsWith("rust_to_ts_"));

      if (rustFiles.length > 0) {
        console.log(`\n✅ Received message: ${rustFiles[0]}`);
        const content = fs.readFileSync(path.join(channelDir, rustFiles[0]), 'utf-8');
        const message = JSON.parse(content);
        console.log("Message data length:", message.length);

        // Decode and display
        const decoded = Buffer.from(message.data, "base64").toString();
        console.log("Decoded message (first 200 chars):", decoded.substring(0, 200));

        // Send response
        const responseId = `${Date.now()}_0`;
        const responseData = {
          type: "response",
          message: "Response from TypeScript",
          timestamp: Date.now()
        };

        const response = {
          id: responseId,
          timestamp: Date.now(),
          data: Buffer.from(JSON.stringify(responseData)).toString("base64"),
          length: JSON.stringify(responseData).length
        };

        const responseFile = path.join(channelDir, `ts_to_rust_${responseId}.msg`);
        fs.writeFileSync(responseFile, JSON.stringify(response, null, 2));

        console.log(`\n✅ Sent response to: ${responseFile}`);

        // Clean up received file
        fs.unlinkSync(path.join(channelDir, rustFiles[0]));

        clearInterval(checkInterval);
        process.exit(0);
      }

      if (attempts > 30) {
        console.log("\n❌ Timeout waiting for message");
        clearInterval(checkInterval);
        process.exit(1);
      }

      if (attempts % 5 === 0) {
        console.log(`Still waiting... (${attempts}s) - Files in dir: ${files.join(", ") || "(empty)"}`);
      }
    }, 1000);

  } else {
    console.error("Invalid role. Use 'sender' or 'receiver'");
    process.exit(1);
  }
}

// Run the test
testProtocol().catch(error => {
  console.error("Error:", error);
  process.exit(1);
});
