#!/usr/bin/env ts-node

import * as fs from "fs";
import * as path from "path";
import { Buffer } from "buffer/";

// Debug script to test channel communication between TypeScript and Rust

const channelName = process.argv[2] || "debug-channel";
const role = process.argv[3] || "sender"; // sender or receiver

// Calculate the correct channel directory path
const channelDir = path.join(__dirname, "tmp", "channels", channelName);

console.log("=== Channel Debug Script ===");
console.log(`Role: ${role}`);
console.log(`Channel name: ${channelName}`);
console.log(`Channel directory: ${channelDir}`);
console.log(`__dirname: ${__dirname}`);
console.log(`process.cwd(): ${process.cwd()}`);

// Ensure channel directory exists
if (!fs.existsSync(channelDir)) {
  fs.mkdirSync(channelDir, { recursive: true });
  console.log("Created channel directory");
} else {
  console.log("Channel directory already exists");
}

// List current contents
const files = fs.readdirSync(channelDir);
console.log(`Current files in channel: ${files.length > 0 ? files.join(", ") : "(empty)"}`);

if (role === "sender") {
  // Send a test message
  const messageId = `${Date.now()}_0`;
  const data = Buffer.from("Hello from TypeScript!");
  const filename = path.join(channelDir, `ts_to_rust_${messageId}.msg`);

  const message = {
    id: messageId,
    timestamp: Date.now(),
    data: data.toString("base64"),
    length: data.length,
  };

  fs.writeFileSync(filename, JSON.stringify(message, null, 2));
  console.log(`\nSent message: ${filename}`);
  console.log(`Message content:`, message);

  // Wait and check for response
  console.log("\nWaiting for response from Rust...");
  let attempts = 0;
  const checkInterval = setInterval(() => {
    attempts++;
    const files = fs.readdirSync(channelDir);
    const rustFiles = files.filter(f => f.startsWith("rust_to_ts_"));

    if (rustFiles.length > 0) {
      console.log(`\nReceived response: ${rustFiles[0]}`);
      const content = fs.readFileSync(path.join(channelDir, rustFiles[0]), 'utf-8');
      const response = JSON.parse(content);
      console.log("Response content:", response);
      clearInterval(checkInterval);
      process.exit(0);
    }

    if (attempts > 30) { // 30 seconds timeout
      console.log("\nTimeout waiting for response");
      clearInterval(checkInterval);
      process.exit(1);
    }

    if (attempts % 5 === 0) {
      console.log(`Still waiting... (${attempts} seconds)`);
    }
  }, 1000);

} else if (role === "receiver") {
  // Wait for a message
  console.log("\nWaiting for message from Rust...");
  let attempts = 0;
  const checkInterval = setInterval(() => {
    attempts++;
    const files = fs.readdirSync(channelDir);
    const rustFiles = files.filter(f => f.startsWith("rust_to_ts_"));

    if (rustFiles.length > 0) {
      console.log(`\nReceived message: ${rustFiles[0]}`);
      const content = fs.readFileSync(path.join(channelDir, rustFiles[0]), 'utf-8');
      const message = JSON.parse(content);
      console.log("Message content:", message);

      // Send response
      const responseId = `${Date.now()}_0`;
      const responseData = Buffer.from("Response from TypeScript!");
      const responseFilename = path.join(channelDir, `ts_to_rust_${responseId}.msg`);

      const response = {
        id: responseId,
        timestamp: Date.now(),
        data: responseData.toString("base64"),
        length: responseData.length,
      };

      fs.writeFileSync(responseFilename, JSON.stringify(response, null, 2));
      console.log(`\nSent response: ${responseFilename}`);

      // Clean up the received message
      fs.unlinkSync(path.join(channelDir, rustFiles[0]));

      clearInterval(checkInterval);
      process.exit(0);
    }

    if (attempts > 30) { // 30 seconds timeout
      console.log("\nTimeout waiting for message");
      clearInterval(checkInterval);
      process.exit(1);
    }

    if (attempts % 5 === 0) {
      console.log(`Still waiting... (${attempts} seconds)`);
      const currentFiles = fs.readdirSync(channelDir);
      console.log(`Current files: ${currentFiles.length > 0 ? currentFiles.join(", ") : "(empty)"}`);
    }
  }, 1000);

} else {
  console.error("Invalid role. Use 'sender' or 'receiver'");
  process.exit(1);
}
