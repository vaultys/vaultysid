#!/usr/bin/env ts-node

import * as fs from "fs";
import * as path from "path";
import { Buffer } from "buffer/";
import { decode, encode } from "@msgpack/msgpack";

// Script to debug protocol messages between Rust and TypeScript

const channelName = process.argv[2] || "debug-protocol";
const role = process.argv[3] || "monitor"; // monitor, analyze-rust, or analyze-ts

const channelDir = path.join(__dirname, "tmp", "channels", channelName);

console.log("=== Protocol Message Debugger ===");
console.log(`Channel: ${channelName}`);
console.log(`Role: ${role}`);
console.log(`Directory: ${channelDir}`);

function analyzeMessage(data: string): any {
  try {
    // Decode base64
    const buffer = Buffer.from(data, "base64");

    // Try to decode as msgpack
    const decoded = decode(buffer) as any;

    // Extract relevant fields
    const result: any = {
      version: decoded.version,
      protocol: decoded.protocol,
      service: decoded.service,
      timestamp: decoded.timestamp,
      state: "UNKNOWN"
    };

    // Determine state based on signatures
    if (decoded.pk1) result.pk1 = Buffer.from(decoded.pk1).toString("base64").substring(0, 20) + "...";
    if (decoded.pk2) result.pk2 = Buffer.from(decoded.pk2).toString("base64").substring(0, 20) + "...";
    if (decoded.nonce) result.nonce_length = decoded.nonce.length;

    if (decoded.sign1 && decoded.sign2) {
      result.state = "COMPLETE";
      result.sign1 = Buffer.from(decoded.sign1).toString("base64").substring(0, 20) + "...";
      result.sign2 = Buffer.from(decoded.sign2).toString("base64").substring(0, 20) + "...";
    } else if (decoded.sign2 && !decoded.sign1) {
      result.state = "STEP1";
      result.sign2 = Buffer.from(decoded.sign2).toString("base64").substring(0, 20) + "...";
    } else if (!decoded.sign1 && !decoded.sign2) {
      result.state = "INIT";
    }

    if (decoded.metadata) {
      result.metadata = {};
      if (decoded.metadata.pk1) result.metadata.pk1 = decoded.metadata.pk1;
      if (decoded.metadata.pk2) result.metadata.pk2 = decoded.metadata.pk2;
    }

    return result;
  } catch (e: any) {
    return { error: `Failed to decode: ${e.message}` };
  }
}

function compareSignatures(msg1: any, msg2: any) {
  console.log("\n=== Signature Comparison ===");

  // Create unsigned version for verification
  const unsigned1 = {
    version: msg1.version,
    protocol: msg1.protocol,
    service: msg1.service,
    timestamp: msg1.timestamp,
    pk1: msg1.pk1,
    pk2: msg1.pk2,
    nonce: msg1.nonce,
    metadata: msg1.metadata
  };

  console.log("Unsigned message for signature verification:");
  console.log("  Fields included: version, protocol, service, timestamp, pk1, pk2, nonce, metadata");

  // Encode the unsigned message
  const encoded = encode(unsigned1);
  console.log(`  Encoded length: ${encoded.length} bytes`);
  console.log(`  Encoded (hex, first 100): ${Buffer.from(encoded).toString("hex").substring(0, 100)}...`);
}

if (role === "monitor") {
  // Monitor mode: watch for all messages
  console.log("\nMonitoring for messages...\n");

  const seenFiles = new Set<string>();

  setInterval(() => {
    if (!fs.existsSync(channelDir)) {
      fs.mkdirSync(channelDir, { recursive: true });
      return;
    }

    const files = fs.readdirSync(channelDir);
    const msgFiles = files.filter(f => f.endsWith(".msg"));

    for (const file of msgFiles) {
      if (!seenFiles.has(file)) {
        seenFiles.add(file);

        const filepath = path.join(channelDir, file);
        const content = fs.readFileSync(filepath, "utf-8");
        const message = JSON.parse(content);

        const direction = file.startsWith("rust_to_ts") ? "Rust → TypeScript" : "TypeScript → Rust";
        console.log(`\n=== ${direction} Message ===`);
        console.log(`File: ${file}`);
        console.log(`Timestamp: ${new Date(message.timestamp).toISOString()}`);
        console.log(`Data length: ${message.length} bytes`);

        const analyzed = analyzeMessage(message.data);
        console.log(`Protocol Analysis:`, JSON.stringify(analyzed, null, 2));
      }
    }
  }, 500);

  console.log("Press Ctrl+C to stop monitoring");

} else if (role === "analyze-rust" || role === "analyze-ts") {
  // Analyze specific messages
  const prefix = role === "analyze-rust" ? "rust_to_ts" : "ts_to_rust";

  if (!fs.existsSync(channelDir)) {
    console.log("Channel directory doesn't exist");
    process.exit(1);
  }

  const files = fs.readdirSync(channelDir);
  const msgFiles = files.filter(f => f.startsWith(prefix) && f.endsWith(".msg")).sort();

  console.log(`\nFound ${msgFiles.length} ${role === "analyze-rust" ? "Rust" : "TypeScript"} messages:\n`);

  for (const file of msgFiles) {
    const filepath = path.join(channelDir, file);
    const content = fs.readFileSync(filepath, "utf-8");
    const message = JSON.parse(content);

    console.log(`\n=== Message: ${file} ===`);
    console.log(`Timestamp: ${new Date(message.timestamp).toISOString()}`);
    console.log(`Data length: ${message.length} bytes`);

    const analyzed = analyzeMessage(message.data);
    console.log(`Analysis:`, JSON.stringify(analyzed, null, 2));

    if (analyzed.state === "COMPLETE") {
      // Decode full message for signature verification
      const buffer = Buffer.from(message.data, "base64");
      const fullMsg = decode(buffer) as any;
      compareSignatures(fullMsg, analyzed);
    }
  }

} else if (role === "compare") {
  // Compare the last exchange
  if (!fs.existsSync(channelDir)) {
    console.log("Channel directory doesn't exist");
    process.exit(1);
  }

  const files = fs.readdirSync(channelDir);
  const rustFiles = files.filter(f => f.startsWith("rust_to_ts") && f.endsWith(".msg")).sort();
  const tsFiles = files.filter(f => f.startsWith("ts_to_rust") && f.endsWith(".msg")).sort();

  console.log(`\nFound ${rustFiles.length} Rust messages and ${tsFiles.length} TypeScript messages\n`);

  // Analyze the complete message (should be the last Rust message)
  if (rustFiles.length > 0) {
    const lastRust = rustFiles[rustFiles.length - 1];
    const filepath = path.join(channelDir, lastRust);
    const content = fs.readFileSync(filepath, "utf-8");
    const message = JSON.parse(content);

    console.log(`\n=== Final COMPLETE Message from Rust ===`);
    console.log(`File: ${lastRust}`);

    const buffer = Buffer.from(message.data, "base64");
    const decoded = decode(buffer) as any;

    console.log("\nDecoded fields:");
    console.log(`  version: ${decoded.version}`);
    console.log(`  protocol: ${decoded.protocol}`);
    console.log(`  service: ${decoded.service}`);
    console.log(`  timestamp: ${decoded.timestamp}`);
    console.log(`  pk1 (length): ${decoded.pk1 ? decoded.pk1.length : "null"}`);
    console.log(`  pk2 (length): ${decoded.pk2 ? decoded.pk2.length : "null"}`);
    console.log(`  nonce (length): ${decoded.nonce ? decoded.nonce.length : "null"}`);
    console.log(`  sign1 (length): ${decoded.sign1 ? decoded.sign1.length : "null"}`);
    console.log(`  sign2 (length): ${decoded.sign2 ? decoded.sign2.length : "null"}`);

    // Check signature format
    if (decoded.sign1) {
      console.log(`\nSignature 1 (sign1) - from Rust:`);
      console.log(`  Raw bytes (hex, first 32): ${Buffer.from(decoded.sign1).toString("hex").substring(0, 64)}`);
      console.log(`  Length: ${decoded.sign1.length} bytes`);
    }

    // Create unsigned version for verification
    console.log("\n=== Recreating Unsigned Message for Verification ===");
    const unsigned = {
      version: decoded.version,
      protocol: decoded.protocol,
      service: decoded.service,
      timestamp: decoded.timestamp,
      pk1: decoded.pk1,
      pk2: decoded.pk2,
      nonce: decoded.nonce,
      metadata: decoded.metadata
    };

    const unsignedEncoded = encode(unsigned);
    console.log(`Unsigned message encoded length: ${unsignedEncoded.length} bytes`);
    console.log(`Unsigned message (hex, first 100): ${Buffer.from(unsignedEncoded).toString("hex").substring(0, 100)}...`);

    // What TypeScript would sign
    const SIGN_INCIPIT = Buffer.from("VAULTYS_SIGN", "utf8");
    const toSign = Buffer.concat([SIGN_INCIPIT, Buffer.from(unsignedEncoded)]);
    console.log(`\nMessage to sign (with VAULTYS_SIGN prefix): ${toSign.length} bytes`);
    console.log(`To sign (hex, first 100): ${toSign.toString("hex").substring(0, 100)}...`);
  }

} else {
  console.error("Invalid role. Use 'monitor', 'analyze-rust', 'analyze-ts', or 'compare'");
  process.exit(1);
}
