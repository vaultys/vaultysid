#!/usr/bin/env ts-node

import * as fs from "fs";
import * as path from "path";
import { Buffer } from "buffer/";
import { decode, encode } from "@msgpack/msgpack";
import { createHash } from "crypto";

// Script to analyze the signature verification issue in the COMPLETE message

const SIGN_INCIPIT = Buffer.from("VAULTYS_SIGN", "utf8");

function hash(algorithm: string, data: Buffer): Buffer {
  return createHash(algorithm).update(data).digest();
}

function analyzeCompleteMessage(messageFile: string) {
  console.log(`\n=== Analyzing COMPLETE Message: ${path.basename(messageFile)} ===\n`);

  // Read the message file
  const content = fs.readFileSync(messageFile, "utf-8");
  const message = JSON.parse(content);

  // Decode the base64 data
  const buffer = Buffer.from(message.data, "base64");

  // Decode as msgpack
  const decoded = decode(buffer) as any;

  console.log("Message Structure:");
  console.log("  version:", decoded.version);
  console.log("  protocol:", decoded.protocol);
  console.log("  service:", decoded.service);
  console.log("  timestamp:", decoded.timestamp);
  console.log("  pk1 length:", decoded.pk1?.length || 0);
  console.log("  pk2 length:", decoded.pk2?.length || 0);
  console.log("  nonce length:", decoded.nonce?.length || 0);
  console.log("  sign1 length:", decoded.sign1?.length || 0);
  console.log("  sign2 length:", decoded.sign2?.length || 0);

  if (decoded.metadata) {
    console.log("  metadata.pk1:", decoded.metadata.pk1);
    console.log("  metadata.pk2:", decoded.metadata.pk2);
  }

  // Create the unsigned version (what should be signed)
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

  console.log("\n=== Signature Verification Process ===\n");

  // Serialize unsigned message
  console.log("1. Creating unsigned message for verification...");
  const unsignedEncoded = encode(unsigned);
  console.log(`   Unsigned message length: ${unsignedEncoded.length} bytes`);
  console.log(`   Unsigned (hex, first 64): ${Buffer.from(unsignedEncoded).toString("hex").substring(0, 64)}`);

  // What should be signed (with SIGN_INCIPIT prefix)
  console.log("\n2. Adding SIGN_INCIPIT prefix...");
  const toSign = Buffer.concat([SIGN_INCIPIT, Buffer.from(unsignedEncoded)]);
  console.log(`   Message with prefix length: ${toSign.length} bytes`);
  console.log(`   With prefix (hex, first 64): ${toSign.toString("hex").substring(0, 64)}`);

  // Hash it
  console.log("\n3. Hashing the message...");
  const hashed = hash("sha256", toSign);
  console.log(`   SHA256 hash: ${hashed.toString("hex")}`);

  // Display the signatures
  console.log("\n4. Signatures in the message:");
  if (decoded.sign1) {
    const sign1Buf = Buffer.from(decoded.sign1);
    console.log(`   sign1 (from Rust/pk1):`);
    console.log(`     Length: ${sign1Buf.length} bytes`);
    console.log(`     Hex (first 64): ${sign1Buf.toString("hex").substring(0, 64)}`);
    console.log(`     Base64: ${sign1Buf.toString("base64").substring(0, 50)}...`);
  }

  if (decoded.sign2) {
    const sign2Buf = Buffer.from(decoded.sign2);
    console.log(`   sign2 (from TypeScript/pk2):`);
    console.log(`     Length: ${sign2Buf.length} bytes`);
    console.log(`     Hex (first 64): ${sign2Buf.toString("hex").substring(0, 64)}`);
    console.log(`     Base64: ${sign2Buf.toString("base64").substring(0, 50)}...`);
  }

  // Check for common issues
  console.log("\n=== Potential Issues Check ===\n");

  // Check if the serialization matches
  console.log("1. Serialization format:");
  console.log(`   Message starts with: 0x${buffer[0].toString(16)} (should be 0x8a for 10-element map)`);

  // Check field order
  console.log("\n2. Field order in unsigned message:");
  const keys = Object.keys(unsigned);
  console.log(`   Fields: ${keys.join(", ")}`);

  // Try alternative serialization (sorted keys)
  console.log("\n3. Alternative serialization (sorted keys):");
  const sortedUnsigned = Object.keys(unsigned).sort().reduce((obj: any, key) => {
    obj[key] = unsigned[key as keyof typeof unsigned];
    return obj;
  }, {});
  const sortedEncoded = encode(sortedUnsigned);
  if (Buffer.from(sortedEncoded).toString("hex") !== Buffer.from(unsignedEncoded).toString("hex")) {
    console.log("   WARNING: Sorted encoding differs from original!");
    console.log(`   Sorted length: ${sortedEncoded.length} bytes`);
    console.log(`   Sorted (hex, first 64): ${Buffer.from(sortedEncoded).toString("hex").substring(0, 64)}`);
  } else {
    console.log("   Sorted encoding matches original (field order consistent)");
  }

  // Check metadata structure
  console.log("\n4. Metadata structure:");
  if (decoded.metadata) {
    console.log(`   Type: ${typeof decoded.metadata}`);
    console.log(`   Keys: ${Object.keys(decoded.metadata).join(", ")}`);
    if (decoded.metadata.pk1) {
      console.log(`   metadata.pk1 keys: ${Object.keys(decoded.metadata.pk1).join(", ")}`);
    }
    if (decoded.metadata.pk2) {
      console.log(`   metadata.pk2 keys: ${Object.keys(decoded.metadata.pk2).join(", ")}`);
    }
  }

  return decoded;
}

// Main execution
const args = process.argv.slice(2);

if (args.length === 0) {
  // Default: analyze the most recent complete message
  const debugDir = path.join(__dirname, "tmp", "channels", "debug");

  if (!fs.existsSync(debugDir)) {
    console.error("Debug directory not found. Run the test first to generate debug files.");
    process.exit(1);
  }

  const files = fs.readdirSync(debugDir);
  const completeMessages = files.filter(f =>
    f.includes("rust_to_ts") &&
    f.endsWith("_1.msg") // The second Rust message should be COMPLETE
  ).sort();

  if (completeMessages.length === 0) {
    console.error("No COMPLETE messages found in debug directory.");
    console.log("Available files:", files);
    process.exit(1);
  }

  const latestComplete = completeMessages[completeMessages.length - 1];
  const filepath = path.join(debugDir, latestComplete);

  console.log("Analyzing the latest COMPLETE message...");
  analyzeCompleteMessage(filepath);

  // Also analyze the STEP1 message for comparison
  const step1Messages = files.filter(f =>
    f.includes("ts_to_rust") &&
    f.endsWith("_0.msg")
  ).sort();

  if (step1Messages.length > 0) {
    const latestStep1 = step1Messages[step1Messages.length - 1];
    const step1Path = path.join(debugDir, latestStep1);
    console.log("\n" + "=".repeat(60));
    console.log("\nFor comparison, analyzing the STEP1 message:");
    analyzeCompleteMessage(step1Path);
  }

} else {
  // Analyze specific file
  const filepath = args[0];
  if (!fs.existsSync(filepath)) {
    console.error(`File not found: ${filepath}`);
    process.exit(1);
  }
  analyzeCompleteMessage(filepath);
}

console.log("\n=== End of Analysis ===\n");
