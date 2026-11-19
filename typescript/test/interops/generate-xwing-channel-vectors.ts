// Deterministic test vectors for rfc/SECURE-CHANNEL.md (§6).
// Run: pnpm test:channel:vectors (from typescript/). Writes xwing-channel-vectors.json next to this file.
// Keys are recomputed with node:crypto, independently of src/xwingChannel.ts.

import { createHash, hkdfSync } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { MemoryChannel } from "../../src/MemoryChannel";
import { acceptXWingChannelWith, BINDING_LABEL, CHANNEL_LABEL, CHANNEL_LABEL_I2R, CHANNEL_LABEL_R2I, encryptRecord, initiateXWingChannelWith, xwingDecapsulate } from "../../src/xwingChannel";

const hex = (u: Uint8Array) => Buffer.from(u).toString("hex");
const lp = (b: Uint8Array) => {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(b.length);
  return Buffer.concat([len, Buffer.from(b)]);
};
const sha256 = (b: Uint8Array) => Uint8Array.from(createHash("sha256").update(b).digest());
/** Public deterministic bytes: SHA-256("vaultysid/test/" || name) expanded by HKDF to `length`. */
export const testBytes = (name: string, length: number) => Uint8Array.from(Buffer.from(hkdfSync("sha256", sha256(Buffer.from(`vaultysid/test/${name}`)), Buffer.alloc(0), Buffer.alloc(0), length)));

export async function buildVectors() {
  const initiatorSeed = testBytes("channel/initiator-seed", 32);
  const encapsulationRandomness = testBytes("channel/encapsulation", 64);
  const pair = MemoryChannel.createBidirectionnal();
  const sent: Uint8Array[] = [];
  const record = (c: typeof pair) => {
    const send = c.send.bind(c);
    c.send = async (data) => {
      sent.push(Uint8Array.from(data));
      return send(data);
    };
  };
  record(pair);
  record(pair.otherend!);
  const [initiator, responder] = await Promise.all([initiateXWingChannelWith(pair, (n) => Uint8Array.from(initiatorSeed.subarray(0, n))), acceptXWingChannelWith(pair.otherend!, (n) => Uint8Array.from(encapsulationRandomness.subarray(0, n)))]);
  const [m1, m2] = sent;
  const ss = xwingDecapsulate(m2.subarray(2), Uint8Array.from(initiatorSeed));
  const th = sha256(Buffer.concat([lp(Buffer.from(CHANNEL_LABEL)), lp(m1), lp(m2)]));
  const i2r = Uint8Array.from(Buffer.from(hkdfSync("sha256", ss, th, Buffer.from(CHANNEL_LABEL_I2R), 32)));
  const r2i = Uint8Array.from(Buffer.from(hkdfSync("sha256", ss, th, Buffer.from(CHANNEL_LABEL_R2I), 32)));
  const binding = sha256(Buffer.concat([lp(Buffer.from(BINDING_LABEL)), th]));
  if (hex(initiator.binding) !== hex(binding) || hex(responder.transcriptHash) !== hex(th)) throw new Error("channel keys mismatch");

  const messages = ["", "hello", "x".repeat(300)];
  const records = [];
  for (const [seq, m] of messages.entries()) {
    records.push({ direction: "i2r", seq, message: Buffer.from(m).toString("hex"), record: hex(encryptRecord(i2r, seq, Buffer.from(m))) });
    records.push({ direction: "r2i", seq, message: Buffer.from(m).toString("hex"), record: hex(encryptRecord(r2i, seq, Buffer.from(m))) });
  }
  // the live channel produces the same records
  await initiator.send(Buffer.from(messages[0]));
  if (hex(sent[2]) !== records[0].record) throw new Error("record mismatch");

  return {
    description: 'rfc/SECURE-CHANNEL.md §6: X-Wing channel v1. initiatorSeed and encapsulationRandomness are PUBLIC test values (HKDF of SHA-256("vaultysid/test/" || name)). M1, M2, ss, th, k_i2r, k_r2i, binding, then records for each direction. Fully deterministic.',
    testValuesArePublic: true,
    initiatorSeed: hex(initiatorSeed),
    encapsulationRandomness: hex(encapsulationRandomness),
    m1: hex(m1),
    m2: hex(m2),
    sharedSecret: hex(ss),
    transcriptHash: hex(th),
    keyI2R: hex(i2r),
    keyR2I: hex(r2i),
    binding: hex(binding),
    records,
  };
}

export const VECTORS_PATH = join(__dirname, "xwing-channel-vectors.json");

if (require.main === module) {
  buildVectors().then((vectors) => {
    writeFileSync(VECTORS_PATH, JSON.stringify(vectors, null, 2) + "\n");
    console.log(`wrote ${VECTORS_PATH}: ${vectors.records.length} records`);
  });
}
