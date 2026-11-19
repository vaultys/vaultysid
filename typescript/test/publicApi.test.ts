import assert from "assert";
import nacl from "tweetnacl";
import { Buffer } from "buffer/";
import * as pkg from "..";
import "./shims";
import { dhiesV2Encrypt as dhiesV2EncryptWith } from "../src/KeyManager/dhies";

// The package must not let callers pin the randomness of DHIES encryption (fixed ephemeral key and nonce).

describe("public API", () => {
  it("dhiesV2Encrypt ignores a testing argument", async () => {
    const sender = nacl.box.keyPair();
    const recipient = nacl.box.keyPair();
    const senderDH = async (pk: Buffer) => nacl.scalarMult(sender.secretKey, pk);
    const pinned = { ephemeralSecretKey: new Uint8Array(32).fill(7), nonce: new Uint8Array(24).fill(9) };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const encrypt = pkg.dhiesV2Encrypt as (...args: any[]) => Promise<Buffer>;
    const a = await encrypt("same", senderDH, sender.publicKey, recipient.publicKey, pinned);
    const b = await encrypt("same", senderDH, sender.publicKey, recipient.publicKey, pinned);
    assert.ok(!Buffer.from(a).equals(Buffer.from(b)));
    // the internal function, used by the vector generators, still honours it
    const c = await dhiesV2EncryptWith("same", senderDH, sender.publicKey, recipient.publicKey, pinned);
    const d = await dhiesV2EncryptWith("same", senderDH, sender.publicKey, recipient.publicKey, pinned);
    assert.ok(Buffer.from(c).equals(Buffer.from(d)));
  });
});
