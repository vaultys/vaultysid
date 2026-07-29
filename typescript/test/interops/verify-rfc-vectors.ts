import { readFileSync } from "fs";
import Challenger from "../../src/Challenger";
import VaultysId from "../../src/VaultysId";

async function main() {
  const vectors = JSON.parse(readFileSync(process.argv[2], "utf8"));

  const alice = VaultysId.fromSecret(vectors.identities.alice.secretHex);
  const bob = VaultysId.fromSecret(vectors.identities.bob.secretHex);

  if (alice.id.toString("hex") !== vectors.identities.alice.idHex) {
    throw new Error(`alice id mismatch: TS=${alice.id.toString("hex")} GO=${vectors.identities.alice.idHex}`);
  }
  if (bob.id.toString("hex") !== vectors.identities.bob.idHex) {
    throw new Error(`bob id mismatch: TS=${bob.id.toString("hex")} GO=${vectors.identities.bob.idHex}`);
  }
  if (alice.did !== vectors.identities.alice.did) {
    throw new Error(`alice DID mismatch: TS=${alice.did} GO=${vectors.identities.alice.did}`);
  }
  if (bob.did !== vectors.identities.bob.did) {
    throw new Error(`bob DID mismatch: TS=${bob.did} GO=${vectors.identities.bob.did}`);
  }
  console.log("OK: identities (id bytes + DID) match Go byte-for-byte");

  const { protocol, service, timestampMs, nonce1Hex, nonce2Hex } = vectors.inputs;
  const nonce1 = Buffer.from(nonce1Hex, "hex");
  const nonce2 = Buffer.from(nonce2Hex, "hex");
  const combinedNonce = Buffer.concat([nonce1, nonce2]);

  // --- INIT: build the exact object Go used, serialize via the real `serialize()` ---
  const initObj: any = {
    version: 1,
    protocol,
    service,
    timestamp: timestampMs,
    pk1: alice.id,
    nonce: nonce1,
    metadata: {},
    state: 0,
  };
  const initChallenger: any = new Challenger(bob); // instance unused except to reach getCertificate()
  initChallenger.challenge = initObj;
  initChallenger.state = 0;
  const initBytes: Buffer = initChallenger.getCertificate();
  const goInit = vectors.steps.find((s: any) => s.name === "init");
  if (initBytes.toString("hex") !== goInit.wireBytesHex) {
    throw new Error(`INIT wire bytes mismatch:\nTS=${initBytes.toString("hex")}\nGO=${goInit.wireBytesHex}`);
  }
  console.log("OK: INIT wire bytes match Go byte-for-byte");

  // --- unsigned bytes used for both sign1 and sign2 ---
  const unsignedObj: any = {
    version: 1,
    protocol,
    service,
    timestamp: timestampMs,
    pk1: alice.id,
    pk2: bob.id,
    nonce: combinedNonce,
    metadata: {},
  };
  const unsignedBytes: Buffer = (Challenger as any).serializeCertificate(unsignedObj);
  const goStep1 = vectors.steps.find((s: any) => s.name === "step1");
  if (unsignedBytes.toString("hex") !== goStep1.unsignedBytesHex) {
    throw new Error(`unsigned bytes mismatch:\nTS=${unsignedBytes.toString("hex")}\nGO=${goStep1.unsignedBytesHex}`);
  }
  console.log("OK: unsigned (signed-over) bytes match Go byte-for-byte");

  // --- verify Go's sign2/sign1 actually verify under TS ---
  const sign2 = Buffer.from(goStep1.sign2Hex, "hex");
  const bobOk = bob.verifyChallenge(unsignedBytes, sign2, true);
  if (!bobOk) throw new Error("TS failed to verify Go-produced sign2");
  console.log("OK: TS verifies Go-produced sign2 against bob's key");

  const goComplete = vectors.steps.find((s: any) => s.name === "complete");
  const sign1 = Buffer.from(goComplete.sign1Hex, "hex");
  const aliceOk = alice.verifyChallenge(unsignedBytes, sign1, true);
  if (!aliceOk) throw new Error("TS failed to verify Go-produced sign1");
  console.log("OK: TS verifies Go-produced sign1 against alice's key");

  // --- TS independently signs the same payload and Go-side signatures should be reproducible-format (not byte-identical, Ed25519 is deterministic per RFC8032 so it actually SHOULD be byte identical) ---
  const tsSign2 = await bob.signChallenge(unsignedBytes);
  if (tsSign2.toString("hex") !== sign2.toString("hex")) {
    throw new Error(`sign2 not byte-identical (Ed25519 should be deterministic):\nTS=${tsSign2.toString("hex")}\nGO=${sign2.toString("hex")}`);
  }
  console.log("OK: TS-produced sign2 is byte-identical to Go-produced sign2 (deterministic Ed25519)");

  // --- STEP1 and COMPLETE wire bytes ---
  const step1Obj: any = { ...unsignedObj, sign2, state: 1 };
  const step1Challenger: any = new Challenger(bob);
  step1Challenger.challenge = step1Obj;
  step1Challenger.state = 1;
  const step1Bytes: Buffer = step1Challenger.getCertificate();
  if (step1Bytes.toString("hex") !== goStep1.wireBytesHex) {
    throw new Error(`STEP1 wire bytes mismatch:\nTS=${step1Bytes.toString("hex")}\nGO=${goStep1.wireBytesHex}`);
  }
  console.log("OK: STEP1 wire bytes match Go byte-for-byte");

  const completeObj: any = { ...unsignedObj, sign1, sign2, state: 2 };
  const completeChallenger: any = new Challenger(alice);
  completeChallenger.challenge = completeObj;
  completeChallenger.state = 2;
  const completeBytes: Buffer = completeChallenger.getCertificate();
  if (completeBytes.toString("hex") !== goComplete.wireBytesHex) {
    throw new Error(`COMPLETE wire bytes mismatch:\nTS=${completeBytes.toString("hex")}\nGO=${goComplete.wireBytesHex}`);
  }
  console.log("OK: COMPLETE wire bytes match Go byte-for-byte");

  console.log("\nALL CROSS-LANGUAGE CHECKS PASSED");
}

main().catch((e) => {
  console.error("FAILED:", e.message);
  process.exit(1);
});
