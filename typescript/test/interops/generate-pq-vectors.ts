import { writeFileSync } from "fs";
import Challenger from "../../src/Challenger";
import VaultysId from "../../src/VaultysId";

// Dilithium (post-quantum ML-DSA) reference vector for the Challenger
// handcheck protocol.
//
// IMPORTANT SCOPE NOTE: this vector is TypeScript-only. As of this
// writing, the Go implementation (go/pkg/keymanager) has no
// DilithiumManager/HybridManager at all -- it only supports Ed25519 --
// so there is nothing on the Go side to cross-validate against yet
// (unlike challenger-handshake-ed25519.json, which is verified
// byte-for-byte against Go). The Rust implementation does have
// libcrux-ml-dsa-backed Dilithium support and an existing TS<->Rust
// Dilithium interop path (interops/run-cross-language-test.sh
// "dilithium" mode); cross-validating this vector against Rust is a
// natural follow-up once the Rust dependency updates are done.
//
// This vector still documents real, concrete, verified behavior: the
// exact wire bytes TS produces and independently verifies for a
// Dilithium-backed handshake, including actual ML-DSA-65 signatures
// (~3300 bytes), so a future Go/Rust implementer has byte-exact ground
// truth to match rather than starting from prose alone.

function fixedBytes(start: number, n: number): Buffer {
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = (start + i) & 0xff;
  return b;
}

async function main() {
  const aliceEntropy = fixedBytes(0x00, 32);
  const bobEntropy = fixedBytes(0x20, 32);

  const alice = await VaultysId.fromEntropy(aliceEntropy, 1 /* TYPE_PERSON */, "dilithium");
  const bob = await VaultysId.fromEntropy(bobEntropy, 1 /* TYPE_PERSON */, "dilithium");

  const protocol = "vaultys.wot";
  const service = "auth";
  const timestamp = 1735689600000; // 2025-01-01T00:00:00.000Z
  const nonce1 = fixedBytes(0x00, 16);
  const nonce2 = fixedBytes(0x10, 16);
  const combinedNonce = Buffer.concat([nonce1, nonce2]);

  // --- INIT ---
  const initObj: any = {
    version: 1,
    protocol,
    service,
    timestamp,
    pk1: alice.id,
    nonce: nonce1,
    metadata: {},
    state: 0,
  };
  const initChallenger: any = new Challenger(bob);
  initChallenger.challenge = initObj;
  initChallenger.state = 0;
  const initBytes: Buffer = initChallenger.getCertificate();
  const desInit = (Challenger as any).deserializeCertificate(initBytes);
  if (desInit.state !== 0) throw new Error(`INIT failed to self-deserialize: state=${desInit.state} error=${desInit.error}`);

  // --- unsigned bytes signed by both parties ---
  const unsignedObj: any = {
    version: 1,
    protocol,
    service,
    timestamp,
    pk1: alice.id,
    pk2: bob.id,
    nonce: combinedNonce,
    metadata: {},
  };
  const unsignedBytes: Buffer = (Challenger as any).serializeCertificate(unsignedObj);

  const sign2 = await bob.signChallenge(unsignedBytes);
  const bobPub = VaultysId.fromId(bob.id);
  if (!bobPub.verifyChallenge(unsignedBytes, sign2, true)) {
    throw new Error("failed to verify bob's Dilithium sign2 against bob's public ID");
  }

  const step1Obj: any = { ...unsignedObj, sign2, state: 1 };
  const step1Challenger: any = new Challenger(bob);
  step1Challenger.challenge = step1Obj;
  step1Challenger.state = 1;
  const step1Bytes: Buffer = step1Challenger.getCertificate();
  const desStep1 = (Challenger as any).deserializeCertificate(step1Bytes);
  if (desStep1.state !== 1) throw new Error(`STEP1 failed to self-deserialize: state=${desStep1.state} error=${desStep1.error}`);

  const sign1 = await alice.signChallenge(unsignedBytes);
  const alicePub = VaultysId.fromId(alice.id);
  if (!alicePub.verifyChallenge(unsignedBytes, sign1, true)) {
    throw new Error("failed to verify alice's Dilithium sign1 against alice's public ID");
  }

  const completeObj: any = { ...unsignedObj, sign1, sign2, state: 2 };
  const completeChallenger: any = new Challenger(alice);
  completeChallenger.challenge = completeObj;
  completeChallenger.state = 2;
  const completeBytes: Buffer = completeChallenger.getCertificate();
  const desComplete = (Challenger as any).deserializeCertificate(completeBytes);
  if (desComplete.state !== 2) throw new Error(`COMPLETE failed to self-deserialize: state=${desComplete.state} error=${desComplete.error}`);

  const out = {
    description:
      "TypeScript-only reference vector for the Challenger handcheck protocol using Dilithium (post-quantum ML-DSA) identities. Go has no PQ key manager yet (see encodingNotes); this vector gives a future Go/Rust implementation byte-exact ground truth. Cross-validated internally (deserialize + verify) but NOT cross-validated against another language implementation.",
    generated: "vaultys/vaultysid typescript/src/{Challenger,VaultysId,KeyManager/DilithiumManager}, generated for RFC/PROTOCOL.md",
    algorithm: "dilithium (ML-DSA-65 via DilithiumManager)",
    inputs: {
      aliceEntropyHex: aliceEntropy.toString("hex"),
      bobEntropyHex: bobEntropy.toString("hex"),
      protocol,
      service,
      timestampMs: timestamp,
      nonce1Hex: nonce1.toString("hex"),
      nonce2Hex: nonce2.toString("hex"),
    },
    identities: {
      alice: { idHex: alice.id.toString("hex"), idLength: alice.id.length, did: alice.did },
      bob: { idHex: bob.id.toString("hex"), idLength: bob.id.length, did: bob.did },
    },
    steps: [
      { name: "init", state: desInit.state, wireBytesHex: initBytes.toString("hex"), wireBytesLength: initBytes.length, verifiedByPeer: true },
      {
        name: "step1",
        state: desStep1.state,
        unsignedBytesHex: unsignedBytes.toString("hex"),
        sign2Hex: sign2.toString("hex"),
        sign2Length: sign2.length,
        wireBytesHex: step1Bytes.toString("hex"),
        wireBytesLength: step1Bytes.length,
        verifiedByPeer: true,
      },
      {
        name: "complete",
        state: desComplete.state,
        unsignedBytesHex: unsignedBytes.toString("hex"),
        sign1Hex: sign1.toString("hex"),
        sign1Length: sign1.length,
        sign2Hex: sign2.toString("hex"),
        wireBytesHex: completeBytes.toString("hex"),
        wireBytesLength: completeBytes.length,
        verifiedByPeer: true,
      },
    ],
    encodingNotes: [
      "As of this vector's generation, the Go implementation (go/pkg/keymanager) implements only Ed25519 -- no DilithiumManager or HybridManager -- so Go cannot parse this vector's pk1/pk2/signature fields at all yet. This is a known, tracked gap, not an oversight in this vector.",
      "The Rust implementation does support Dilithium (libcrux-ml-dsa) and already has a working TS<->Rust Dilithium interop path (see interops/run-cross-language-test.sh 'dilithium' mode); that is the natural path to cross-validate this vector once Rust's libcrux dependency bump is done.",
      "All general Challenger wire-format rules apply identically regardless of signature algorithm: canonical/minimal-width integer encoding, unsigned timestamp, and the exact per-state field order documented in challenger-handshake-ed25519.json apply here too -- only pk1/pk2/sign1/sign2 grow much larger (Dilithium ML-DSA-65 public keys and signatures are roughly two orders of magnitude bigger than Ed25519's).",
    ],
  };

  writeFileSync(process.argv[2] || "/tmp/pq-vectors.json", JSON.stringify(out, null, 2));
  console.log("Dilithium vector generated and self-verified OK");
  console.log("sign1 length:", sign1.length, "sign2 length:", sign2.length, "pk length:", alice.id.length);
}

main().catch((e) => {
  console.error("FAILED:", e);
  process.exit(1);
});
