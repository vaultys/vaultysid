/**
 * Deterministic cross-language vectors for the 4.0.0 security spec
 * (handshake v1 / VAULTYS_HANDSHAKE_V1, DHIES v2, VAULTYS_RAW, OTP).
 *
 *   npx tsx test/interops/generate-security-v2-vectors.ts
 *
 * Writes test/interops/security-v2-vectors.json and copies it to
 * ../go/test/compatibility/testdata/ and ../rust/tests/data/.
 * Running it twice produces byte-identical output.
 */
import { copyFileSync, mkdirSync, writeFileSync } from "fs";
import { dirname, resolve } from "path";
import { Buffer } from "buffer/";
import nacl from "tweetnacl";
import VaultysId from "../../src/VaultysId";
import Challenger, { ChallengeType } from "../../src/Challenger";
import { hash } from "../../src/crypto";
import { dhiesV2Decrypt, dhiesV2Encrypt } from "../../src/KeyManager/dhies";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

export async function generateSecurityV2Vectors() {
  const aliceEntropy = Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex");
  const bobEntropy = Buffer.from("f0e0d0c0b0a090807060504030201000f1e1d1c1b1a191817161514131211101", "hex");
  const alice = await VaultysId.fromEntropy(aliceEntropy, 1, "ed25519"); // person
  const bob = await VaultysId.fromEntropy(bobEntropy, 0, "ed25519"); // machine

  // ---- (a) complete v1 handshake certificate ------------------------------------
  const challenge: ChallengeType = {
    version: 1,
    protocol: "p2p",
    service: "auth",
    timestamp: 1700000000000,
    pk1: alice.id,
    pk2: bob.id,
    nonce: Buffer.from("00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100", "hex"),
    metadata: { pk1: { name: "alice" }, pk2: { name: "bob" } },
    state: 1,
  };
  const unsigned = Challenger.serializeCertificate(challenge);
  const handshakeDigest = hash("sha256", Buffer.concat([Buffer.from("VAULTYS_HANDSHAKE_V1", "ascii"), unsigned]));
  challenge.sign2 = await bob.signHandshake(unsigned);
  challenge.sign1 = await alice.signHandshake(unsigned);

  const serializer = new Challenger(alice);
  serializer.challenge = { ...challenge, sign1: undefined, state: 0, pk2: undefined, nonce: challenge.nonce!.subarray(0, 16), metadata: { pk1: challenge.metadata.pk1 } };
  const init = serializer.getCertificate();
  serializer.challenge = { ...challenge, sign1: undefined, state: 1 };
  const step1 = serializer.getCertificate();
  serializer.challenge = { ...challenge, state: 2 };
  const complete = serializer.getCertificate();

  const parsed = Challenger.deserializeCertificate(complete);
  if (parsed.state !== 2) throw new Error("generated certificate does not verify: " + parsed.error);
  if (Challenger.deserializeCertificate(step1).state !== 1) throw new Error("generated STEP1 does not verify");
  if (Challenger.deserializeCertificate(init).state !== 0) throw new Error("generated INIT does not parse");

  // ---- (b) DHIES v2 from alice to bob ---------------------------------------------
  const plaintext = "VaultysID DHIES v2 cross-language test vector";
  const ephemeralSecretKey = Buffer.from("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "hex");
  const dhiesNonce = Buffer.from("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7", "hex");
  const aliceCypher = await alice.keyManager.getCypher();
  const bobCypher = await bob.keyManager.getCypher();
  const dhies = await dhiesV2Encrypt(plaintext, aliceCypher.diffieHellman, alice.keyManager.cypher.publicKey, bob.keyManager.cypher.publicKey, {
    ephemeralSecretKey,
    nonce: dhiesNonce,
  });
  const check = await dhiesV2Decrypt(dhies, bobCypher.diffieHellman, bob.keyManager.cypher.publicKey, alice.keyManager.cypher.publicKey);
  if (check?.toString("utf-8") !== plaintext) throw new Error("DHIES v2 vector does not decrypt");
  const ephemeralPublicKey = Buffer.from(nacl.box.keyPair.fromSecretKey(ephemeralSecretKey).publicKey);
  const es = Buffer.from(nacl.scalarMult(ephemeralSecretKey, bob.keyManager.cypher.publicKey));
  const ss = Buffer.from(nacl.scalarMult(alice.keyManager.cypher.secretKey!, bob.keyManager.cypher.publicKey));
  const dhiesKey = hash("sha512", Buffer.concat([es, ss, Buffer.from("VAULTYS_DHIES_V2", "ascii"), ephemeralPublicKey, alice.keyManager.cypher.publicKey, bob.keyManager.cypher.publicKey])).subarray(0, 32);

  // ---- (c) VAULTYS_RAW signature (and VAULTYS_SIGN for comparison) ------------------
  const rawMessage = Buffer.from("VaultysID VAULTYS_RAW cross-language test vector", "utf-8");
  const rawSignature = await alice.sign(rawMessage);
  const rawDigest = hash("sha256", Buffer.concat([Buffer.from("VAULTYS_RAW", "ascii"), rawMessage]));
  const signChallengeSignature = await alice.signChallenge(rawMessage);
  const signDigest = hash("sha256", Buffer.concat([Buffer.from("VAULTYS_SIGN", "ascii"), rawMessage]));
  if (!VaultysId.fromId(alice.id).verify(rawMessage, rawSignature)) throw new Error("raw signature does not verify");

  // ---- (d) OTP ------------------------------------------------------------------------
  const otpTime = 1700000000000;
  const otpTimelock = 24 * 3600000;
  const bobContact = VaultysId.fromId(bob.id, complete);
  const aliceContact = VaultysId.fromId(alice.id, complete);
  const otp = await alice.getOTP(bobContact, "password", otpTimelock, otpTime);
  if (otp !== (await bob.getOTP(aliceContact, "password", otpTimelock, otpTime))) throw new Error("OTP mismatch");

  return {
    description: "VaultysID 4.0.0 security spec cross-language vectors (generated by TypeScript, deterministic)",
    generator: "typescript/test/interops/generate-security-v2-vectors.ts",
    identities: {
      alice: {
        entropy: hex(aliceEntropy),
        type: alice.type,
        algorithm: "ed25519",
        id: hex(alice.id),
        did: alice.did,
        secret: alice.getSecret(),
        signingPublicKey: hex(alice.keyManager.signer.publicKey),
        cypherPublicKey: hex(alice.keyManager.cypher.publicKey),
      },
      bob: {
        entropy: hex(bobEntropy),
        type: bob.type,
        algorithm: "ed25519",
        id: hex(bob.id),
        did: bob.did,
        secret: bob.getSecret(),
        signingPublicKey: hex(bob.keyManager.signer.publicKey),
        cypherPublicKey: hex(bob.keyManager.cypher.publicKey),
      },
    },
    handshake: {
      domain: "VAULTYS_HANDSHAKE_V1",
      initiator: "alice",
      responder: "bob",
      version: challenge.version,
      protocol: challenge.protocol,
      service: challenge.service,
      timestamp: challenge.timestamp,
      nonce: hex(challenge.nonce!),
      metadata: challenge.metadata,
      init: hex(init),
      step1: hex(step1),
      complete: hex(complete),
      unsignedBytes: hex(unsigned),
      handshakeDigest: hex(handshakeDigest),
      sign1: hex(challenge.sign1!),
      sign2: hex(challenge.sign2!),
    },
    dhiesV2: {
      sender: "alice",
      recipient: "bob",
      plaintext,
      plaintextHex: hex(Buffer.from(plaintext, "utf-8")),
      ephemeralSecretKey: hex(ephemeralSecretKey),
      ephemeralPublicKey: hex(ephemeralPublicKey),
      nonce: hex(dhiesNonce),
      key: hex(dhiesKey),
      ciphertext: hex(dhies),
    },
    rawSignature: {
      domain: "VAULTYS_RAW",
      signer: "alice",
      message: rawMessage.toString("utf-8"),
      messageHex: hex(rawMessage),
      digest: hex(rawDigest),
      signature: hex(rawSignature),
    },
    signChallenge: {
      domain: "VAULTYS_SIGN",
      signer: "alice",
      messageHex: hex(rawMessage),
      digest: hex(signDigest),
      signature: hex(signChallengeSignature),
    },
    otp: {
      description: "HMAC-SHA256(SHA-256(X25519(own cypher sk, remote cypher pk)), prefix || certificate || uint64be(floor(time / timelock)))",
      prefix: "password",
      certificate: "handshake.complete",
      time: otpTime,
      timelock: otpTimelock,
      counter: Math.floor(otpTime / otpTimelock),
      otp,
    },
  };
}

if (require.main === module) {
  generateSecurityV2Vectors()
    .then((vectors) => {
      const json = JSON.stringify(vectors, null, 2) + "\n";
      const main = resolve(__dirname, "security-v2-vectors.json");
      writeFileSync(main, json);
      console.log("wrote", main);
      for (const target of [resolve(__dirname, "../../../go/test/compatibility/testdata/security-v2-vectors.json"), resolve(__dirname, "../../../rust/tests/data/security-v2-vectors.json")]) {
        mkdirSync(dirname(target), { recursive: true });
        copyFileSync(main, target);
        console.log("copied to", target);
      }
    })
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
