import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:tls";
import type { Server } from "node:tls";
import type { AddressInfo } from "node:net";
import { after, before, beforeEach, describe, it } from "node:test";
import { Buffer, Challenger, VaultysId } from "../../typescript/index";
import { KMIPSigner } from "@vaultys/id-kmip";
import type { KMIPSignerOptions } from "@vaultys/id-kmip";

const rawEd25519Key = (key: ReturnType<typeof generateKeyPairSync>["publicKey"]) => {
  assert.equal(key.asymmetricKeyType, "ed25519");
  return key.export({ format: "der", type: "spki" }).subarray(-32);
};

function tlsIdentity(name: string, purpose: "serverAuth" | "clientAuth") {
  const directory = mkdtempSync(join(tmpdir(), "vaultys-kmip-"));
  try {
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", `/CN=${name}`, "-addext", `extendedKeyUsage=${purpose}`, "-keyout", "key.pem", "-out", "cert.pem"], {
      cwd: directory,
      stdio: "pipe",
    });
    return { key: readFileSync(join(directory, "key.pem")), cert: readFileSync(join(directory, "cert.pem")) };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

// Fixed KMIP 2.1 TTLV frames for a single Sign batch item, key ID "ed-key".
// Keep the wire fixtures independent of the production encoder and decoder.
const protocolVersion = "420069010000002042006a0200000004000000020000000042006b02000000040000000100000000";
const batchCount = "42000d02000000040000000100000000";
const responseHeader = "42007a0100000048" + protocolVersion + "4200920900000008000000006553f100" + batchCount;
const operation = "42005c05000000040000002100000000";
const success = "42007f05000000040000000000000000";
const keyId = "420094070000000665642d6b65790000";
const signatureTag = "4200c30800000040";
const signRequestPrefix = "42007801000000b04200770100000038" + protocolVersion + batchCount + "42000f0100000068" + operation + "4200790100000050" + keyId + "42002b0100000010420028050000000400000037000000004200c20800000020";

const signedResponse = (signature: Uint8Array, uid = keyId) => Buffer.from("42007b01000000d8" + responseHeader + "42000f0100000080" + operation + success + "42007c0100000058" + uid + signatureTag + Buffer.from(signature).toString("hex"), "hex");

describe("KMIP-backed type 01", { timeout: 5000 }, () => {
  const signingKey = generateKeyPairSync("ed25519");
  const otherKey = generateKeyPairSync("ed25519");
  const publicKey = rawEd25519Key(signingKey.publicKey);
  // Choose the exact Ed25519 and X25519 keys a local VaultysId would use.
  const encryptionSecret = Buffer.alloc(32, 42);
  const seed = signingKey.privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const localSecret = Buffer.concat([Buffer.from("0183a17601a178c420", "hex"), seed, Buffer.from("a165c420", "hex"), encryptionSecret]);
  const local = VaultysId.fromSecret(localSecret);

  let server: Server;
  let options: KMIPSignerOptions;
  let reply: (data: Buffer) => Buffer | undefined;
  let seen: Buffer[];

  before(async () => {
    const serverTls = tlsIdentity("kmip.test", "serverAuth");
    const clientTls = tlsIdentity("vaultys.test", "clientAuth");
    server = createServer({ ...serverTls, ca: clientTls.cert, requestCert: true, rejectUnauthorized: true }, (socket) => {
      assert.equal(socket.authorized, true);
      socket.on("error", () => socket.destroy());
      let request = Buffer.alloc(0);
      socket.on("data", (chunk) => {
        request = Buffer.concat([request, chunk]);
        if (request.length < 8 || request.length < 8 + request.readUInt32BE(4)) return;
        const data = request.subarray(-32);
        if (request.toString("hex") !== signRequestPrefix + data.toString("hex")) socket.destroy();
        assert.equal(request.toString("hex"), signRequestPrefix + data.toString("hex"));
        seen.push(data);
        const response = reply(data);
        if (response) {
          // Split the outer header and payload across separate writes.
          socket.write(response.subarray(0, 3));
          setImmediate(() => socket.write(response.subarray(3)));
        }
      });
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    options = { ...clientTls, ca: serverTls.cert, host: "127.0.0.1", servername: "kmip.test", port: (server.address() as AddressInfo).port, keyId: "ed-key", publicKey };
  });

  after(async () => {
    if (server?.listening) await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  });

  beforeEach(() => {
    seen = [];
    reply = (data) => signedResponse(nodeSign(null, data, signingKey.privateKey));
  });

  it("preserves IDs, DIDs, and all signing domains, including after reattaching the signer", async () => {
    const identity = await VaultysId.fromSigner(new KMIPSigner(options), encryptionSecret);
    assert.equal(identity.type, 0x01);
    assert.equal(identity.id.toString("hex"), local.id.toString("hex"));
    assert.equal(identity.did, local.did);
    assert.deepEqual(identity.didDocument, local.didDocument);
    assert.throws(() => identity.getSecret(), /Cannot export/);

    const restored = await VaultysId.fromSigner(new KMIPSigner(options), encryptionSecret);
    const verifier = VaultysId.fromId(identity.id);
    const data = Buffer.from("00ff3071", "hex");
    const raw = await restored.sign(data);
    const challenge = await identity.signChallenge(data);
    const handshake = await identity.signHandshake(data);
    for (const [index, domain] of ["VAULTYS_RAW", "VAULTYS_SIGN", "VAULTYS_HANDSHAKE_V1"].entries()) {
      assert.equal(seen[index].toString("hex"), createHash("sha256").update(domain).update(data).digest("hex"));
    }
    assert.equal(raw.toString("hex"), (await local.sign(data)).toString("hex"));
    assert(verifier.verify(data, raw));
    assert(verifier.verifyChallenge(data, challenge, false));
    assert(verifier.verifyHandshake(data, handshake));
    assert(!verifier.verifyChallenge(data, raw, false));
    assert(!verifier.verify(Buffer.from([0]), raw));
    assert.equal((await identity.hmac("test"))?.toString("hex"), (await local.hmac("test"))?.toString("hex"));

    assert.equal(identity.toVersion(0).id.toString("hex"), local.toVersion(0).id.toString("hex"));
    local.toVersion(1);
    identity.keyManager.cleanSecureData();
    await assert.rejects(identity.sign(data), /Could not sign/);
    assert.equal(seen.length, 3);
  });

  it("accepts pluggable Ed25519 signers and rejects a secp256k1 public key", async () => {
    const identity = await VaultysId.fromSigner(
      {
        getPublicKey: async () => publicKey,
        sign: async (data) => nodeSign(null, data, signingKey.privateKey),
      },
      encryptionSecret,
    );
    assert.equal(identity.did, local.did);
    const secp256k1 = generateKeyPairSync("ec", { namedCurve: "secp256k1" });
    const message = Buffer.from("1234", "hex");
    const digest = createHash("sha256").update("VAULTYS_RAW").update(message).digest();
    const ecdsaSignature = nodeSign("sha256", digest, { key: secp256k1.privateKey, dsaEncoding: "ieee-p1363" });
    assert.equal(ecdsaSignature.length, 64);
    assert(!VaultysId.fromId(identity.id).verify(message, ecdsaSignature));
    await assert.rejects(
      VaultysId.fromSigner(
        {
          getPublicKey: async () => secp256k1.publicKey.export({ format: "der", type: "spki" }),
          sign: async (data) => nodeSign("sha256", data, secp256k1.privateKey),
        },
        encryptionSecret,
      ),
      /Ed25519 public key/,
    );
  });

  it("completes a relationship handshake with a software peer", async () => {
    const identity = await VaultysId.fromSigner(new KMIPSigner(options), encryptionSecret);
    const initiator = new Challenger(await VaultysId.generateMachine());
    const responder = new Challenger(identity);
    initiator.createChallenge("p2p", "auth");
    await responder.update(initiator.getCertificate());
    await initiator.update(responder.getCertificate());
    await responder.update(initiator.getCertificate());
    assert(initiator.isComplete());
    assert(responder.isComplete());
    assert.equal(initiator.getContactId().did, identity.did);
    assert(await Challenger.verifyCertificate(initiator.getCertificate()));
    assert.equal(seen.length, 1);
  });

  it("rejects a signature from a different key or over different bytes", async () => {
    const identity = await VaultysId.fromSigner(new KMIPSigner(options), encryptionSecret);
    reply = (data) => signedResponse(nodeSign(null, data, otherKey.privateKey));
    await assert.rejects(identity.sign("abcd"), /did not verify/);
    reply = (data) => signedResponse(nodeSign(null, createHash("sha256").update(data).digest(), signingKey.privateKey));
    await assert.rejects(identity.sign("abcd"), /did not verify/);
    reply = (data) => signedResponse(nodeSign(null, data, signingKey.privateKey), "4200940700000006616c742d69640000");
    await assert.rejects(identity.sign("abcd"), /key ID does not match/);
  });

  it("reports KMIP operation failures and rejects an untrusted TLS endpoint", async () => {
    reply = () => Buffer.from("42007b0100000088" + responseHeader + "42000f0100000030" + operation + "42007f0500000004000000010000000042007e05000000040000000500000000", "hex");
    const identity = await VaultysId.fromSigner(new KMIPSigner(options), encryptionSecret);
    await assert.rejects(identity.sign("abcd"), /KMIP Sign failed \(status 1, reason 0x00000005\)/);
    const untrusted = await VaultysId.fromSigner(new KMIPSigner({ ...options, servername: "other.test" }), encryptionSecret);
    await assert.rejects(untrusted.sign("abcd"), { code: "ERR_TLS_CERT_ALTNAME_INVALID" });
    const untrustedClient = tlsIdentity("unknown.test", "clientAuth");
    await assert.rejects(new KMIPSigner({ ...options, ...untrustedClient }).sign(Buffer.alloc(32)));
    assert.equal(seen.length, 1);
  });

  it("rejects malformed and oversized KMIP frames", async () => {
    const identity = await VaultysId.fromSigner(new KMIPSigner(options), encryptionSecret);
    reply = () => Buffer.from("42007b0100010000", "hex");
    await assert.rejects(identity.sign("abcd"), /Invalid KMIP response header/);
    reply = (data) => {
      const response = signedResponse(nodeSign(null, data, signingKey.privateKey));
      // Set the Signature Data length one byte short, retaining the TTLV padding.
      response.writeUInt32BE(63, response.length - 68);
      return response;
    };
    await assert.rejects(identity.sign("abcd"), /invalid Ed25519 signature length/);
  });

  it("times out if the endpoint leaves a Sign request unanswered", async () => {
    reply = () => undefined;
    const identity = await VaultysId.fromSigner(new KMIPSigner({ ...options, timeoutMs: 500 }), encryptionSecret);
    await assert.rejects(identity.sign("abcd"), /KMIP Sign timed out/);
    assert.equal(seen.length, 1);
  });
});
