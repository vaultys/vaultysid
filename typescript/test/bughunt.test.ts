// Regression tests for the bug-hunt report (numbers refer to its findings).
import assert from "assert";
import "./shims";
import * as nodeCrypto from "crypto";
import cbor from "cbor";
import { Buffer, IdManager, MemoryChannel, MemoryStorage, VaultysId } from "../";
import { hash, randomBytes } from "../src/crypto";
import { deserialize, serialize } from "../src/MemoryStorage";
import { convertWebWritableStreamToNodeWritable, StreamChannel } from "../src/MemoryChannel";
import { decrypt } from "../src/platform/pbkdf2.node";
import { encryptInfo } from "../src/platform/abstract";
import DeprecatedKeyManager from "../src/KeyManager/DeprecatedKeyManager";
import { Ed25519Manager } from "../src/KeyManager";
import SoftCredentials from "../src/platform/SoftCredentials";

const connect = async (a: IdManager, b: IdManager) => {
  const channel = MemoryChannel.createBidirectionnal();
  await Promise.all([a.askContact(channel), b.acceptContact(channel.otherend!)]);
};

describe("Bug hunt regressions", () => {
  it("#1 serialize keeps plain arrays as arrays", () => {
    const back = deserialize(serialize({ list: ["a", "b"], nums: [1, 2], bytes: new Uint8Array([1, 2]) }));
    assert.deepEqual(back.list, ["a", "b"]);
    assert.deepEqual(back.nums, [1, 2]);
    assert.ok(Buffer.from([1, 2]).equals(back.bytes));
  });

  it("#2 web writable bridge forwards every chunk", async () => {
    const received: string[] = [];
    const web = new WritableStream({ write: (chunk) => void received.push(Buffer.from(chunk).toString()) });
    const node = convertWebWritableStreamToNodeWritable(web);
    await new Promise<void>((resolve, reject) => {
      node.on("error", reject);
      node.write("a");
      node.write("b");
      node.end("c", resolve);
    });
    assert.deepEqual(received, ["a", "b", "c"]);
  });

  it("#3 StreamChannel download finishes when the upload ran first", async () => {
    const channel = MemoryChannel.createBidirectionnal();
    await StreamChannel(channel).uploadData(Buffer.from("hello"));
    const data = await StreamChannel(channel.otherend!).downloadData();
    assert.equal(data.toString(), "hello");
  }).timeout(2000);

  it("#4/#12/#13/#14 ES256 soft credentials round trip", async () => {
    const request = SoftCredentials.createRequest(-7);
    const attestation = await SoftCredentials.create(request);
    const response = attestation.response as AuthenticatorAttestationResponse;
    assert.equal(SoftCredentials.extractChallenge(response.clientDataJSON), Buffer.from(request.publicKey!.challenge as ArrayBuffer).toString("base64"));
    const ato = cbor.decode(Buffer.from(response.attestationObject));
    const coseKey = cbor.decode(Buffer.from(ato.authData).subarray(37 + 16 + 2 + attestation.rawId.byteLength));
    assert.equal(coseKey.get(-1), 1, "P-256 curve id");

    const assertion = await SoftCredentials.get({
      publicKey: { challenge: randomBytes(32), allowCredentials: [{ type: "public-key", id: attestation.rawId }] },
    });
    const userHandle = (assertion.response as AuthenticatorAssertionResponse).userHandle!;
    assert.equal(Buffer.from(userHandle).toString("utf8"), "Vaultys Wallet ID");
    assert.equal(await SoftCredentials.verify(attestation, assertion), true);
  });

  it("#7 deprecated key manager verifies its own swap certificate", async () => {
    const km = await DeprecatedKeyManager.create_Id25519_fromEntropy(randomBytes(32));
    const hiscp = await km.createSwapingCertificate();
    assert.ok(hiscp);
    assert.equal(await km.verifySwapingCertificate(hiscp!), true);
  });

  it("#8 saveApp persists the store", async () => {
    let saves = 0;
    const manager = new IdManager(
      await VaultysId.generatePerson(),
      MemoryStorage(() => void saves++),
    );
    const before = saves;
    manager.saveApp(await VaultysId.generateMachine(), "app");
    assert.equal(saves, before + 1);
  });

  it("#9 listCertificates does not break verifyWebOfTrust", async () => {
    const alice = new IdManager(
      await VaultysId.generatePerson(),
      MemoryStorage(() => ""),
    );
    await connect(
      alice,
      new IdManager(
        await VaultysId.generatePerson(),
        MemoryStorage(() => ""),
      ),
    );
    assert.ok(alice.listCertificates().length > 0);
    assert.equal(await alice.verifyWebOfTrust(), true);
    // stores already rewritten by the old listCertificates still verify
    const wot = alice.store.substore("wot");
    for (const id of wot.list()) wot.set(id, { timestamp: 1, raw: wot.get(id) });
    assert.equal(await alice.verifyWebOfTrust(), true);
  }).timeout(30000);

  it("#11 decrypt uses the backup's own key derivation parameters", async () => {
    const info = { ...encryptInfo, ITERATIONS: 1000, HASH: "SHA-512" };
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const key = nodeCrypto.pbkdf2Sync("passphrase", salt, info.ITERATIONS, 32, "sha512");
    const cipher = nodeCrypto.createCipheriv("aes-256-gcm", key, iv);
    const data = Buffer.concat([cipher.update(Buffer.from("secret")), cipher.final(), cipher.getAuthTag()]);
    const plain = await decrypt({ version: 1, encryptInfo: { ...info, salt: salt.toString("base64"), iv: iv.toString("base64") }, data }, "passphrase");
    assert.equal(plain?.toString(), "secret");
  });

  it("#15 public-only managers refuse to sign", async () => {
    const vid = await VaultysId.generatePerson("ed25519");
    const km = Ed25519Manager.instantiate(JSON.parse(JSON.stringify(vid.keyManager)));
    assert.equal(km.capability, "public");
    assert.equal(await km.sign(Buffer.from("data")), null);
  });

  it("#19 unsupported hash algorithms throw", () => {
    assert.throws(() => hash("sha1", Buffer.from("x")), /Unsupported hash algorithm/);
  });
});
