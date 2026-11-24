import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { VaultysId } from "../typescript/dist/node/index.js";
import { listPassportReaders, readPassportAA } from "@vaultys/passport-nfc";

async function fakeHelper(t, implementation) {
  const directory = await mkdtemp(join(tmpdir(), "vaultys-passport-nfc-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const executable = join(directory, "mock-nfc");
  await writeFile(
    executable,
    `#!/usr/bin/env node
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { sign } = require("node:crypto");
assert.deepEqual(process.argv.slice(2), []);
const request = JSON.parse(readFileSync(0, "utf8"));
${implementation}
`,
    { mode: 0o700 },
  );
  return executable;
}

test("reads the passport data groups and signs a VaultysID message through the helper", async (t) => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = publicKey.export({ type: "spki", format: "der" });
  const dg14 = Buffer.from("6e1b311930170606678108010105020101060a04007f00070101040103", "hex");
  const executable = await fakeHelper(t, `
if (request.operation === "list") {
  assert.equal(Object.keys(request).length, 1);
  console.log(JSON.stringify({readers: ["Test NFC"]}));
} else {
  assert.equal(request.mrz, "test MRZ");
  if (request.operation === "read") {
    console.log(JSON.stringify({reader: "Test NFC", dg15: ${JSON.stringify(spki.toString("base64"))}, dg14: ${JSON.stringify(dg14.toString("base64"))}}));
  } else {
    assert.equal(request.operation, "sign");
    assert.equal(request.reader, "Test NFC");
    assert.equal(request.responseLength, 64);
    assert.equal(new Set(request.challenges).size, 4);
    const key = ${JSON.stringify(privateKey.export({ type: "pkcs8", format: "pem" }))};
    const signatures = request.challenges.map((entry) => {
      const challenge = Buffer.from(entry, "base64");
      assert.equal(challenge.length, 8);
      return sign("sha256", challenge, { key, dsaEncoding: "ieee-p1363" }).toString("base64");
    });
    console.log(JSON.stringify({signatures}));
  }
}
`);
  assert.deepEqual(await listPassportReaders({ executable }), ["Test NFC"]);
  const passport = await readPassportAA({ executable, mrz: "test MRZ" });
  assert.deepEqual(passport.dg15, spki);
  assert.deepEqual(passport.dg14, dg14);
  const identity = VaultysId.fromPassportAA({ ...passport, encryptionSecretKey: Buffer.alloc(32, 42) });
  const message = Buffer.from("NFC integration");
  const proof = await identity.sign(message);
  assert(VaultysId.fromId(identity.id).verify(message, proof));
});

test("reports helper failures, deadlines and invalid bytes", async (t) => {
  const denied = await fakeHelper(t, 'console.error("no PC/SC smart-card reader detected"); process.exit(1);');
  await assert.rejects(readPassportAA({ executable: denied, mrz: "test MRZ" }), /no PC\/SC smart-card reader/);
  const stalled = await fakeHelper(t, "setInterval(() => {}, 1_000);");
  await assert.rejects(listPassportReaders({ executable: stalled, timeoutMs: 500 }), /timed out/);
  const invalid = await fakeHelper(t, 'console.log(JSON.stringify({reader: "Test NFC", dg15: "!!"}));');
  await assert.rejects(readPassportAA({ executable: invalid, mrz: "test MRZ" }), /invalid passport NFC DG15/i);
});
