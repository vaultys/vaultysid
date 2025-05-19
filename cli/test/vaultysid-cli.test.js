const { execFile } = require("child_process");
const assert = require("assert");
const path = require("path");
const { VaultysId } = require("../../dist/browser/vaultysid.min.js");

// Assuming vaultysid-cli is in the parent directory of the test file
const VAULTYSID_CLI = path.join(__dirname, "../bin", "vaultysid-cli");

// Promisify execFile for easier async/await usage
const execFileAsync = (file, args) => {
  return new Promise((resolve, reject) => {
    execFile(file, args, (error, stdout, stderr) => {
      if (error) reject(error);
      resolve(stdout.trim());
    });
  });
};

describe("vaultysid-cli", function () {
  this.timeout(10000); // Increase timeout if needed
  before(async () => {
    // load once the cli, before starting, so test are faster
    await execFileAsync(VAULTYSID_CLI, ["generate"]);
  });

  let secret1, secret2, secret3, id1, id2, id3, encrypted;

  it("should generate secrets", async function () {
    secret1 = await execFileAsync(VAULTYSID_CLI, ["generate"]);
    secret2 = await execFileAsync(VAULTYSID_CLI, ["generate"]);
    secret3 = await execFileAsync(VAULTYSID_CLI, ["generate"]);

    assert(secret1 && secret1.length > 0, "Secret 1 should be generated");
    assert(secret2 && secret2.length > 0, "Secret 2 should be generated");
    assert(secret3 && secret3.length > 0, "Secret 3 should be generated");
    assert.notStrictEqual(secret1, secret2, "Secrets should be unique");
    assert.notStrictEqual(secret2, secret3, "Secrets should be unique");
    assert.notStrictEqual(secret1, secret3, "Secrets should be unique");
  });

  it("should derive IDs from secrets", async function () {
    id1 = await execFileAsync(VAULTYSID_CLI, ["fromSecret", secret1, "--display", "id"]);
    id2 = await execFileAsync(VAULTYSID_CLI, ["fromSecret", secret2, "--display", "id"]);
    id3 = await execFileAsync(VAULTYSID_CLI, ["fromSecret", secret3, "--display", "id"]);

    const vid = VaultysId.fromSecret(secret1, "base64").toVersion(0);
    assert(id1 && id1.length > 0, "ID 1 should be derived");
    assert.equal(vid.did, VaultysId.fromId(Buffer.from(id1, "base64")).toVersion(0).did);
    assert(id2 && id2.length > 0, "ID 2 should be derived");
    assert(id3 && id3.length > 0, "ID 3 should be derived");
  });

  it("should display DID and fingerprint", async function () {
    const did = await execFileAsync(VAULTYSID_CLI, ["fromSecret", secret1, "--display", "did"]);
    const fingerprint = await execFileAsync(VAULTYSID_CLI, ["fromSecret", secret1, "--display", "fingerprint"]);
    assert(did && did.startsWith("did:"), 'DID should be displayed and start with "did:"');
    assert(fingerprint && fingerprint.length > 0, "Fingerprint should be displayed");
  });

  it("should encrypt and decrypt messages", async function () {
    encrypted = await execFileAsync(VAULTYSID_CLI, ["encrypt", "aGVsbG8gd29ybGQ=", id1, id2]);
    assert(encrypted && encrypted.length > 0, "Message should be encrypted");

    const decrypted1 = await execFileAsync(VAULTYSID_CLI, ["decrypt", encrypted, secret1]);
    const decrypted2 = await execFileAsync(VAULTYSID_CLI, ["decrypt", encrypted, secret2]);

    assert.strictEqual(decrypted1, "aGVsbG8gd29ybGQ=", "Decrypted message should match original for secret1");
    assert.strictEqual(decrypted2, "aGVsbG8gd29ybGQ=", "Decrypted message should match original for secret2");

    try {
      await execFileAsync(VAULTYSID_CLI, ["decrypt", encrypted, secret3]);
      assert.fail("Decryption with secret3 should fail");
    } catch (error) {
      assert(error, "Decryption with secret3 should throw an error");
    }
  });

  it("should sign messages", async function () {
    const signature = await execFileAsync(VAULTYSID_CLI, ["sign", "aGVsbG8gd29ybGQ=", secret1]);
    assert(signature && signature.length > 0, "Signature should be generated");
  });

  it("should verify messages", async function () {
    const vid = VaultysId.fromSecret(secret1, "base64");
    const signature1 = await vid.signChallenge(Buffer.from("aGVsbG8gd29ybGQ=", "base64"));
    const signature = await execFileAsync(VAULTYSID_CLI, ["sign", "aGVsbG8gd29ybGQ=", secret1]);
    //console.log(signature1.toString("base64"), signature);
    assert(signature && signature.length > 0, "Signature should be generated");
    assert.equal(signature, signature1.toString("base64"));
    const verify = await execFileAsync(VAULTYSID_CLI, ["verify", "aGVsbG8gd29ybGQ=", signature1.toString("base64"), "--id", vid.id.toString("base64")]);
    assert.equal(verify, "true");
  });

  it("should deserialize certificate", async function () {
    const result = await execFileAsync(VAULTYSID_CLI, ["deserializeCertificate", "iahwcm90b2NvbKNwMnCnc2VydmljZahyZWdpc3Rlcql0aW1lc3RhbXDPAAABko9gLwijcGsxxHQBhKF2AKFwxQAgthOolbL2HWtbnAkuAyLHAjfbnS8njgLhHlxWlosbC6uheMUAIBXMRt4jV1gxWK5/TF1jNx0kD+v2qKTWFnfEDQsrOeIvoWXFACCwkdnz8o6yhL86amqfB4/nUoznXnmSs9wAIIT30iGhaaNwazLEdACEoXYAoXDFACARZg0feo56ckkSEU8xc0G/xCH5vjeLeQjP9/KtRC4X76F4xQAg9qbrfdWleMqBsN8y7qPmZ1/ObCqFxeQmIopZBwJGfa2hZcUAIHKiC8fHbhLl902mhMbl/h04JvVnWLBCyAGb22orn5dVpW5vbmNlxCAofLkkt7f/YFen3ve05OcpDl8AFJRnejfZbMC6q37gOqVzaWduMcRAby4aZAta/aZL/8NxtqX8NnDUMTfXZ44qEdW5QVl3Gp/nh7sNDtdJfpF3XdJ1bJ7FtinGDDtTkRCzW5Hm9S+EAqVzaWduMsRA0xyketeALY1yA/KbPo7gTWTGdBVyxmG4u60kQJ2WtTDdjhVnCVzlb56xZtWhtGX/DJxw43yEehPyPxI/HvgwB6htZXRhZGF0YYA="]);
    const data = Buffer.from(result, "base64").toString("utf-8");
    const certificate = JSON.parse(data);
    assert.deepEqual(certificate, {
      protocol: "p2p",
      service: "register",
      timestamp: 1728982298376,
      pk1: "AYShdgGhcMQgthOolbL2HWtbnAkuAyLHAjfbnS8njgLhHlxWlosbC6uheMQgFcxG3iNXWDFYrn9MXWM3HSQP6/aopNYWd8QNCys54i+hZcQgsJHZ8/KOsoS/OmpqnweP51KM5155krPcACCE99IhoWk=",
      pk2: "AIShdgGhcMQgEWYNH3qOenJJEhFPMXNBv8Qh+b43i3kIz/fyrUQuF++heMQg9qbrfdWleMqBsN8y7qPmZ1/ObCqFxeQmIopZBwJGfa2hZcQgcqILx8duEuX3TaaExuX+HTgm9WdYsELIAZvbaiufl1U=",
      nonce: "KHy5JLe3/2BXp973tOTnKQ5fABSUZ3o32WzAuqt+4Do=",
      sign1: "by4aZAta/aZL/8NxtqX8NnDUMTfXZ44qEdW5QVl3Gp/nh7sNDtdJfpF3XdJ1bJ7FtinGDDtTkRCzW5Hm9S+EAg==",
      sign2: "0xyketeALY1yA/KbPo7gTWTGdBVyxmG4u60kQJ2WtTDdjhVnCVzlb56xZtWhtGX/DJxw43yEehPyPxI/HvgwBw==",
      metadata: {},
      state: 2,
      error: "",
    });
  });
});
