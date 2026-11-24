import assert from "node:assert/strict";
import { constants, createHash, generateKeyPairSync, privateEncrypt, randomBytes, sign } from "node:crypto";
import { encode } from "@msgpack/msgpack";
import { Buffer, Challenger, IdManager, MemoryStorage, VaultysId, createPassportAAReader } from "../index";

const sha256 = (...parts: Uint8Array[]) => {
  const digest = createHash("sha256");
  for (const part of parts) digest.update(part);
  return Buffer.from(digest.digest());
};

const ecKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const ecSpki = Buffer.from(ecKey.publicKey.export({ type: "spki", format: "der" }));
const dg15 = Buffer.concat([Buffer.from([0x6f, ecSpki.length]), ecSpki]);
// DG14 wrapping a SecurityInfos SET with one ActiveAuthenticationInfo (P-256 / SHA-256).
const ecDG14 = Buffer.from("6e1b311930170606678108010105020101060a04007f00070101040103", "hex");
const encryptionSecretKey = Buffer.alloc(32, 7);

function ecReader(onChallenge: (challenge: Buffer) => void = () => {}) {
  return createPassportAAReader(async (command) => {
    const apdu = Buffer.from(command);
    assert.equal(apdu.length, 14);
    assert.equal(apdu.slice(0, 5).toString("hex"), "0088000008");
    assert.equal(apdu[13], 0);
    const challenge = apdu.slice(5, 13);
    onChallenge(challenge);
    const signature = sign("sha256", challenge, { key: ecKey.privateKey, dsaEncoding: "ieee-p1363" });
    return Buffer.concat([signature, Buffer.from("9000", "hex")]);
  });
}

describe("passport Active Authentication", function () {
  this.timeout(10_000);

  it("signs a message through four ICAO commands and verifies it from a public ID", async () => {
    const challenges: Buffer[] = [];
    const reader = ecReader((challenge) => challenges.push(challenge));
    const identity = VaultysId.fromPassportAA({ dg15, dg14: ecDG14, reader, encryptionSecretKey });
    const publicIdentity = VaultysId.fromId(identity.id);
    assert.equal(identity.type, 0x05);
    assert.equal(identity.did, publicIdentity.did);
    assert.equal(identity.did, VaultysId.fromPassportAA({ dg15: ecSpki, dg14: ecDG14, reader, encryptionSecretKey }).did);
    assert.equal(identity.toVersion(0).version, 1);
    assert.equal(identity.keyManager.signer.secretKey, undefined);
    assert.throws(() => identity.getSecret(), /Cannot export/);
    assert.throws(() => VaultysId.fromSecret(Buffer.from([0x05, 0x00])), /fromPassportAA/);
    assert.throws(() => VaultysId.fromId(Buffer.concat([identity.id, Buffer.from([0])])), /Invalid VaultysId id/);

    const message = Buffer.from("message");
    const signature = await identity.sign(message);
    assert.equal(challenges.length, 4);
    assert.equal(new Set(challenges.map((c) => c.toString("hex"))).size, 4);
    assert.equal(signature.length, 32 + 4 * 64);
    const digest = sha256(Buffer.from("VAULTYS_RAW"), message);
    const expected = sha256(Buffer.from("VAULTYS_PASSPORT_AA_V1"), sha256(identity.id), digest, signature.slice(0, 32));
    assert.deepEqual(Buffer.concat(challenges), expected);
    assert(publicIdentity.verify(message, signature));
    assert(!publicIdentity.verify(Buffer.from("tampered"), signature));
    assert(!publicIdentity.verifyChallenge(message, signature, false));
    assert(!publicIdentity.verify(message, signature.slice(0, -1)));
    const reordered = Buffer.concat([signature.slice(0, 32), signature.slice(96, 160), signature.slice(32, 96), signature.slice(160)]);
    assert(!publicIdentity.verify(message, reordered));
    const alteredSalt = Buffer.from(signature);
    alteredSalt[0] ^= 1;
    assert(!publicIdentity.verify(message, alteredSalt));

    const again = await identity.sign(message);
    assert(!signature.slice(0, 32).equals(again.slice(0, 32)));
    assert(publicIdentity.verify(message, again));
    const otherIdentity = VaultysId.fromPassportAA({ dg15, dg14: ecDG14, reader, encryptionSecretKey: Buffer.alloc(32, 5) });
    assert(!otherIdentity.verify(message, signature));
    await assert.rejects(publicIdentity.sign(message), /Could not sign/);
    identity.keyManager.cleanSecureData();
    await assert.rejects(identity.sign(message), /Could not sign/);
  });

  it("completes a relationship handshake and restores the passport contact from storage", async () => {
    const identity = VaultysId.fromPassportAA({ dg15, dg14: ecDG14, reader: ecReader(), encryptionSecretKey });
    const softwareIdentity = await VaultysId.generatePerson();
    const initiator = new Challenger(softwareIdentity);
    const responder = new Challenger(identity);
    initiator.createChallenge("p2p", "auth");
    await responder.update(initiator.getCertificate());
    await initiator.update(responder.getCertificate());
    await responder.update(initiator.getCertificate());
    assert(initiator.isComplete() && responder.isComplete());
    const contact = initiator.getContactId();
    assert.equal(contact.did, identity.did);
    assert(await Challenger.verifyCertificate(initiator.getCertificate()));

    const store = MemoryStorage();
    const profile = new IdManager(softwareIdentity, store);
    profile.saveContact(contact);
    const restored = await IdManager.fromStore(
      store.fromString(
        store.toString(),
        () => {},
        () => {},
      ),
    );
    assert.equal(restored.contacts[0]?.did, identity.did);
    assert(await restored.verifyWebOfTrust());
  });

  it("verifies RSA ISO 9796-2 partial recovery and uses the extended APDU when requested", async () => {
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const spki = rsa.publicKey.export({ type: "spki", format: "der" });
    const modulus = BigInt("0x" + Buffer.from(rsa.publicKey.export({ format: "jwk" }).n!, "base64").toString("hex"));
    let legacyTrailer = false;
    const reader = createPassportAAReader(async (command) => {
      const apdu = Buffer.from(command);
      assert.equal(apdu.length, 17);
      assert.equal(apdu.slice(0, 7).toString("hex"), "00880000000008");
      assert.equal(apdu.slice(15).toString("hex"), "0000");
      const challenge = apdu.slice(7, 15);
      const trailer = Buffer.from(legacyTrailer ? "bc" : "34cc", "hex");
      const digest = createHash(legacyTrailer ? "sha1" : "sha256");
      const nonce = randomBytes(256 - 1 - digest.copy().digest().length - trailer.length);
      const representative = Buffer.concat([Buffer.from([0x6a]), nonce, digest.update(nonce).update(challenge).digest(), trailer]);
      const raw = privateEncrypt({ key: rsa.privateKey, padding: constants.RSA_NO_PADDING }, representative);
      const complement = modulus - BigInt("0x" + raw.toString("hex"));
      const response = legacyTrailer ? Buffer.from(complement.toString(16).padStart(512, "0"), "hex") : raw;
      return Buffer.concat([response, Buffer.from("9000", "hex")]);
    }, true);
    const identity = VaultysId.fromPassportAA({ dg15: spki, reader, encryptionSecretKey });
    const signature = await identity.signChallenge("1234");
    assert(VaultysId.fromId(identity.id).verifyChallenge("1234", signature, false));
    assert(!VaultysId.fromId(identity.id).verifyChallenge("1334", signature, false));
    assert(!VaultysId.fromId(identity.id).verify("1234", signature));
    legacyTrailer = true;
    assert(VaultysId.fromId(identity.id).verifyChallenge("1234", await identity.signChallenge("1234"), false));
  });

  it("rejects malformed keys, unsupported hashes, and card failures", async () => {
    const options = { dg15, dg14: ecDG14, reader: ecReader(), encryptionSecretKey };
    assert.throws(() => VaultysId.fromPassportAA({ ...options, dg14: undefined }), /DG14/);
    assert.throws(() => VaultysId.fromPassportAA({ ...options, dg15: dg15.slice(0, -1) }), /Truncated/);
    const sha1DG14 = Buffer.from(ecDG14);
    sha1DG14[sha1DG14.length - 1] = 1;
    assert.throws(() => VaultysId.fromPassportAA({ ...options, dg14: sha1DG14 }), /Unsupported passport AA hash/);

    const identity = VaultysId.fromPassportAA({ ...options, reader: createPassportAAReader(async () => Buffer.from("6982", "hex")) });
    await assert.rejects(identity.sign("1234"), /status 0x6982/);
    const wrong = VaultysId.fromPassportAA({ ...options, reader: async () => Array.from({ length: 4 }, () => Buffer.alloc(64)) });
    await assert.rejects(wrong.sign("1234"), /does not match/);
    // An alternate field ordering would assign a different DID to the same key.
    const badId = Buffer.concat([Buffer.from([0x05]), encode({ v: 1, h: 2, x: ecSpki, e: Buffer.alloc(32) })]);
    assert.throws(() => VaultysId.fromId(badId), /canonical serialization/);
  });
});
