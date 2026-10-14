import { VaultysId, Challenger } from "../";
import { Buffer } from "buffer/";
import assert from "assert";
import "./shims";
import { decode, encode } from "@msgpack/msgpack";
import { hash, randomBytes } from "../src/crypto";
import { createRandomVaultysId } from "./utils";

const delay = (ms: number = 1000) => new Promise((resolve) => setTimeout(resolve, ms));

// decode a serialized challenge, let `fn` tamper with it, re-encode it
const tamper = (certificate: Buffer, fn: (c: any) => void) => {
  const c = decode(certificate) as any;
  fn(c);
  return Buffer.from(encode(c));
};

const handshake = async (alg?: "ed25519") => {
  const id1 = alg ? await VaultysId.generatePerson(alg) : await createRandomVaultysId();
  const id2 = alg ? await VaultysId.generateMachine(alg) : await createRandomVaultysId();
  const c1 = new Challenger(id1);
  const c2 = new Challenger(id2);
  c1.createChallenge("p2p", "auth", { name: "alice" });
  const init = c1.getCertificate();
  await c2.update(init, { name: "bob" });
  const step1 = c2.getCertificate();
  await c1.update(step1);
  const complete = c1.getCertificate();
  await c2.update(complete);
  return { id1, id2, c1, c2, init, step1, complete };
};

const challengeNext = async (vaultysId: VaultysId, newCertificate?: Buffer, oldCertificate?: Buffer) => {
  const challenger = new Challenger(vaultysId);
  if (oldCertificate) {
    await challenger.init(oldCertificate);
  } else if (!newCertificate) {
    challenger.createChallenge("p2p", "test");
  }
  if (newCertificate) await challenger.update(newCertificate);
  return challenger.getCertificate();
};

describe("Symetric Proof of Relationship - SRG - v1", () => {
  it("Perform Protocol", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2);
    assert.equal(challenger1.isComplete(), false);
    assert.equal(challenger1.hasFailed(), false);
    challenger1.createChallenge("p2p", "auth");
    assert.equal(challenger1.state, 0);
    assert.equal(challenger2.state, -1);
    await challenger2.update(challenger1.getCertificate());
    assert.equal(challenger1.state, 0);
    assert.equal(challenger2.state, 1);
    await challenger1.update(challenger2.getCertificate());
    assert.equal(challenger1.state, 2);
    assert.equal(challenger2.state, 1);
    assert.ok(challenger1.isComplete());
    assert.ok(!challenger2.isComplete());
    await challenger2.update(challenger1.getCertificate());
    assert.equal(challenger1.state, 2);
    assert.equal(challenger2.state, 2);
    // SYMETRIC PROOF
    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
    assert.equal(challenger1.getCertificate().toString("hex"), challenger2.getCertificate().toString("hex"));
    assert.equal(challenger1.getContactId().did, VaultysId.fromId(vaultysId2.id).toVersion(1).did);
    assert.equal(challenger2.getContactId().did, VaultysId.fromId(vaultysId1.id).toVersion(1).did);
    assert.equal(await Challenger.verifyCertificate(challenger1.getCertificate()), true);
    assert.equal(Challenger.deserializeCertificate(challenger1.getCertificate()).version, 1);
  });

  it("Perform Protocol with metadata", async () => {
    const { c1, c2 } = await handshake();
    assert.deepEqual(c1.challenge!.metadata, { pk1: { name: "alice" }, pk2: { name: "bob" } });
    assert.deepEqual(c2.challenge!.metadata, { pk1: { name: "alice" }, pk2: { name: "bob" } });
  });

  it("Perform Protocol with a stateless responder", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const vaultysId2 = await createRandomVaultysId();
    const initiator = new Challenger(vaultysId1);
    initiator.createChallenge("p2p", "test");
    const step1 = await challengeNext(vaultysId2, initiator.getCertificate());
    await initiator.update(step1);
    const complete = initiator.getCertificate();
    const finalise = await challengeNext(vaultysId2, complete, step1);
    assert.equal(complete.toString("base64"), finalise.toString("base64"));
  });

  it("A stateless initiator can't be emulated (a fresh challenger never signs a STEP1)", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const vaultysId2 = await createRandomVaultysId();
    const init = await challengeNext(vaultysId1);
    const step1 = await challengeNext(vaultysId2, init);
    await assert.rejects(challengeNext(vaultysId1, step1));
  });

  it("Stateless resume refuses a STEP1 not produced by this identity", async () => {
    const { id1, step1 } = await handshake("ed25519");
    const other = await VaultysId.generateMachine();
    await assert.rejects(new Challenger(other).init(step1), { message: "challenge is not corresponding to the right id" });
    // nor an INIT
    const c = new Challenger(id1);
    c.createChallenge("p2p", "auth");
    await assert.rejects(new Challenger(other).init(c.getCertificate()));
  });

  it("Perform Protocol attacking protocol", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2);
    challenger1.createChallenge("p2p", "auth");
    await challenger2.update(tamper(challenger1.getCertificate(), (c) => (c.protocol = "hack")));
    assert.equal(challenger2.state, 1);
    await assert.rejects(challenger1.update(challenger2.getCertificate()), {
      message: "The challenge was expecting protocol 'p2p' and service 'auth', received 'hack' and 'auth'",
    });
    assert.ok(challenger1.hasFailed());
  });

  it("Perform Protocol attacking service", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2);
    challenger1.createChallenge("p2p", "auth");
    await challenger2.update(tamper(challenger1.getCertificate(), (c) => (c.service = "hack")));
    await assert.rejects(challenger1.update(challenger2.getCertificate()), {
      message: "The challenge was expecting protocol 'p2p' and service 'auth', received 'p2p' and 'hack'",
    });
  });

  it("Perform Protocol attacking nonce", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2);
    challenger1.createChallenge("p2p", "auth");
    await challenger2.update(tamper(challenger1.getCertificate(), (c) => (c.nonce = randomBytes(16))));
    await assert.rejects(challenger1.update(challenger2.getCertificate()), { message: "Nonce has been tampered with" });
  });

  it("Perform Protocol attacking timestamp", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2);
    challenger1.createChallenge("p2p", "auth");
    await delay(2);
    await challenger2.update(tamper(challenger1.getCertificate(), (c) => (c.timestamp = Date.now())));
    await assert.rejects(challenger1.update(challenger2.getCertificate()), { message: "Timestamp has been tampered with" });
  });

  it("Perform Protocol attacking metadata of pk1", async () => {
    const challenger1 = new Challenger(await createRandomVaultysId());
    const challenger2 = new Challenger(await createRandomVaultysId());
    challenger1.createChallenge("p2p", "auth", { name: "alice" });
    await challenger2.update(tamper(challenger1.getCertificate(), (c) => (c.metadata.pk1.name = "mallory")));
    await assert.rejects(challenger1.update(challenger2.getCertificate()), { message: "Metadata has been tampered with" });
  });

  it("Reject a STEP1 tampered after signature (service, timestamp, version, metadata)", async () => {
    const tampers: ((c: any) => void)[] = [(c) => (c.service = "hack"), (c) => (c.timestamp = c.timestamp + 1), (c) => (c.version = 0), (c) => (c.metadata = { ...c.metadata, pk2: { name: "mallory" } }), (c) => (c.protocol = "hack")];
    for (const fn of tampers) {
      const challenger1 = new Challenger(await VaultysId.generatePerson());
      const challenger2 = new Challenger(await VaultysId.generateMachine());
      challenger1.createChallenge("p2p", "auth");
      await challenger2.update(challenger1.getCertificate());
      await assert.rejects(challenger1.update(tamper(challenger2.getCertificate(), fn)));
      assert.ok(challenger1.hasFailed());
      assert.equal(challenger1.challenge!.sign1, undefined);
    }
  });

  it("Reject a COMPLETE tampered (service, timestamp, version, metadata, nonce)", async () => {
    const tampers: ((c: any) => void)[] = [(c) => (c.service = "hack"), (c) => (c.timestamp = c.timestamp + 1), (c) => (c.version = 0), (c) => (c.version = 2), (c) => (c.metadata = {}), (c) => (c.metadata.pk2 = { name: "mallory" }), (c) => (c.nonce = randomBytes(32))];
    for (const fn of tampers) {
      const challenger1 = new Challenger(await VaultysId.generatePerson());
      const challenger2 = new Challenger(await VaultysId.generateMachine());
      challenger1.createChallenge("p2p", "auth", { name: "alice" });
      await challenger2.update(challenger1.getCertificate(), { name: "bob" });
      await challenger1.update(challenger2.getCertificate());
      await assert.rejects(challenger2.update(tamper(challenger1.getCertificate(), fn)));
      assert.ok(challenger2.hasFailed());
      assert.ok(!challenger2.isComplete());
    }
  });

  it("Reject a COMPLETE re-signed by a malicious initiator over different bytes", async () => {
    const id1 = await VaultysId.generatePerson();
    const challenger1 = new Challenger(id1);
    const challenger2 = new Challenger(await VaultysId.generateMachine());
    challenger1.createChallenge("p2p", "auth");
    await challenger2.update(challenger1.getCertificate());
    const step1 = decode(challenger2.getCertificate()) as any;
    step1.service = "hack";
    const unsigned = Challenger.serializeCertificate({ ...step1, state: 1 });
    step1.sign1 = await new Challenger(id1).vaultysId.signHandshake(unsigned);
    await assert.rejects(challenger2.update(Buffer.from(encode(step1))));
    assert.ok(!challenger2.isComplete());
  });

  it("Reject a replayed COMPLETE (legit but different certificate)", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const vaultysId2 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const challenger2 = new Challenger(vaultysId2);
    challenger1.createChallenge("p2p", "auth");
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    await challenger2.update(challenger1.getCertificate());

    const challenger3 = new Challenger(vaultysId1);
    const challenger4 = new Challenger(vaultysId2);
    challenger3.createChallenge("p2p", "auth");
    await challenger4.update(challenger3.getCertificate());
    await challenger3.update(challenger4.getCertificate());

    await assert.rejects(challenger4.update(challenger1.getCertificate()), { message: "Nonce has been tampered with" });
  });

  it("Reject a COMPLETE received while UNINITIALISED (replay)", async () => {
    const { id2, complete } = await handshake("ed25519");
    const fresh = new Challenger(id2);
    await assert.rejects(fresh.update(complete));
    assert.ok(fresh.hasFailed());
    assert.ok(!fresh.isComplete());
  });

  it("Reject a STEP1 received while UNINITIALISED (no signing oracle)", async () => {
    // a relay sends to the victim (pk1) a STEP1 it never initiated
    const victim = await VaultysId.generatePerson();
    const attacker = await VaultysId.generateMachine();
    const honest = new Challenger(victim);
    honest.createChallenge("p2p", "auth");
    const attackerChallenger = new Challenger(attacker);
    await attackerChallenger.update(honest.getCertificate());
    const step1 = attackerChallenger.getCertificate();

    const victimChallenger = new Challenger(victim);
    await assert.rejects(victimChallenger.update(step1));
    assert.ok(victimChallenger.hasFailed());
    assert.equal(victimChallenger.challenge, undefined);
  });

  it("Reject version 0 and any non-1 version", async () => {
    for (const version of [0, 2, undefined, "1"]) {
      const challenger1 = new Challenger(await VaultysId.generatePerson());
      const challenger2 = new Challenger(await VaultysId.generateMachine());
      challenger1.createChallenge("p2p", "auth");
      const init = tamper(challenger1.getCertificate(), (c) => {
        if (version === undefined) delete c.version;
        else c.version = version;
      });
      assert.equal(Challenger.deserializeCertificate(init).state, -2);
      await assert.rejects(challenger2.update(init));
      assert.equal(challenger2.challenge, undefined);
    }
  });

  it("Reject reflection (INIT from the same identity)", async () => {
    const id = await VaultysId.generatePerson();
    const challenger1 = new Challenger(id);
    challenger1.createChallenge("p2p", "auth");
    const challenger2 = new Challenger(id);
    await assert.rejects(challenger2.update(challenger1.getCertificate()), { message: "Refusing a challenge initiated by this same identity" });
    assert.equal(challenger2.challenge?.sign2, undefined);
  });

  it("Reject an INIT carrying pk2 metadata or a wrong nonce length", async () => {
    const challenger1 = new Challenger(await VaultysId.generatePerson());
    challenger1.createChallenge("p2p", "auth");
    const cert = challenger1.getCertificate();
    await assert.rejects(new Challenger(await VaultysId.generateMachine()).update(tamper(cert, (c) => (c.metadata = { pk2: { a: "b" } }))));
    await assert.rejects(new Challenger(await VaultysId.generateMachine()).update(tamper(cert, (c) => (c.nonce = randomBytes(15)))));
    await assert.rejects(new Challenger(await VaultysId.generateMachine()).update(tamper(cert, (c) => (c.pk1 = randomBytes(77)))));
  });

  it("Handshake signatures are domain separated (VAULTYS_HANDSHAKE_V1)", async () => {
    const id1 = await VaultysId.generatePerson();
    const challenger1 = new Challenger(id1);
    const challenger2 = new Challenger(await VaultysId.generateMachine());
    challenger1.createChallenge("p2p", "auth");
    await challenger2.update(challenger1.getCertificate());
    const step1 = decode(challenger2.getCertificate()) as any;
    const unsigned = Challenger.serializeCertificate({ ...step1, state: 1 });
    const signer = new Challenger(id1).vaultysId;
    // VAULTYS_SIGN and VAULTYS_RAW signatures over the same bytes are not handshake signatures
    for (const sign1 of [await signer.signChallenge(unsigned), await signer.sign(unsigned)]) {
      const forged = Buffer.from(encode({ ...step1, sign1 }));
      assert.equal(Challenger.deserializeCertificate(forged).state, -2);
      assert.equal(await Challenger.verifyCertificate(forged), false);
      await assert.rejects(challenger2.update(forged));
    }
    // and the handshake signature is over SHA-256("VAULTYS_HANDSHAKE_V1" || unsigned)
    const good = await signer.signHandshake(unsigned);
    assert.ok(signer.keyManager.verify(hash("sha256", Buffer.concat([Buffer.from("VAULTYS_HANDSHAKE_V1"), unsigned])), good));
    assert.ok(!signer.verifyChallenge(unsigned, good, false));
    assert.ok(!signer.verify(unsigned, good));
  });

  it("setChallenge / fromCertificate are read-only", async () => {
    const { id1, id2, complete, step1 } = await handshake("ed25519");
    const reader = new Challenger(id2);
    assert.equal(await reader.setChallenge(complete), true);
    assert.ok(!reader.isComplete());
    assert.equal(reader.getContactDid(), VaultysId.fromId(id1.id).toVersion(1).did);
    await assert.rejects(reader.update(complete));
    assert.throws(() => reader.createChallenge("p2p", "auth"));

    // an INIT loaded with setChallenge is not signed
    const c = new Challenger(id1);
    c.createChallenge("p2p", "auth");
    const reader2 = new Challenger(id2);
    assert.equal(await reader2.setChallenge(c.getCertificate()), false);
    assert.equal(reader2.challenge!.sign2, undefined);
    assert.equal(reader2.challenge!.pk2, undefined);

    // public-only identities can be used to inspect certificates
    const publicReader = new Challenger(VaultysId.fromId(id1.id));
    assert.equal(await publicReader.setChallenge(complete), true);
    const fromCert = await Challenger.fromCertificate(step1);
    assert.ok(fromCert && !fromCert.isComplete());
    await assert.rejects(fromCert!.update(complete));
  });

  it("deserializeCertificate never throws on garbage", async () => {
    const { complete } = await handshake("ed25519");
    const inputs = [Buffer.from([]), Buffer.from([0xc1]), randomBytes(100), Buffer.from(encode("string")), Buffer.from(encode([1, 2])), Buffer.from(encode({ version: 1, protocol: "p", service: "s", timestamp: Date.now(), pk1: randomBytes(3), nonce: randomBytes(16), metadata: {} }))];
    for (const input of inputs) {
      assert.equal(Challenger.deserializeCertificate(input).state, -2);
      assert.equal(await Challenger.verifyCertificate(input), false);
    }
    for (let i = 0; i < complete.length; i += 7) {
      const rogue = Buffer.from(complete);
      rogue[i] = rogue[i] ^ 0xff;
      assert.notEqual(Challenger.deserializeCertificate(rogue).state, 2);
    }
  });

  it("Fail for liveliness at first round", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1, 50);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2, 50);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth");
    await delay(100);
    await assert.rejects(challenger2.update(challenger1.getCertificate()), {
      name: "Error",
      message: "challenge timestamp failed the liveliness",
    });
  });

  it("Fail for liveliness at second round", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1, 50);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2, 50);
    challenger1.createChallenge("p2p", "auth");
    await challenger2.update(challenger1.getCertificate());
    await delay(100);
    await assert.rejects(challenger1.update(challenger2.getCertificate()), {
      name: "Error",
      message: "challenge timestamp failed the liveliness",
    });
  });

  it("Pass for liveliness at third round", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1, 500);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2, 500);
    challenger1.createChallenge("p2p", "auth");
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    await delay(200);
    await challenger2.update(challenger1.getCertificate());

    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
    assert.ok(!challenger1.hasFailed());
  });

  it("Pass with time deviation of 59s in the future", async () => {
    const challenger1 = new Challenger(await createRandomVaultysId());
    const challenger2 = new Challenger(await createRandomVaultysId());
    challenger1.createChallenge("p2p", "auth");
    challenger1.challenge!.timestamp = challenger1.challenge!.timestamp + 59000;
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    await delay(100);
    await challenger2.update(challenger1.getCertificate());
    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
  });

  it("Pass with time deviation of 59s in the past", async () => {
    const challenger1 = new Challenger(await createRandomVaultysId());
    const challenger2 = new Challenger(await createRandomVaultysId());
    challenger1.createChallenge("p2p", "auth");
    challenger1.challenge!.timestamp = challenger1.challenge!.timestamp - 59000;
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    await delay(100);
    await challenger2.update(challenger1.getCertificate());
    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
  });

  it("Fail with time deviation of 60s in the future", async () => {
    const challenger1 = new Challenger(await createRandomVaultysId());
    const challenger2 = new Challenger(await createRandomVaultysId());
    challenger1.createChallenge("p2p", "auth");
    challenger1.challenge!.timestamp = challenger1.challenge!.timestamp + 60001;
    await assert.rejects(challenger2.update(challenger1.getCertificate()), {
      name: "Error",
      message: "challenge timestamp failed the liveliness",
    });
  });

  it("Fail with time deviation of 60s in the past", async () => {
    const challenger1 = new Challenger(await createRandomVaultysId());
    const challenger2 = new Challenger(await createRandomVaultysId());
    challenger1.createChallenge("p2p", "auth");
    challenger1.challenge!.timestamp = challenger1.challenge!.timestamp - 60000;
    await assert.rejects(challenger2.update(challenger1.getCertificate()), {
      name: "Error",
      message: "challenge timestamp failed the liveliness",
    });
  });
});
