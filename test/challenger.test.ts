import { VaultysId, Challenger } from "../";
import { Buffer } from "buffer/";
import assert from "assert";
import "./shims";
import { randomBytes } from "../src/crypto";
import { createRandomVaultysId } from "./utils";

const testCertificate = (rogueCert: Buffer) => {
  try {
    const result = Challenger.deserializeCertificate(rogueCert);
    return result;
  } catch (error) {
    return {
      state: -2,
    };
  }
};

const delay = (ms: number = 1000) => new Promise((resolve) => setTimeout(resolve, ms));

const challengeNext = async (vaultysId: VaultysId, newCertificate?: Buffer, oldCertificate?: Buffer) => {
  //console.log(newCertificate, oldCertificate);
  const challenger = new Challenger(vaultysId);
  if (oldCertificate) {
    await challenger.init(oldCertificate);
  } else if (!newCertificate) {
    challenger.createChallenge("p2p", "test");
  }
  if (newCertificate) await challenger.update(newCertificate);
  return challenger.getCertificate();
};

describe("Symetric Proof of Relationship - SRG", () => {
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
    assert.equal(challenger1.toString(), challenger2.toString());
  });

  it("Perform Stateless Protocol", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const vaultysId2 = await createRandomVaultysId();
    const init = await challengeNext(vaultysId1);
    // console.log("init", Challenger.deserializeCertificate(init));
    const step1 = await challengeNext(vaultysId2, init);
    // console.log("step1", Challenger.deserializeCertificate(step1));
    const complete = await challengeNext(vaultysId1, step1);
    // console.log("complete", Challenger.deserializeCertificate(complete));
    const finalise = await challengeNext(vaultysId2, complete, step1);
    assert.equal(complete.toString("base64"), finalise.toString("base64"));
  });

  it("Perform Protocol attacking protocol", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2);
    const challengerattack = new Challenger(vaultysId2);
    assert.equal(challenger1.isComplete(), false);
    assert.equal(challenger1.hasFailed(), false);
    challenger1.createChallenge("p2p", "auth");
    assert.equal(challenger1.state, 0);
    assert.equal(challenger2.state, -1);
    await challengerattack.setChallenge(challenger1.getCertificate());
    challengerattack.challenge!.protocol = "hack";
    delete challengerattack.challenge?.pk2;
    delete challengerattack.challenge?.sign2;
    challengerattack.challenge!.nonce = Buffer.from(challengerattack.challenge!.nonce!.subarray(0, 16));
    await challenger2.update(challengerattack.getCertificate());
    // console.log(challengerattack.challenge);
    assert.equal(challenger1.state, 0);
    assert.equal(challenger2.state, 1);
    try {
      await challenger1.update(challenger2.getCertificate());
    } catch (err: any) {
      assert.equal(err?.message, "The challenge was expecting protocol 'p2p' and service 'auth', received 'hack' and 'auth'");
      return;
    }
    assert.fail("The protocol with tampered nonce should have failed");
  });

  it("Perform Protocol attacking service", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2);
    const challengerattack = new Challenger(vaultysId2);
    assert.equal(challenger1.isComplete(), false);
    assert.equal(challenger1.hasFailed(), false);
    challenger1.createChallenge("p2p", "auth");
    assert.equal(challenger1.state, 0);
    assert.equal(challenger2.state, -1);
    await challengerattack.setChallenge(challenger1.getCertificate());
    challengerattack.challenge!.service = "hack";
    delete challengerattack.challenge?.pk2;
    delete challengerattack.challenge?.sign2;
    challengerattack.challenge!.nonce = Buffer.from(challengerattack.challenge!.nonce!.subarray(0, 16));
    await challenger2.update(challengerattack.getCertificate());
    // console.log(challengerattack.challenge);
    assert.equal(challenger1.state, 0);
    assert.equal(challenger2.state, 1);
    try {
      await challenger1.update(challenger2.getCertificate());
    } catch (err: any) {
      assert.equal(err?.message, "The challenge was expecting protocol 'p2p' and service 'auth', received 'p2p' and 'hack'");
      return;
    }
    assert.fail("The protocol with tampered nonce should have failed");
  });

  it("Perform Protocol attacking nonce", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2);
    const challengerattack = new Challenger(vaultysId2);
    assert.equal(challenger1.isComplete(), false);
    assert.equal(challenger1.hasFailed(), false);
    challenger1.createChallenge("p2p", "auth");
    assert.equal(challenger1.state, 0);
    assert.equal(challenger2.state, -1);
    await challengerattack.setChallenge(challenger1.getCertificate());
    challengerattack.challenge!.nonce = randomBytes(16);
    delete challengerattack.challenge?.pk2;
    delete challengerattack.challenge?.sign2;
    // console.log(challengerattack.challenge);
    // console.log("boom");
    await challenger2.update(challengerattack.getCertificate());
    assert.equal(challenger1.state, 0);
    assert.equal(challenger2.state, 1);
    try {
      await challenger1.update(challenger2.getCertificate());
    } catch (err: any) {
      assert.equal(err?.message, "Nonce has been tampered with");
      return;
    }
    assert.fail("The protocol with tampered nonce should have failed");
  });

  it("Perform Protocol attacking timestamp", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2);
    const challengerattack = new Challenger(vaultysId2);
    assert.equal(challenger1.isComplete(), false);
    assert.equal(challenger1.hasFailed(), false);
    challenger1.createChallenge("p2p", "auth");
    assert.equal(challenger1.state, 0);
    assert.equal(challenger2.state, -1);
    await challengerattack.setChallenge(challenger1.getCertificate());
    await delay(2); //new timestamp might be the same!
    challengerattack.challenge!.timestamp = Date.now();
    delete challengerattack.challenge?.pk2;
    delete challengerattack.challenge?.sign2;
    challengerattack.challenge!.nonce = Buffer.from(challengerattack.challenge!.nonce!.subarray(0, 16));
    await challenger2.update(challengerattack.getCertificate());
    assert.equal(challenger1.state, 0);
    assert.equal(challenger2.state, 1);
    try {
      await challenger1.update(challenger2.getCertificate());
    } catch (err: any) {
      assert.equal(err?.message, "Timestamp has been tampered with");
      return;
    }
    assert.fail("The protocol with tampered timestamp should have failed");
  });

  it("Perform Protocol attacking with legit but different certificate", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
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

    try {
      await challenger4.update(challenger1.getCertificate());
    } catch (err: any) {
      assert.equal(err?.message, "Nonce has been tampered with");
      return;
    }
    assert.fail("The protocol with tampered legit certificate should have failed");
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
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
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
    const challenger1 = new Challenger(vaultysId1, 50);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2, 50);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth");
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    await delay(20);
    await challenger2.update(challenger1.getCertificate());

    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
    assert.ok(!challenger1.hasFailed());
    assert.equal(challenger1.toString(), challenger2.toString());
  });

  it("Pass with time deviation of 59s in the future", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth");
    if (!challenger1.challenge) assert.fail();
    challenger1.challenge.timestamp = challenger1.challenge.timestamp + 59000;
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    await new Promise((resolve) => setTimeout(resolve, 100));
    await challenger2.update(challenger1.getCertificate());
    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
    assert.ok(!challenger1.hasFailed());

    assert.equal(challenger1.toString(), challenger2.toString());
  });

  it("Pass with time deviation of 59s in the past", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth");
    if (!challenger1.challenge) assert.fail();
    challenger1.challenge.timestamp = challenger1.challenge.timestamp - 59000;
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    await new Promise((resolve) => setTimeout(resolve, 100));
    await challenger2.update(challenger1.getCertificate());
    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
    assert.ok(!challenger1.hasFailed());

    assert.equal(challenger1.toString(), challenger2.toString());
  });

  it("Fail with time deviation of 60s in the future", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth");
    challenger1.challenge!.timestamp = challenger1.challenge!.timestamp + 60001;
    await assert.rejects(challenger2.update(challenger1.getCertificate()), {
      name: "Error",
      message: "challenge timestamp failed the liveliness",
    });
  });

  it("Fail with time deviation of 60s in the past", async () => {
    const vaultysId1 = await createRandomVaultysId();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth");
    challenger1.challenge!.timestamp = challenger1.challenge!.timestamp - 60000;
    await assert.rejects(challenger2.update(challenger1.getCertificate()), {
      name: "Error",
      message: "challenge timestamp failed the liveliness",
    });
  });
  /*
  it("Fail with tampered certificate (FIDO2)", async () => {
    const attestation1 = await navigator.credentials.create(
      SoftCredentials.createRequest(-7),
    );
    const vaultysId1 = await VaultysId.fido2FromAttestation(attestation1);
    const challenger1 = new Challenger(vaultysId1);

    const attestation2 = await navigator.credentials.create(
      SoftCredentials.createRequest(-8),
    );
    const vaultysId2 = await VaultysId.fido2FromAttestation(attestation2);
    const challenger2 = new Challenger(vaultysId2);

    challenger1.createChallenge("interesting", "stuff");
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    await challenger2.update(challenger1.getCertificate());
    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
    const rogueCert = challenger2.getCertificate();
    for(let i = 0; i < rogueCert.length; i++) {
      const back = rogueCert[i];
      rogueCert[i] = back + Math.floor(Math.random() * 254) + 1
      const t = testCertificate(rogueCert);
      assert.notEqual(t.state, 2);
      rogueCert[i] = back;
    }
  }).timeout(10000);

  it("Fail with tampered certificate all possibilities (FIDO2)", async () => {
    const vaultysId1 = await VaultysId.generateMachine();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await VaultysId.generateMachine();
    const challenger2 = new Challenger(vaultysId2);

    challenger1.createChallenge("interesting", "stuff");
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    await challenger2.update(challenger1.getCertificate());
    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
    const rogueCert = challenger2.getCertificate();
    for(let i = 0; i < rogueCert.length; i++) {
      const back = rogueCert[i];
      // TODO fix this malleability for
      // �timestamp��DS_� a974696d657374616d70cf000001884453195fa3
      // �timestamp��DS_� a974696d657374616d70d3000001884453195fa3
      // or use another serialisation for identifying certificate.
      if(i != 46 && i != rogueCert.length - 1) {
        for(let j = 0; j < 256; j++){
          if(j != back) {
            rogueCert[i] = j;
            const t = testCertificate(rogueCert);
            if(t.state == 2) {
              console.log(i, j, t);
              console.log(
                Buffer.from(rogueCert).toString("utf-8").slice(i-10, i+10),
                Buffer.from(rogueCert).toString("hex").slice(i*2-20, i*2+20),
                Buffer.from(challenger2.getCertificate()).toString("utf-8").slice(i-10, i+10),
                Buffer.from(challenger2.getCertificate()).toString("hex").slice(i*2-20, i*2+20)
              );
            }
            assert.notEqual(t.state, 2);
          }
        }
      }
      console.log(i, rogueCert.length);
      rogueCert[i] = back;
    }
  }).timeout(10000);

  it("Fail with tampered certificate", async () => {
    const vaultysId1 = await VaultysId.generateMachine();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await VaultysId.generateMachine();
    const challenger2 = new Challenger(vaultysId2);

    challenger1.createChallenge("random", "test");
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    await challenger2.update(challenger1.getCertificate());
    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
    const rogueCert = challenger2.getCertificate();
    for(let i = 0; i < rogueCert.length; i++) {
      const back = rogueCert[i];
      rogueCert[i] = back + Math.floor(Math.random() * 254) + 1
      const t = testCertificate(rogueCert);
      assert.notEqual(t.state, 2);
      rogueCert[i] = back;
    }
  }).timeout(10000);
  */
});
