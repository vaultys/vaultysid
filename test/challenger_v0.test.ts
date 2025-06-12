import { VaultysId, Challenger } from "../";
import { Buffer } from "buffer/";
import assert from "assert";
import "./shims";
import { randomBytes } from "../src/crypto";
import { createRandomVaultysId } from "./utils";
import { decrypt } from "../src/cryptoChannel";

const delay = (ms: number = 1000) => new Promise((resolve) => setTimeout(resolve, ms));

const challengeNext = async (vaultysId: VaultysId, newCertificate?: Buffer, oldCertificate?: Buffer) => {
  //console.log(newCertificate, oldCertificate);
  const challenger = new Challenger(vaultysId);
  challenger.version = 0;
  if (oldCertificate) {
    await challenger.init(oldCertificate);
  } else if (!newCertificate) {
    challenger.createChallenge("p2p", "test", 0);
  }
  if (newCertificate) await challenger.update(newCertificate);
  return challenger.getCertificate();
};

describe("Symetric Proof of Relationship - SRG - v0", () => {
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
    for (let i = 0; i < 10; i++) {
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
    }
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

  it("Perform Protocol attacking version", async () => {
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
    challengerattack.version = challengerattack.version ? 1 : 0;
    challengerattack.challenge!.version = challengerattack.challenge!.version ? 1 : 0;
    try {
      await challenger2.update(challengerattack.getCertificate());
    } catch (err: any) {
      assert.equal(err?.message, "challenge is not corresponding to the right id");
      return;
    }
    assert.fail("The protocol with tampered version should have failed");
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
    const challenger1 = new Challenger(vaultysId1, 500);
    const vaultysId2 = await createRandomVaultysId();
    const challenger2 = new Challenger(vaultysId2, 500);
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

  it("Should deserialize a succesful v0 certificate", async () => {
    const cert = "iahwcm90b2NvbKNwMnCnc2VydmljZahyZWdpc3Rlcql0aW1lc3RhbXDPAAABko9gLwijcGsxxHQBhKF2AKFwxQAgthOolbL2HWtbnAkuAyLHAjfbnS8njgLhHlxWlosbC6uheMUAIBXMRt4jV1gxWK5/TF1jNx0kD+v2qKTWFnfEDQsrOeIvoWXFACCwkdnz8o6yhL86amqfB4/nUoznXnmSs9wAIIT30iGhaaNwazLEdACEoXYAoXDFACARZg0feo56ckkSEU8xc0G/xCH5vjeLeQjP9/KtRC4X76F4xQAg9qbrfdWleMqBsN8y7qPmZ1/ObCqFxeQmIopZBwJGfa2hZcUAIHKiC8fHbhLl902mhMbl/h04JvVnWLBCyAGb22orn5dVpW5vbmNlxCAofLkkt7f/YFen3ve05OcpDl8AFJRnejfZbMC6q37gOqVzaWduMcRAby4aZAta/aZL/8NxtqX8NnDUMTfXZ44qEdW5QVl3Gp/nh7sNDtdJfpF3XdJ1bJ7FtinGDDtTkRCzW5Hm9S+EAqVzaWduMsRA0xyketeALY1yA/KbPo7gTWTGdBVyxmG4u60kQJ2WtTDdjhVnCVzlb56xZtWhtGX/DJxw43yEehPyPxI/HvgwB6htZXRhZGF0YYA=";
    const result = Challenger.deserializeCertificate(Buffer.from(cert, "base64"));
    assert.equal(result.error, "");
    assert.equal(result.state, 2);
  });

  it("Should deserialize a succesful v0 certificate 2", async () => {
    const message = "QNGwy7yyIskbWees8qH39YHp6QpODl4Gsp970YFp3j+VjWbU2j1wAw7qLMWk0Ra0YeE6mVcENvohrXRfGdcM763qrYTgpFj72+jznW6szC+XxvDFkwCm9tba/qj6H+wpoDKphscI7UzJ8J1RoKytcLl3yg5BF6ikoJW0DMG58jE/T44tyEVhS0XVD5buSF6nGgam0Hge/rOMIh4Z0G6W5XQzEjMlobk7HYEV4nQAxRV8qaSLPtspF1ZcPgke2Q278n/KTwd65Nq+YYkr6cFPkxkmz9jZx9Zv0jKGiOw48MuirweOnD2AtvkpWq5fg6vi+pNZ/tymfIxwQ9LTnYbyKOwMR6/OzTulrbOBNftwDb2+PXLLT9Y=";
    const key = "9ee1d044677cac34984b2da0acbc66d238e884a5e944cde54b96be77e3fc1e8e";
    const cert = decrypt(Buffer.from(message, "base64"), Buffer.from(key, "hex"));
    // console.log(dearmorAndDecrypt(cert));
    // console.log(decode(cert));
    const result = Challenger.deserializeCertificate(cert);
    assert.equal(result.error, "");
    assert.equal(result.state, 0);
  });

  it("Should deserialize a succesful v0 certificate 3", async () => {
    const message = "Cf+KnycFC0odoGv9Yxjc2JvUgZSYBNmzBN1UomUz/3VzXds3K/Fr2odh9ZI4q86ZmFsKu/bIxsXhDNg2sM7PhESvgpAJte+3QfVD8e1pzSG4+mqQs2HSkXm5xo6gcPfoN7OyJfzUbaDW5ts1Cy9dIWxJpr8JcT6BUofVgoQk4loi8LPsDdsA4Kxk6FaAE05CeqvuglYayaOnOk/u+cQFHN9rBHe2cpHCrgQAr4Qa+MeLMo4GU7pB4Qd4nA7AQxDBXJqR+tVvPIA2GZWb/EW2OGDFU7YzRJJLP7RdXnjcsSYRkUzuCPpI7l7vfaVy8nxNqy9PkEIPlzyO3TCHOHqHWlEy2YN8O1Mx";
    const key = "cc4dfd01327a30e10d9286344d485f2e4807ddb4c3e007f8b7fba20bb6c16985";
    const cert = decrypt(Buffer.from(message, "base64"), Buffer.from(key, "hex"));
    //console.log(dearmorAndDecrypt(cert));
    // console.log(decode(cert));
    const result = Challenger.deserializeCertificate(cert);
    assert.equal(result.error, "");
    assert.equal(result.state, 0);
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
