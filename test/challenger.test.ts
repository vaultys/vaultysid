import Challenger from "../src/Challenger";
import SoftCredentials from "../src/SoftCredentials";
import VaultysId from "../src/VaultysId";
import assert from "assert";
import "./utils";
import { randomBytes } from "../src/crypto";

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

describe("Symetric Proof of Relationship - SRG", () => {
  it("Perform Protocol with KeyManager", async () => {
    const vaultysId1 = await VaultysId.generateMachine();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await VaultysId.generateOrganization();
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

  it("Perform Protocol with KeyManager attacking nonce", async () => {
    const vaultysId1 = await VaultysId.generateMachine();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await VaultysId.generateOrganization();
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

  it("Perform Protocol with KeyManager attacking timestamp", async () => {
    const vaultysId1 = await VaultysId.generateMachine();
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await VaultysId.generateOrganization();
    const challenger2 = new Challenger(vaultysId2);
    const challengerattack = new Challenger(vaultysId2);
    assert.equal(challenger1.isComplete(), false);
    assert.equal(challenger1.hasFailed(), false);
    challenger1.createChallenge("p2p", "auth");
    assert.equal(challenger1.state, 0);
    assert.equal(challenger2.state, -1);
    await challengerattack.setChallenge(challenger1.getCertificate());
    challengerattack.challenge!.timestamp = Date.now();
    delete challengerattack.challenge?.pk2;
    delete challengerattack.challenge?.sign2;
    challengerattack.challenge!.nonce = challengerattack.challenge!.nonce?.subarray(0, 16);
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

  it("Perform Protocol with Fido2Manager", async () => {
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-ignore
    const vaultysId1 = await VaultysId.fido2FromAttestation(attestation1);
    const challenger1 = new Challenger(vaultysId1);

    const attestation2 = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    // @ts-ignore
    const vaultysId2 = await VaultysId.fido2FromAttestation(attestation2);
    const challenger2 = new Challenger(vaultysId2);

    assert.equal(challenger1.isComplete(), false);
    assert.equal(challenger1.hasFailed(), false);
    challenger1.createChallenge("p2p", "auth");
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    assert.ok(challenger1.isComplete());
    assert.ok(!challenger2.isComplete());
    await challenger2.update(challenger1.getCertificate());
    // SYMETRIC PROOF
    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
    assert.equal(challenger1.toString(), challenger2.toString());
  });

  it("Fail for liveliness at first round", async () => {
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-ignore
    const vaultysId1 = await VaultysId.fido2FromAttestation(attestation1);
    const challenger1 = new Challenger(vaultysId1, 50);
    const vaultysId2 = await VaultysId.generatePerson();
    const challenger2 = new Challenger(vaultysId2, 50);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth");
    await delay(100);
    await assert.rejects(challenger2.update(challenger1.getCertificate()), {
      name: "Error",
      message: "challenge timestamp failed the liveliness at first signature",
    });
  });

  it("Fail for liveliness at second round", async () => {
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    // @ts-ignore
    const vaultysId1 = await VaultysId.fido2FromAttestation(attestation1);
    const challenger1 = new Challenger(vaultysId1, 50);
    const vaultysId2 = await VaultysId.generateMachine();
    const challenger2 = new Challenger(vaultysId2, 50);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth");
    await challenger2.update(challenger1.getCertificate());
    await delay(100);
    await assert.rejects(challenger1.update(challenger2.getCertificate()), {
      name: "Error",
      message: "challenge timestamp failed the liveliness at 2nd signature",
    });
  });

  it("Pass for liveliness at third round", async () => {
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-ignore
    const vaultysId1 = await VaultysId.fido2FromAttestation(attestation1);
    const challenger1 = new Challenger(vaultysId1, 50);
    const vaultysId2 = await VaultysId.generateOrganization();
    const challenger2 = new Challenger(vaultysId2, 50);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth");
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    await delay(100);
    await challenger2.update(challenger1.getCertificate());

    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
    assert.ok(!challenger1.hasFailed());
    assert.equal(challenger1.toString(), challenger2.toString());
  });

  it("Pass with time deviation of 5s in the future", async () => {
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-ignore
    const vaultysId1 = await VaultysId.fido2FromAttestation(attestation1);
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await VaultysId.generatePerson();
    const challenger2 = new Challenger(vaultysId2);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth");
    if (!challenger1.challenge) assert.fail();
    challenger1.challenge.timestamp = challenger1.challenge.timestamp + 5000;
    await challenger2.update(challenger1.getCertificate());
    await challenger1.update(challenger2.getCertificate());
    await new Promise((resolve) => setTimeout(resolve, 100));
    await challenger2.update(challenger1.getCertificate());
    assert.ok(challenger1.isComplete());
    assert.ok(challenger2.isComplete());
    assert.ok(!challenger1.hasFailed());

    assert.equal(challenger1.toString(), challenger2.toString());
  });

  it("Fail with time deviation of 15s in the future", async () => {
    const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    // @ts-ignore
    const vaultysId1 = await VaultysId.fido2FromAttestation(attestation1);
    const challenger1 = new Challenger(vaultysId1);
    const vaultysId2 = await VaultysId.generateOrganization();
    const challenger2 = new Challenger(vaultysId2);
    assert.ok(!challenger1.isComplete());
    assert.ok(!challenger1.hasFailed());
    challenger1.createChallenge("p2p", "auth");
    challenger1.challenge!.timestamp = challenger1.challenge!.timestamp + 15000;
    await assert.rejects(challenger2.update(challenger1.getCertificate()), {
      name: "Error",
      message: "challenge timestamp failed the liveliness at first signature",
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
