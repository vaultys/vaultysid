import assert from "assert";
import VaultysId from "../src/VaultysId";
import { migrateVaultysId } from "../src/utils/migration";
import { Buffer } from "buffer/";
import DeprecatedKeyManager from "../src/KeyManager/DeprecatedKeyManager";

const serializer = (object: object) => {
  return JSON.stringify(
    object,
    (key, value) => {
      if (value?.data && value?.type == "Buffer") {
        return Buffer.from(value.data).toString("base64");
      } else if (key === "publicKey" || key === "secretKey") {
        return value.toString("base64");
      } else {
        //console.log(key, value, typeof value);
        return value;
      }
    },
    2,
  );
};

const IDs: Record<string, object> = {
  "AYShdgGhcMQgAkdXeakmUj369/IVsxtgfZDvIl5H20sMr4Hvscd6vv2heMQg087CgsDqArlFnddT45WIE4q5ASE29yMy2ymtYF7wayqhZcQgc6ZsnBDgIVgudow5lIhodS2/hS8OL0lah8m9XE9QDng=": {
    type: 1,
    keyManager: {
      version: 1,
      level: 2,
      proof: "AkdXeakmUj369/IVsxtgfZDvIl5H20sMr4Hvscd6vv0=",
      capability: "public",
      signer: {
        publicKey: "087CgsDqArlFnddT45WIE4q5ASE29yMy2ymtYF7wayo=",
      },
      cypher: {
        publicKey: "c6ZsnBDgIVgudow5lIhodS2/hS8OL0lah8m9XE9QDng=",
      },
      authType: "Ed25519VerificationKey2020",
      encType: "X25519KeyAgreementKey2019",
    },
  },
  "BIOhdgGhY8RNpQECAyYgASFYIAahPdTq/F42/PU9WcYGaF4k7BQ1gnD9QIwX2wAcfjKoIlggO56gS5dUKbQZSeBrcYZcOZHZF5F568tgRiDLO2mv5/KhZcQgQ136sOFkQ6Ywe3GbYeGF8bZkLxM0D3Ym7JmdZAubAxE=": {
    type: 4,
    keyManager: {
      version: 1,
      capability: "public",
      signer: {
        publicKey: "BAahPdTq/F42/PU9WcYGaF4k7BQ1gnD9QIwX2wAcfjKoO56gS5dUKbQZSeBrcYZcOZHZF5F568tgRiDLO2mv5/I=",
      },
      cypher: {
        publicKey: "Q136sOFkQ6Ywe3GbYeGF8bZkLxM0D3Ym7JmdZAubAxE=",
      },
      _transports: 0,
      prfsalt: "VmF1bHR5c0lEIHNhbHQ=",
      authType: "P256VerificationKey2020",
      encType: "X25519KeyAgreementKey2019",
      ckey: "pQECAyYgASFYIAahPdTq/F42/PU9WcYGaF4k7BQ1gnD9QIwX2wAcfjKoIlggO56gS5dUKbQZSeBrcYZcOZHZF5F568tgRiDLO2mv5/I=",
      webAuthn: {},
    },
  },
};

describe("Test Vectors - legacy (bip32-ed25519)", () => {
  it("pass IDs", async () => {
    for (const id of Object.keys(IDs)) {
      const vid = VaultysId.fromId(Buffer.from(id, "base64"));
      assert.deepEqual(JSON.parse(serializer(vid)), IDs[id]);
    }
  });
  it("migrate VaultysID serialization", () => {
    const vid = "AYShdgGhcMQgAkdXeakmUj369/IVsxtgfZDvIl5H20sMr4Hvscd6vv2heMQg087CgsDqArlFnddT45WIE4q5ASE29yMy2ymtYF7wayqhZcQgc6ZsnBDgIVgudow5lIhodS2/hS8OL0lah8m9XE9QDng=";
    const newvid = "AYOhdgGheMQg087CgsDqArlFnddT45WIE4q5ASE29yMy2ymtYF7wayqhZcQgc6ZsnBDgIVgudow5lIhodS2/hS8OL0lah8m9XE9QDng=";
    assert.equal(migrateVaultysId(Buffer.from(vid, "base64")).toString("base64"), newvid);
    //console.log(vid.length, newvid.length);
    const id1 = VaultysId.fromId(vid, undefined, "base64");
    const id2 = VaultysId.fromId(newvid, undefined, "base64");
    //console.log(id1, id2);
    const dkm = id1.keyManager as DeprecatedKeyManager;
    delete dkm.proof;
    delete dkm.level;
    assert.equal(serializer(id1), serializer(id2));
  });

  it("migrate VaultysID serialization from secret", () => {
    const secret = "AIShdgGhcMQgX1Ypp/enZi4OvMlPyVFZqNnFDOfcwz2mYuzUmtOlM5SheMRg4DwUKviWw6rawQUMi3M62u1JFtq0CmEOX6G71mZ310OSrjI56c1/8kOrkHTXD27L0kjqldZQS+Oc2wbEBAJomsqoF9wwtlBWiZNWpSAoOhCHwW11fE1Z7N1JcMPnikGBoWXEIAxvqP1VncsKcHWTDIkwwOR9q/VdKR+N69V7Ck5HF8ek";
    const vid = VaultysId.fromSecret(secret, "base64").id.toString("base64");
    const newvid = "AIOhdgGheMQgcLKV+bymQ35KYDhFe7Lwh+8ircJiwhQATyKI7PcxPx+hZcQg8HyAjvBjWl+lhsOxm+ILaOcNP19jiPSxOuscgYA9kSw=";
    //console.log(VaultysId.fromSecret(secret, "base64"));
    assert.equal(migrateVaultysId(Buffer.from(vid, "base64")).toString("base64"), newvid);
    //console.log(vid.length, newvid.length);
    const id1 = VaultysId.fromId(vid, undefined, "base64");
    const id2 = VaultysId.fromId(newvid, undefined, "base64");
    const dkm = id1.keyManager as DeprecatedKeyManager;
    delete dkm.proof;
    delete dkm.level;
    assert.equal(serializer(id1), serializer(id2));
  });

  it("should validate signature of deprecated ID", async () => {
    const data = {
      serverId: "AIShdgGhcMQgElUJZ+qkMSASY7D/3RHa7ONo3X58XYYmtNdDs+H+UJSheMQgQMzbrE2ADcwHYY/XOjQm9UmmaGq9hnH2bQ64vTw+ZVmhZcQg+Ubxwfp1Y+dNOi49vJWJE0CHt/8Ebw+vYpYkjelr5zc=",
      signature: "anDSvD0r/q7Ozczt40R7Cc2HdjQ0SwFVooU/GWCXfsEtMJ6keUrvfX0wTO2M0uwoPgIr0dZs7Is6JtRPTxU5Ag==",
      timestamp: 1756929814984,
    };
    const id = VaultysId.fromId(data.serverId, undefined, "base64");
    //console.log(id);
    assert.equal(id.verifyChallenge_v0("vaultys.link.vaultys.org", Buffer.from(data.signature, "base64"), false, Buffer.from(data.serverId, "base64")), true);
  });

  it("deprecated ID type 1 backward compatibility", async () => {
    const km = await DeprecatedKeyManager.generate_Id25519();
    const vid = new VaultysId(km, undefined, 1);
    //console.log(vid);

    const message = "test random message not so random";
    const verifyID = VaultysId.fromId(vid.id);
    //console.log(verifyID);
    //console.log(vid.id.toString("base64"));
    //console.log(vid.getSecret("base64"));

    assert.deepEqual(km.proof, (verifyID.keyManager as DeprecatedKeyManager).proof);

    assert.equal(verifyID.verifyChallenge(message, await vid.signChallenge(message), true), true);
    assert.equal(verifyID.verifyChallenge_v0(message, await vid.signChallenge_v0(message, vid.id), true, vid.id), true);
  });
});

describe("Test Vectors", () => {
  it("should generate and deserialize v3.x IDs", async () => {
    // Test Ed25519Manager format (77 bytes)
    const person = await VaultysId.generatePerson();
    const verifyID = VaultysId.fromId(person.id);
    assert(verifyID);
    assert.equal(verifyID.id.toString("base64"), person.id.toString("base64"));
  });

  it("should sign and verify with v3.x format", async () => {
    const person = await VaultysId.generatePerson();
    const message = "test message";

    const signature = await person.signChallenge(message);
    assert(signature);

    const verifyID = VaultysId.fromId(person.id);
    const verified = verifyID.verifyChallenge(message, signature, false);
    assert.equal(verified, true);
  });

  it("should handle different identity types", async () => {
    const person = await VaultysId.generatePerson();
    const org = await VaultysId.generateOrganization();
    const machine = await VaultysId.generateMachine();

    assert(VaultysId.fromId(person.id));
    assert(VaultysId.fromId(org.id));
    assert(VaultysId.fromId(machine.id));
  });
});
