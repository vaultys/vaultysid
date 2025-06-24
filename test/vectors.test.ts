import assert from "assert";
import VaultysId from "../src/VaultysId";
import { migrateVaultysId } from "../src/utils/migration";
import { Buffer } from "buffer/";

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
      authType: "P256VerificationKey2020",
      encType: "X25519KeyAgreementKey2019",
      ckey: "pQECAyYgASFYIAahPdTq/F42/PU9WcYGaF4k7BQ1gnD9QIwX2wAcfjKoIlggO56gS5dUKbQZSeBrcYZcOZHZF5F568tgRiDLO2mv5/I=",
      webAuthn: {
        origin: "test",
      },
    },
  },
};

describe("Test Vectors", () => {
  it("pass IDs", async () => {
    for (const id of Object.keys(IDs)) {
      const vid = VaultysId.fromId(Buffer.from(id, "base64"));
      assert.deepEqual(JSON.parse(serializer(vid)), IDs[id]);
    }
  });
  it("migrate VaultysID serialization", () => {
    const vid = "AYShdgGhcMQgAkdXeakmUj369/IVsxtgfZDvIl5H20sMr4Hvscd6vv2heMQg087CgsDqArlFnddT45WIE4q5ASE29yMy2ymtYF7wayqhZcQgc6ZsnBDgIVgudow5lIhodS2/hS8OL0lah8m9XE9QDng=";
    const newvid = "AYShdgGhcMQAoXjEINPOwoLA6gK5RZ3XU+OViBOKuQEhNvcjMtsprWBe8GsqoWXEIHOmbJwQ4CFYLnaMOZSIaHUtv4UvDi9JWofJvVxPUA54";
    assert.equal(migrateVaultysId(Buffer.from(vid, "base64")).toString("base64"), newvid);

    const id1 = VaultysId.fromId(vid, undefined, "base64");
    const id2 = VaultysId.fromId(newvid, undefined, "base64");
    //id1.keyManager.proof = Buffer.from([]);
    assert.equal(serializer(id1), serializer(id2));
  });
});
