/**
 * Fido2PRFManager extends Fido2Manager and overrides createFromAttestation and
 * fromSecret, but not instantiate/fromId. Those two used to hardcode
 * `new Fido2Manager()`, so a type-4 (passkey + PRF) id was rehydrated as a plain
 * Fido2Manager. Because Fido2Manager.get id applies serializeID_v0 at version 0
 * while Fido2PRFManager never does, the DID silently changed on every round-trip
 * and a passkey identity could not be looked up by a relying party.
 */
import assert from "assert";
import VaultysId from "../src/VaultysId";
import Fido2Manager from "../src/KeyManager/Fido2Manager";
import Fido2PRFManager from "../src/KeyManager/Fido2PRFManager";
import SoftCredentials from "../src/platform/SoftCredentials";
import "./shims";

const create = async (prf: boolean, alg: -7 | -8 = -7) => {
  const attestation = await navigator.credentials.create(SoftCredentials.createRequest(alg, prf));
  // @ts-expect-error SoftCredentials mockup
  return (await VaultysId.fido2FromAttestation(attestation))!;
};

describe("FIDO2 id round-trip", () => {
  for (const [label, prf, type, Manager] of [
    ["passkey (type 3)", false, 3, Fido2Manager],
    ["passkey + PRF (type 4)", true, 4, Fido2PRFManager],
  ] as const) {
    describe(label, () => {
      it("is created with the expected type", async () => {
        const id = await create(prf);
        assert.equal(id.type, type);
        assert.ok(id.keyManager instanceof Manager);
      });

      for (const version of [0, 1] as const) {
        it(`keeps its DID through fromId at version ${version}`, async () => {
          const id = await create(prf);
          const expected = id.toVersion(version).did;
          const restored = VaultysId.fromId(id.toVersion(version).id);
          assert.equal(restored.did, expected);
          // and the rehydrated key manager must be the right class, otherwise the
          // id serialization silently switches format
          assert.ok(restored.keyManager instanceof Manager);
        });
      }

      it("keeps its DID through instantiate (stored contact rehydration)", async () => {
        const id = await create(prf);
        const expected = id.toVersion(0).did;
        const km = Manager.instantiate(JSON.parse(JSON.stringify(id.toVersion(0).keyManager)));
        assert.ok(km instanceof Manager);
        assert.equal(new VaultysId(km, undefined, type).toVersion(0).did, expected);
      });
    });
  }
});
