/**
 * A security key that answers an extension (a YubiKey asked for `prf` replies with
 * {"hmac-secret": true}) sets the ED flag and appends authenticator extension data
 * after the credential public key inside authData.
 *
 * parseAuthData used to take the whole tail as the COSE key, so every later
 * cbor.decode of it failed with `UnexpectedDataError: Unexpected data: 0xa1` and no
 * FIDO2 profile could be created. Platform passkeys were unaffected because they
 * return no authenticator extension data, which is why only hardware keys broke.
 */
import assert from "assert";
import cbor from "cbor";
import { Buffer } from "buffer/";
import SoftCredentials from "../src/platform/SoftCredentials";
import VaultysId from "../src/VaultysId";
import "./shims";

/** Re-emit an attestation with authenticator extension data appended, ED flag set. */
const withExtensionData = (attestation: any, extension: Map<string, unknown>) => {
  const ato = cbor.decode(Buffer.from(attestation.response.attestationObject) as unknown as Buffer);
  const authData = Buffer.from(ato.authData);

  const flagsOffset = 32;
  authData[flagsOffset] = authData[flagsOffset] | 0x80; // ED
  const patched = Buffer.concat([authData, Buffer.from(cbor.encode(extension))]);

  const rebuilt = cbor.encode({ ...ato, authData: patched });
  return {
    ...attestation,
    response: { ...attestation.response, attestationObject: Buffer.from(rebuilt) },
    getClientExtensionResults: () => attestation.getClientExtensionResults(),
  };
};

describe("FIDO2 authenticator extension data", () => {
  for (const [label, alg] of [
    ["ECDSA (-7)", -7],
    ["EdDSA (-8)", -8],
  ] as const) {
    it(`${label}: the COSE key is isolated from trailing extension data`, async () => {
      const attestation = await navigator.credentials.create(SoftCredentials.createRequest(alg, false));
      const patched = withExtensionData(attestation, new Map([["hmac-secret", true]]));

      const ckey = SoftCredentials.getCOSEPublicKey(patched as any);
      assert.ok(ckey, "a COSE key must be extracted");
      // Must decode on its own, with nothing left over.
      const decoded = cbor.decodeFirstSync(Buffer.from(ckey) as unknown as Buffer, { extendedResults: true });
      assert.equal(decoded.unused?.length ?? 0, 0, "the COSE key must not carry trailing bytes");
    });

    it(`${label}: an identity can still be created`, async () => {
      const attestation = await navigator.credentials.create(SoftCredentials.createRequest(alg, false));
      const patched = withExtensionData(attestation, new Map([["hmac-secret", true]]));

      const id = await VaultysId.fido2FromAttestation(patched as any);
      assert.ok(id, "fido2FromAttestation must succeed");
      assert.equal(id!.type, 3);
      assert.notEqual(id!.keyManager.authType, "Unknown");
    });
  }
});
