/**
 * Real WebAuthn hands back ArrayBuffers; the node SoftCredentials mock hands back
 * Buffers. msgpack only encodes Uint8Arrays and views as `bin` — a bare ArrayBuffer
 * is silently encoded as an empty map. So Fido2Manager.getSigner used to ship a
 * signature payload whose three fields decoded to {}, and verification died with
 * '"[object Object]" is not valid JSON' deep inside extractChallenge.
 *
 * This was invisible to every other test in this suite because they all run against
 * the Buffer-returning mock. Here we wrap the provider so it behaves like a browser.
 */
import assert from "assert";
import { Buffer } from "buffer/";
import VaultysId from "../src/VaultysId";
import SoftCredentials from "../src/platform/SoftCredentials";
import "./shims";

// Turn every byte field of the assertion into a bare ArrayBuffer, exactly as a real
// navigator.credentials.get() would.
const toArrayBuffer = (b: Uint8Array | ArrayBuffer): ArrayBuffer => {
  if (b instanceof ArrayBuffer) return b;
  const view = new Uint8Array(b.byteLength);
  view.set(b as Uint8Array);
  return view.buffer;
};

const browserify = (id: VaultysId) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const km = id.keyManager as any;
  const inner = km.webAuthn;
  km.webAuthn = {
    ...inner,
    get: async (publicKey: PublicKeyCredentialRequestOptions) => {
      const credential = await inner.get(publicKey);
      const r = credential.response;
      return {
        ...credential,
        response: {
          signature: toArrayBuffer(r.signature),
          clientDataJSON: toArrayBuffer(r.clientDataJSON),
          authenticatorData: toArrayBuffer(r.authenticatorData),
          userHandle: null,
        },
      };
    },
  };
  return id;
};

const create = async (prf: boolean) => {
  const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-7, prf));
  // @ts-expect-error SoftCredentials mockup
  return (await VaultysId.fido2FromAttestation(attestation))!;
};

describe("FIDO2 signatures built from ArrayBuffers (real browser shape)", () => {
  for (const [label, prf] of [
    ["passkey (type 3)", false],
    ["passkey + PRF (type 4)", true],
  ] as const) {
    it(`${label}: signs and verifies`, async () => {
      const id = browserify(await create(prf));
      const challenge = Buffer.from("a challenge to sign");

      const signature = await id.signChallenge(challenge);
      assert.ok(signature, "signing must produce a payload");
      assert.equal(id.verifyChallenge(challenge, signature, false), true);
    });

    it(`${label}: the payload carries real bytes, not empty maps`, async () => {
      const id = browserify(await create(prf));
      const signature = await id.signChallenge(Buffer.from("another challenge"));
      const { decode } = await import("@msgpack/msgpack");
      const decoded = decode(Buffer.from(signature) as unknown as Uint8Array) as Record<string, unknown>;
      for (const field of ["s", "c", "a"]) {
        const value = decoded[field];
        assert.ok(ArrayBuffer.isView(value) || value instanceof ArrayBuffer, `field ${field} decoded as ${Object.prototype.toString.call(value)} instead of bytes`);
        assert.ok((value as Uint8Array).byteLength > 0, `field ${field} is empty`);
      }
    });
  }
});
