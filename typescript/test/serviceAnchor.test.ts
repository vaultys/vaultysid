import assert from "assert";
import { readFileSync } from "node:fs";
import { Buffer } from "buffer/";
import { IdManager, MemoryChannel, MemoryStorage, VaultysId } from "..";
import "./shims";
import { checkAnchorPin, createServiceAnchor, serviceAnchorUrl, verifyServiceAnchor } from "../src/serviceAnchor";
import { acceptOverXWing, connectOverXWing, isChannelError } from "../src/xwingChannel";
import { buildVectors, VECTORS_PATH } from "./interops/generate-service-anchor-vectors";

// rfc/SERVICE-IDENTITIES.md §8

const SERVICE = "https://service-a.test";

describe("Service anchors", () => {
  for (const alg of ["ed25519", "dilithium", "dilithium_ed25519"] as const) {
    it(`round-trips (${alg})`, async () => {
      const service = await VaultysId.generateOrganization(alg);
      const anchor = await createServiceAnchor(service, SERVICE);
      const identity = verifyServiceAnchor(anchor, SERVICE);
      assert.ok(identity);
      assert.strictEqual(identity!.did, service.did);
      assert.strictEqual(verifyServiceAnchor(anchor, "https://service-b.test"), null);
    });
  }

  it("refuses a non-canonical service id when creating", async () => {
    await assert.rejects(createServiceAnchor(await VaultysId.generateOrganization(), "https://Service-A.test/"), /invalid service id/);
  });

  it("gives the anchor URL of an origin, none for app: ids", () => {
    assert.strictEqual(serviceAnchorUrl("https://Service-A.test/"), "https://service-a.test/.well-known/vaultysid-service");
    assert.throws(() => serviceAnchorUrl("app:test.service.c"), /no web origin/);
  });

  it("pins the first identity and reports a change", async () => {
    const pins = new Map<string, string>();
    const first = await VaultysId.generateOrganization();
    const second = await VaultysId.generateOrganization();
    assert.strictEqual(checkAnchorPin(pins, SERVICE, first), "pinned");
    assert.strictEqual(checkAnchorPin(pins, SERVICE, VaultysId.fromId(first.id)), "same");
    assert.strictEqual(checkAnchorPin(pins, SERVICE, second), "changed");
  });

  it("makes the bound handshake refuse an impostor that answers for the origin", async () => {
    const real = new IdManager(
      await VaultysId.generateOrganization(),
      MemoryStorage(() => ""),
    );
    const impostor = new IdManager(
      await VaultysId.generateOrganization(),
      MemoryStorage(() => ""),
    );
    const user = new IdManager(
      await VaultysId.generatePerson(),
      MemoryStorage(() => ""),
    );
    const expected = verifyServiceAnchor(await createServiceAnchor(real.vaultysId, SERVICE), SERVICE)!;
    const ok = MemoryChannel.createBidirectionnal();
    await Promise.all([connectOverXWing(user, ok, SERVICE, {}, { expectedPeer: expected }), acceptOverXWing(real, ok.otherend!, SERVICE)]);
    const bad = MemoryChannel.createBidirectionnal();
    const results = await Promise.allSettled([connectOverXWing(user, bad, SERVICE, {}, { expectedPeer: expected }), acceptOverXWing(impostor, bad.otherend!, SERVICE)]);
    assert.ok(results[0].status === "rejected" && isChannelError(results[0].reason, "PEER_MISMATCH"));
  });

  describe("test vectors", () => {
    const vectors = JSON.parse(readFileSync(VECTORS_PATH, "utf8"));
    it("accepts the valid anchors", () => {
      for (const v of vectors.valid) assert.strictEqual(verifyServiceAnchor(Buffer.from(v.anchor, "hex"), v.serviceId)?.did, v.did, v.serviceId);
    });
    it("refuses the invalid anchors", () => {
      for (const v of vectors.invalid) assert.strictEqual(verifyServiceAnchor(Buffer.from(v.anchor, "hex"), v.serviceId), null, v.name);
    });
    it("are reproducible", async () => {
      assert.deepStrictEqual(JSON.parse(JSON.stringify(await buildVectors())), vectors);
    });
  });
});
