import assert from "assert";
import { readFileSync } from "node:fs";
import { Buffer } from "buffer/";
import { IdManager, MemoryChannel, MemoryStorage, VaultysId } from "..";
import "./shims";
import { canonicalServiceId, deriveServiceIdentity, isCanonicalServiceId, MASTER_SECRET_LENGTH, type ServiceAlgorithm } from "../src/serviceIdentity";
import { buildVectors, testMaster, VECTORS_PATH } from "./interops/generate-service-identity-vectors";

// rfc/SERVICE-IDENTITIES.md

const MASTER = testMaster("master");
const ALGS: ServiceAlgorithm[] = ["ed25519", "dilithium", "dilithium_ed25519"];

/** Offsets of the 8-byte windows that appear in both arrays. */
function commonWindows(a: Uint8Array, b: Uint8Array, size = 8): number[] {
  const seen = new Set<string>();
  for (let i = 0; i + size <= a.length; i++) seen.add(Buffer.from(a.subarray(i, i + size)).toString("hex"));
  const found: number[] = [];
  for (let j = 0; j + size <= b.length; j++) if (seen.has(Buffer.from(b.subarray(j, j + size)).toString("hex"))) found.push(j);
  return found;
}

describe("Service identities", () => {
  describe("canonicalServiceId", () => {
    it("gives one id for equivalent spellings", () => {
      for (const s of ["https://Example.com/", "https://example.com", "https://example.com:443", "HTTPS://EXAMPLE.COM"]) {
        assert.strictEqual(canonicalServiceId(s), "https://example.com");
      }
    });

    it("keeps different services apart", () => {
      assert.notStrictEqual(canonicalServiceId("https://sub.example.com"), canonicalServiceId("https://example.com"));
      assert.strictEqual(canonicalServiceId("https://example.com:8443"), "https://example.com:8443");
      assert.strictEqual(canonicalServiceId("http://example.com", { allowDevelopmentHosts: true }), "http://example.com");
    });

    it("refuses ambiguous or non-origin input", () => {
      for (const s of ["https://example.com/login", "https://example.com?q", "https://example.com#f", "https://user@example.com", "https://ex%61mple.com", "https://example.com.", "https://exémple.com", "ftp://example.com", "", "app:Com.x", "app:x", "https://0x7f.1"]) {
        assert.throws(() => canonicalServiceId(s), /invalid service id/, s);
      }
    });

    it("refuses http and development hosts by default", () => {
      for (const s of ["http://example.com", "http://localhost:3000", "https://127.0.0.1", "http://[::1]:8080"]) {
        assert.throws(() => canonicalServiceId(s), /invalid service id/, s);
      }
      assert.strictEqual(canonicalServiceId("http://localhost:3000", { allowDevelopmentHosts: true }), "http://localhost:3000");
    });

    it("never decodes punycode", () => {
      assert.strictEqual(canonicalServiceId("https://XN--XAMPLE-2OF.COM/"), "https://xn--xample-2of.com");
    });

    it("isCanonicalServiceId never throws", () => {
      assert.ok(isCanonicalServiceId("https://example.com"));
      assert.ok(!isCanonicalServiceId("https://Example.com/"));
      assert.ok(!isCanonicalServiceId(42));
    });
  });

  describe("deriveServiceIdentity", () => {
    for (const alg of ALGS) {
      it(`is deterministic (${alg})`, async () => {
        const a = await deriveServiceIdentity(MASTER, "https://example.com", { alg });
        const b = await deriveServiceIdentity(Uint8Array.from(MASTER), "https://Example.com/", { alg });
        assert.strictEqual(a.did, b.did);
        assert.ok(Buffer.from(a.id).equals(Buffer.from(b.id)));
      });
    }

    it("defaults to a classical Ed25519 person", async () => {
      const id = await deriveServiceIdentity(MASTER, "https://example.com");
      assert.strictEqual(id.type, 1);
      assert.strictEqual(id.id.length, 77);
      assert.ok(id.isPerson() && !id.isPostQuantum());
    });

    it("derives post-quantum and other role types", async () => {
      const pq = await deriveServiceIdentity(MASTER, "https://example.com", { alg: "dilithium_ed25519", postQuantum: true });
      assert.strictEqual(pq.type, 0x11);
      assert.ok(pq.isPostQuantum());
      const org = await deriveServiceIdentity(MASTER, "https://example.com", { role: "organization" });
      assert.strictEqual(org.type, 2);
      await assert.rejects(deriveServiceIdentity(MASTER, "https://example.com", { postQuantum: true }), /require a dilithium/);
    });

    it("gives unrelated identities to two services", async () => {
      for (const alg of ALGS) {
        const a = await deriveServiceIdentity(MASTER, "https://service-a.test", { alg });
        const b = await deriveServiceIdentity(MASTER, "https://service-b.test", { alg });
        assert.notStrictEqual(a.did, b.did);
        const pa = Uint8Array.from(a.keyManager.signer.publicKey);
        const pb = Uint8Array.from(b.keyManager.signer.publicKey);
        assert.deepStrictEqual(commonWindows(pa, pb), [], alg);
      }
    });

    it("gives different keys to two algorithms or two types of one service", async () => {
      const ed = await deriveServiceIdentity(MASTER, "https://example.com", { alg: "ed25519" });
      const hybrid = await deriveServiceIdentity(MASTER, "https://example.com", { alg: "dilithium_ed25519" });
      const edSigner = Buffer.from(ed.keyManager.signer.publicKey);
      assert.strictEqual(Buffer.from(hybrid.id).indexOf(edSigner), -1);
      const person = await deriveServiceIdentity(MASTER, "https://example.com", { role: "person" });
      const machine = await deriveServiceIdentity(MASTER, "https://example.com", { role: "machine" });
      assert.ok(!Buffer.from(person.keyManager.signer.publicKey).equals(Buffer.from(machine.keyManager.signer.publicKey)));
    });

    it("signs and verifies", async () => {
      const id = await deriveServiceIdentity(MASTER, "https://example.com", { alg: "dilithium_ed25519" });
      const data = Buffer.from("message");
      const signature = await id.sign(data);
      assert.ok(signature && VaultysId.fromId(id.id).verify(data, signature));
    });

    it("leaves the master secret untouched", async () => {
      const master = Uint8Array.from(MASTER);
      await deriveServiceIdentity(master, "https://example.com");
      assert.ok(Buffer.from(master).equals(Buffer.from(MASTER)));
    });

    it("refuses a bad master secret, service, algorithm or role", async () => {
      await assert.rejects(deriveServiceIdentity(new Uint8Array(MASTER_SECRET_LENGTH), "https://example.com"), /invalid master secret/);
      await assert.rejects(deriveServiceIdentity(new Uint8Array(31).fill(1), "https://example.com"), /invalid master secret/);
      await assert.rejects(deriveServiceIdentity(MASTER, "https://example.com/login"), /invalid service id/);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await assert.rejects(deriveServiceIdentity(MASTER, "https://example.com", { alg: "rsa" as any }), /unsupported algorithm/);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await assert.rejects(deriveServiceIdentity(MASTER, "https://example.com", { role: "admin" as any }), /unsupported role/);
    });

    it("lets two services see different identities in a handshake, and one service the same twice", async () => {
      const serviceA = new IdManager(
        await VaultysId.generateOrganization(),
        MemoryStorage(() => ""),
      );
      const serviceB = new IdManager(
        await VaultysId.generateOrganization(),
        MemoryStorage(() => ""),
      );
      const connect = async (service: IdManager, serviceId: string) => {
        const user = new IdManager(
          await deriveServiceIdentity(MASTER, serviceId),
          MemoryStorage(() => ""),
        );
        const channel = MemoryChannel.createBidirectionnal();
        const [, seen] = await Promise.all([user.askContact(channel, {}), service.acceptContact(channel.otherend!, {})]);
        return seen!.did;
      };
      const seenByA1 = await connect(serviceA, "https://service-a.test");
      const seenByA2 = await connect(serviceA, "https://service-a.test");
      const seenByB = await connect(serviceB, "https://service-b.test");
      assert.strictEqual(seenByA1, seenByA2);
      assert.notStrictEqual(seenByA1, seenByB);
    });
  });

  describe("test vectors", () => {
    it("are reproducible", async () => {
      const onDisk = JSON.parse(readFileSync(VECTORS_PATH, "utf8"));
      assert.deepStrictEqual(JSON.parse(JSON.stringify(await buildVectors())), onDisk);
    });
  });
});
