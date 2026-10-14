/**
 * Cross-version SRP handshake: @vaultys/id@2.4.10 (legacy, bip32-ed25519) against
 * the current source tree.
 *
 * This is the production scenario. SmartLink still runs 2.4.x and stores legacy
 * identities; WalletID ships the current library. Certificates are exchanged as raw
 * buffers, exactly as they travel over the wire, so the two libraries never share an
 * object and nothing can accidentally pass through a shared code path.
 *
 * The suite that matters most is "existing user upgrades the wallet": a legacy key
 * loaded by the current library must still complete a v0 handshake against an
 * un-migrated 2.4.x server, with an unchanged DID.
 */
import assert from "assert";
import { Buffer } from "buffer/";
import { Challenger as OldChallenger, VaultysId as OldVaultysId } from "@vaultys/id_2";
import NewChallenger from "../../src/Challenger";
import NewVaultysId from "../../src/VaultysId";
import "../shims";

// The two libraries return different Buffer implementations; the wire format is
// plain bytes, so normalise on every hop.
const wire = (cert: unknown) => Buffer.from(cert as Uint8Array) as unknown as Buffer;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const contactDid = (challenger: unknown) => (challenger as any).getContactId().did as string;

describe("Cross-version SRP - legacy 2.4.10 vs current", () => {
  describe("reading legacy identities", () => {
    it("resolves a legacy id out of a certificate with an unchanged DID", async () => {
      const oldId = await OldVaultysId.generatePerson();
      const oldChallenger = new OldChallenger(oldId);
      oldChallenger.createChallenge("p2p", "auth", 0);

      // Exactly what SmartLink puts on the wire and the wallet has to parse.
      const parsed = NewChallenger.deserializeCertificate(wire(oldChallenger.getCertificate()));
      assert.ok(parsed.pk1, "pk1 must be present in the INIT certificate");

      const resolved = NewVaultysId.fromId(Buffer.from(parsed.pk1 as unknown as Uint8Array));
      assert.equal(resolved.did, oldId.toVersion(0).did);
    });

    it("verifies a legacy .well-known style signature", async () => {
      const server = await OldVaultysId.generateMachine();
      const host = "smartlink.example.org";
      const signature = wire(await server.signChallenge(host));

      // The wallet re-derives the server identity from the published serverId.
      const serverId = server.toVersion(1).id;
      const resolved = NewVaultysId.fromId(wire(serverId));
      assert.equal(resolved.verifyChallenge_v0(host, signature, false, wire(serverId)), true);
    });
  });

  describe("existing user upgrades the wallet (legacy key, current library)", () => {
    it("completes a v0 handshake against an un-migrated 2.4.x server", async () => {
      const legacy = await OldVaultysId.generatePerson();
      const secret = legacy.getSecret("base64");

      const server = new OldChallenger(await OldVaultysId.generateMachine());
      const walletId = NewVaultysId.fromSecret(secret, "base64");
      const wallet = new NewChallenger(walletId.toVersion(0));

      // The DID the server has on file must not move.
      assert.equal(walletId.toVersion(0).did, legacy.toVersion(0).did);
      assert.equal(walletId.toVersion(0).id.length, 116, "must present the legacy envelope");

      server.createChallenge("p2p", "auth", 0);
      await wallet.update(wire(server.getCertificate()));
      await server.update(wire(wallet.getCertificate()));
      await wallet.update(wire(server.getCertificate()));

      assert.ok(server.isComplete(), "server side must complete");
      assert.ok(wallet.isComplete(), "wallet side must complete");
      assert.ok(!server.hasFailed());
      assert.ok(!wallet.hasFailed());
      assert.equal(server.toString(), wallet.toString(), "symmetric proof");
      assert.equal(contactDid(server), legacy.toVersion(0).did, "server must recognise the known DID");
    });

    it("completes when the current library initiates", async () => {
      const legacy = await OldVaultysId.generatePerson();
      const walletId = NewVaultysId.fromSecret(legacy.getSecret("base64"), "base64");

      const wallet = new NewChallenger(walletId.toVersion(0));
      const server = new OldChallenger(await OldVaultysId.generateMachine());

      wallet.createChallenge("p2p", "auth", 0);
      await server.update(wire(wallet.getCertificate()));
      await wallet.update(wire(server.getCertificate()));
      await server.update(wire(wallet.getCertificate()));

      assert.ok(wallet.isComplete());
      assert.ok(server.isComplete());
      assert.equal(wallet.toString(), server.toString());
    });

    it("produces a certificate the current library can re-verify", async () => {
      const legacy = await OldVaultysId.generatePerson();
      const walletId = NewVaultysId.fromSecret(legacy.getSecret("base64"), "base64");

      const server = new OldChallenger(await OldVaultysId.generateMachine());
      const wallet = new NewChallenger(walletId.toVersion(0));

      server.createChallenge("p2p", "auth", 0);
      await wallet.update(wire(server.getCertificate()));
      await server.update(wire(wallet.getCertificate()));
      await wallet.update(wire(server.getCertificate()));

      const parsed = NewChallenger.deserializeCertificate(wire(wallet.getCertificate()));
      assert.ok(!parsed.error, `certificate must parse cleanly, got: ${parsed.error}`);
      assert.ok(parsed.sign1 && parsed.sign2, "both signatures must be present");
      assert.ok(NewVaultysId.fromId(Buffer.from(parsed.pk1 as unknown as Uint8Array)));
      assert.ok(NewVaultysId.fromId(Buffer.from(parsed.pk2 as unknown as Uint8Array)));
    });
  });

  describe("known limitation: 2.4.x cannot read native ids", () => {
    /**
     * 2.4.10 decodes an id as msgpack {v,p,x,e} and stores `km.proof = data.p`.
     * A native 77-byte {v,x,e} id therefore parses WITHOUT error, yielding a
     * silently corrupted identity whose `proof` is undefined; the failure only
     * surfaces later, when the DID is derived or a signature is verified. That is
     * why a native identity shows up as "[STEP1] failed the verification of pk2"
     * rather than as a clean parse error.
     *
     * This cannot be fixed from the current library — the 2.4.x code is already
     * deployed. Consequence for the rollout: SmartLink must be upgraded BEFORE any
     * natively generated identity tries to register, because a freshly created
     * identity cannot enrol on a 2.4.x server. These tests pin the behaviour so
     * the constraint is tracked instead of rediscovered in production.
     */
    it("parses a native id without error but silently corrupts it", async () => {
      const native = await NewVaultysId.generatePerson();
      assert.equal(native.toVersion(0).id.length, 77, "native ids are 77 bytes");

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const parsed = (OldVaultysId as any).fromId(wire(native.toVersion(0).id));
      assert.equal(parsed.keyManager.proof, undefined, "the legacy proof field cannot be recovered");

      // The corruption only becomes visible when the DID is derived.
      let didError: Error | undefined;
      try {
        void parsed.did;
      } catch (e) {
        didError = e as Error;
      }
      assert.ok(didError, "deriving a DID from a corrupted legacy identity must fail");
    });

    it("fails the handshake when a native identity faces a 2.4.x peer", async () => {
      const native = await NewVaultysId.generatePerson();
      const server = new OldChallenger(await OldVaultysId.generateMachine());
      const wallet = new NewChallenger(native.toVersion(0));

      server.createChallenge("p2p", "auth", 0);
      await wallet.update(wire(server.getCertificate()));

      // The server cannot make sense of pk2, so it rejects the answer.
      await assert.rejects(async () => server.update(wire(wallet.getCertificate())));
    });
  });
});
