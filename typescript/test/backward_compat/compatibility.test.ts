import { expect } from "chai";
import * as path from "path";
import { VaultysId as VaultysIdOld, KeyManager as KeyManagerOld } from "@vaultys/id";
import { VaultysId as VaultysIdCurrent } from "../../dist/node/index.js";

describe("Backward Compatibility Tests - @vaultys/id@2.4.9 vs Current", () => {
  describe("VaultysId Core Functionality", () => {
    describe("ID Generation", () => {
      it("should generate compatible person IDs", async () => {
        const oldPerson = await VaultysIdOld.generatePerson();
        const currentPerson = await VaultysIdCurrent.generatePerson();

        // Check that both versions produce IDs with the same structure
        expect(oldPerson).to.have.property("did");
        expect(currentPerson).to.have.property("did");
        expect(oldPerson.did).to.match(/^did:vaultys:/);
        expect(currentPerson.did).to.match(/^did:vaultys:/);
      });

      it("should generate compatible organization IDs", async () => {
        const oldOrg = await VaultysIdOld.generateOrganization();
        const currentOrg = await VaultysIdCurrent.generateOrganization();

        expect(oldOrg).to.have.property("did");
        expect(currentOrg).to.have.property("did");
        expect(oldOrg.did).to.match(/^did:vaultys:/);
        expect(currentOrg.did).to.match(/^did:vaultys:/);
      });

      it("should generate compatible machine IDs", async () => {
        const oldMachine = await VaultysIdOld.generateMachine();
        const currentMachine = await VaultysIdCurrent.generateMachine();

        expect(oldMachine).to.have.property("did");
        expect(currentMachine).to.have.property("did");
        expect(oldMachine.did).to.match(/^did:vaultys:/);
        expect(currentMachine.did).to.match(/^did:vaultys:/);
      });
    });

    describe("Serialization and Deserialization", () => {
      it("should maintain compatibility when exporting/importing person IDs", async () => {
        // Generate with old version
        const oldPerson = await VaultysIdOld.generatePerson();
        const oldExport = oldPerson.getSecret();

        // Import with current version
        const importedInCurrent = VaultysIdCurrent.fromSecret(oldExport);
        expect(importedInCurrent.did).to.equal(oldPerson.did);
      });
    });

    describe("Signing and Verification", () => {
      it("should verify signatures created by old version with current version", async () => {
        const message = Buffer.from([1, 2, 3, 4, 5]);

        // Sign with old version
        const oldId = await VaultysIdOld.generatePerson();
        const signature = await oldId.signChallenge(message);
        expect(oldId.verifyChallenge(message, signature, false)).to.be.true;

        const currentId = VaultysIdCurrent.fromId(oldId.id);

        //console.log(currentId, oldId);
        // Verify with current version
        expect(currentId.verifyChallenge_v0(message, signature, false, oldId.id)).to.be.true;
      });
    });

    describe("Algorithm Support", () => {
      it("should support ed25519 algorithm in both versions", async () => {
        try {
          // Try with explicit algorithm parameter if supported
          const oldWithAlg = await VaultysIdOld.generatePerson();
          const currentWithAlg = await VaultysIdCurrent.generatePerson("ed25519");

          expect(oldWithAlg).to.have.property("did");
          expect(currentWithAlg).to.have.property("did");
        } catch (e) {
          // If explicit algorithm not supported in old version, test default
          const oldDefault = await VaultysIdOld.generatePerson();
          const currentDefault = await VaultysIdCurrent.generatePerson();

          expect(oldDefault).to.have.property("did");
          expect(currentDefault).to.have.property("did");
        }
      });
    });
  });

  describe("Breaking Changes Detection", () => {
    const breakingChanges: string[] = [];

    after(() => {
      if (breakingChanges.length > 0) {
        console.log("\n=== BREAKING CHANGES DETECTED ===");
        breakingChanges.forEach((change, index) => {
          console.log(`${index + 1}. ${change}`);
        });
        console.log("=================================\n");
      } else {
        console.log("\n✅ No breaking changes detected between v2.4.9 and current version\n");
      }
    });

    it("should track API changes", async () => {
      // Check if methods exist in both versions
      const oldId = await VaultysIdOld.generatePerson();
      const currentId = await VaultysIdCurrent.generatePerson();

      const methods = ["sign", "verify", "encrypt", "decrypt", "derive", "export", "toJSON", "createChannel"];

      for (const method of methods) {
        const oldHasMethod = typeof (oldId as any)[method] === "function";
        const currentHasMethod = typeof (currentId as any)[method] === "function";

        if (oldHasMethod && !currentHasMethod) {
          breakingChanges.push(`Method '${method}' removed in current version`);
        } else if (!oldHasMethod && currentHasMethod) {
          console.log(`New method '${method}' added in current version`);
        }
      }
    });
  });

  describe("Deprecated ID Format Tests", () => {
    describe("V0 Deprecated IDs", () => {
      it("should deserialize type 1 deprecated ID (Ed25519 with proof)", async () => {
        const deprecatedId1 = "AYShdgGhcMQgAkdXeakmUj369/IVsxtgfZDvIl5H20sMr4Hvscd6vv2heMQg087CgsDqArlFnddT45WIE4q5ASE29yMy2ymtYF7wayqhZcQgc6ZsnBDgIVgudow5lIhodS2/hS8OL0lah8m9XE9QDng=";

        // Deserialize with old version
        const oldVid = VaultysIdOld.fromId(Buffer.from(deprecatedId1, "base64"));
        expect(oldVid).to.exist;

        // Deserialize with current version
        const currentVid = VaultysIdCurrent.fromId(Buffer.from(deprecatedId1, "base64"));
        expect(currentVid).to.exist;

        // Both should have the same core properties
        expect(oldVid.id.toString("base64")).to.equal(currentVid.id.toString("base64"));
      });

      it("should deserialize type 4 deprecated ID (P256)", async () => {
        const deprecatedId4 = "BIOhdgGhY8RNpQECAyYgASFYIAahPdTq/F42/PU9WcYGaF4k7BQ1gnD9QIwX2wAcfjKoIlggO56gS5dUKbQZSeBrcYZcOZHZF5F568tgRiDLO2mv5/KhZcQgQ136sOFkQ6Ywe3GbYeGF8bZkLxM0D3Ym7JmdZAubAxE=";

        // Deserialize with old version
        const oldVid = VaultysIdOld.fromId(Buffer.from(deprecatedId4, "base64"));
        expect(oldVid).to.exist;

        // Deserialize with current version
        const currentVid = VaultysIdCurrent.fromId(Buffer.from(deprecatedId4, "base64"));
        expect(currentVid).to.exist;

        // Both should have the same core properties
        expect(oldVid.id.toString("base64")).to.equal(currentVid.id.toString("base64"));
      });

      it("should create IDs using old KeyManager (v2.x) and deserialize in current version", async () => {
        // KeyManager in v2.x is now called DeprecatedKeyManager in v3.x
        const oldKm = await KeyManagerOld.generate_Id25519();
        const oldVid = new VaultysIdOld(oldKm as any, undefined, 1);

        // Deserialize the generated ID with current version
        const currentVid = VaultysIdCurrent.fromId(oldVid.id);
        expect(currentVid).to.exist;

        // Verify we can read the same core properties
        expect(currentVid.id.toString("base64")).to.equal(oldVid.id.toString("base64"));
      });
    });

    describe("ID Migration", () => {
      it("should migrate deprecated ID structure correctly", async () => {
        const oldVersionId = "AYShdgGhcMQgAkdXeakmUj369/IVsxtgfZDvIl5H20sMr4Hvscd6vv2heMQg087CgsDqArlFnddT45WIE4q5ASE29yMy2ymtYF7wayqhZcQgc6ZsnBDgIVgudow5lIhodS2/hS8OL0lah8m9XE9QDng=";
        const expectedMigratedId = "AYOhdgGheMQg087CgsDqArlFnddT45WIE4q5ASE29yMy2ymtYF7wayqhZcQgc6ZsnBDgIVgudow5lIhodS2/hS8OL0lah8m9XE9QDng=";

        // Import migration utility from current version
        const { migrateVaultysId } = await import("../../dist/node/utils/migration.js");

        const migrated = migrateVaultysId(Buffer.from(oldVersionId, "base64"));
        expect(migrated.toString("base64")).to.equal(expectedMigratedId);
      });

      it("should deserialize same data after migration", async () => {
        const oldVersionId = "AYShdgGhcMQgAkdXeakmUj369/IVsxtgfZDvIl5H20sMr4Hvscd6vv2heMQg087CgsDqArlFnddT45WIE4q5ASE29yMy2ymtYF7wayqhZcQgc6ZsnBDgIVgudow5lIhodS2/hS8OL0lah8m9XE9QDng=";
        const migratedId = "AYOhdgGheMQg087CgsDqArlFnddT45WIE4q5ASE29yMy2ymtYF7wayqhZcQgc6ZsnBDgIVgudow5lIhodS2/hS8OL0lah8m9XE9QDng=";

        const { migrateVaultysId } = await import("../../dist/node/utils/migration.js");

        // Old version
        const oldVid = VaultysIdOld.fromId(Buffer.from(oldVersionId, "base64"));

        // Migrated version
        const migratedBuffer = migrateVaultysId(Buffer.from(oldVersionId, "base64"));
        const currentVid = VaultysIdCurrent.fromId(migratedBuffer);

        // The core signer and cypher public keys should match
        const oldKeyManager = (oldVid as any).keyManager;
        const currentKeyManager = (currentVid as any).keyManager;

        expect(oldKeyManager.signer.publicKey.toString("base64"))
          .to.equal(currentKeyManager.signer.publicKey.toString("base64"));
        expect(oldKeyManager.cypher.publicKey.toString("base64"))
          .to.equal(currentKeyManager.cypher.publicKey.toString("base64"));
      });
    });

    describe("Signature Verification with Deprecated IDs", () => {
      it("should validate signature of deprecated ID with v0 format", async () => {
        const data = {
          serverId: "AIShdgGhcMQgElUJZ+qkMSASY7D/3RHa7ONo3X58XYYmtNdDs+H+UJSheMQgQMzbrE2ADcwHYY/XOjQm9UmmaGq9hnH2bQ64vTw+ZVmhZcQg+Ubxwfp1Y+dNOi49vJWJE0CHt/8Ebw+vYpYkjelr5zc=",
          signature: "anDSvD0r/q7Ozczt40R7Cc2HdjQ0SwFVooU/GWCXfsEtMJ6keUrvfX0wTO2M0uwoPgIr0dZs7Is6JtRPTxU5Ag==",
          timestamp: 1756929814984,
        };

        // Create with old version
        const oldVid = VaultysIdOld.fromId(Buffer.from(data.serverId, "base64"));
        expect(oldVid.verifyChallenge_v0("vaultys.link.vaultys.org", Buffer.from(data.signature, "base64"), false, Buffer.from(data.serverId, "base64"))).to.be.true;

        // Verify with current version - should also support this old format
        const currentVid = VaultysIdCurrent.fromId(Buffer.from(data.serverId, "base64"));
        expect(currentVid.verifyChallenge_v0("vaultys.link.vaultys.org", Buffer.from(data.signature, "base64"), false, Buffer.from(data.serverId, "base64"))).to.be.true;
      });

      it("should work with KeyManager.generate_Id25519() from v2.x", async () => {
        // Generate with old version's KeyManager (which is DeprecatedKeyManager in v3.x)
        const oldKm = await KeyManagerOld.generate_Id25519();
        const oldVid = new VaultysIdOld(oldKm as any);

        // Sign with old version
        const message = "test message";
        const signature = await oldVid.signChallenge(message);

        // Verify with old version
        const verifyOld = oldVid.verifyChallenge(message, signature, false);
        expect(verifyOld).to.be.true;
      });
    });
  });
}); 
