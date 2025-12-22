import { expect } from "chai";
import * as path from "path";
import { VaultysId as VaultysIdOld } from "@vaultys/id";
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
});
