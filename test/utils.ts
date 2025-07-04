import { VaultysId } from "../";
import SoftCredentials from "../src/platform/SoftCredentials";
import { PQ_COSE_ALG } from "../src/pqCrypto";

export const createApp = async () => {
  return VaultysId.generateMachine();
};

export const createContact = async () => {
  const types = [1, 2];
  if (typeof window === "undefined") {
    types.push(3);
    types.push(4);
  }

  const type = types[Math.floor(Math.random() * types.length)];

  switch (type) {
    case 1:
      return VaultysId.generatePerson();
    case 2:
      return VaultysId.generateOrganization();
    case 3:
      const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(Math.random() < 0.5 ? -7 : -8, false));
      // @ts-expect-error mockup
      return VaultysId.fido2FromAttestation(attestation1);
    case 4:
      const attestation2 = await navigator.credentials.create(SoftCredentials.createRequest(Math.random() < 0.5 ? -7 : -8, true));
      // @ts-expect-error mockup
      return VaultysId.fido2FromAttestation(attestation2);
    default:
      return VaultysId.generatePerson();
  }
};

export const createRandomVaultysId = async (): Promise<VaultysId> => {
  const types = [0, 1, 2];
  if (typeof window === "undefined") {
    types.push(3);
    types.push(4);
  }

  const rand = Math.random();
  const alg = rand < 0.34 ? "dilithium" : rand < 0.67 ? "ed25519" : "dilithium_ed25519";

  const type = types[Math.floor(Math.random() * types.length)];

  switch (type) {
    case 0:
      return VaultysId.generateMachine(alg);
    case 1:
      return VaultysId.generatePerson(alg);
    case 2:
      return VaultysId.generateOrganization(alg);
    case 3:
      const attestation1 = await navigator.credentials.create(SoftCredentials.createRequest(alg === "dilithium" ? PQ_COSE_ALG.DILITHIUM2 : Math.random() < 0.5 ? -8 : -7, false));
      // @ts-expect-error mockup
      return VaultysId.fido2FromAttestation(attestation1);
    case 4:
      const attestation2 = await navigator.credentials.create(SoftCredentials.createRequest(alg === "dilithium" ? PQ_COSE_ALG.DILITHIUM2 : Math.random() < 0.5 ? -8 : -7, true));
      // @ts-expect-error mockup
      return VaultysId.fido2FromAttestation(attestation2);
    default:
      return VaultysId.generatePerson();
  }
};

export const allVaultysIdType = async (): Promise<VaultysId[]> => {
  const result: VaultysId[] = [await VaultysId.generateMachine(), await VaultysId.generateMachine("dilithium"), await VaultysId.generateMachine("dilithium_ed25519"), await VaultysId.generatePerson(), await VaultysId.generatePerson("dilithium"), await VaultysId.generatePerson("dilithium_ed25519")];

  if (typeof window === "undefined") {
    let attestation = await navigator.credentials.create(SoftCredentials.createRequest(PQ_COSE_ALG.DILITHIUM2));
    // @ts-expect-error mockup
    result.push(await VaultysId.fido2FromAttestation(attestation));
    attestation = await navigator.credentials.create(SoftCredentials.createRequest(-7));
    // @ts-expect-error mockup
    result.push(await VaultysId.fido2FromAttestation(attestation));
    attestation = await navigator.credentials.create(SoftCredentials.createRequest(-8));
    // @ts-expect-error mockup
    result.push(await VaultysId.fido2FromAttestation(attestation));
  }

  return result;
};
