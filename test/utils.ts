import { VaultysId } from "../";
import SoftCredentials from "../src/platform/SoftCredentials";

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

  const type = types[Math.floor(Math.random() * types.length)];

  switch (type) {
    case 0:
      return VaultysId.generateMachine();
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
