import { Buffer } from "buffer/";
import { WebAuthnProvider } from "./webauthn";

export const encryptInfo = {
  ALG: "PBKDF2",
  ITERATIONS: 20000000,
  DERIVED_KEY_TYPE: "AES-GCM",
  DERIVED_KEY_LENGTH: 256,
  HASH: "SHA-256",
};

export type VaultysBackup = {
  version?: 1;
  encryptInfo?: typeof encryptInfo & { iv: string; salt: string };
  data: Buffer;
};

export interface IPlatformCrypto {
  webauthn: WebAuthnProvider;
  pbkdf2: {
    encrypt: (mnemonic: string, plaintext: Buffer) => Promise<VaultysBackup | undefined>;
    decrypt: (backup: VaultysBackup, passphrase: string) => Promise<Buffer | null>;
  };
  // Add other platform-specific methods
}
