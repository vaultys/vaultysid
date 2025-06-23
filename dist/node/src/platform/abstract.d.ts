import { Buffer } from "buffer/";
import { WebAuthnProvider } from "./webauthn";
export declare const encryptInfo: {
    ALG: string;
    ITERATIONS: number;
    DERIVED_KEY_TYPE: string;
    DERIVED_KEY_LENGTH: number;
    HASH: string;
};
export type VaultysBackup = {
    version?: 1;
    encryptInfo?: typeof encryptInfo & {
        iv: string;
        salt: string;
    };
    data: Buffer;
};
export interface IPlatformCrypto {
    webauthn: WebAuthnProvider;
    pbkdf2: {
        encrypt: (mnemonic: string, plaintext: Buffer) => Promise<VaultysBackup | undefined>;
        decrypt: (backup: VaultysBackup, passphrase: string) => Promise<Buffer | null>;
    };
}
