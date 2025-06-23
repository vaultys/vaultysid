import { VaultysBackup } from "./abstract";
import { Buffer } from "buffer/";
export declare const pinEncryptInfo: {
    ALG: string;
    ITERATIONS: number;
    DERIVED_KEY_TYPE: string;
    DERIVED_KEY_LENGTH: number;
    HASH: string;
    SALT_LENGTH: number;
    IV_LENGTH: number;
};
/**
 * Imports key material from a string
 */
export declare function getKeyMaterial(mnemonic: string): Promise<CryptoKey>;
/**
 * Derives a key from key material and salt
 */
export declare function getKey(keyMaterial: CryptoKey, salt: BufferSource): Promise<CryptoKey>;
/**
 * Decrypts data using a passphrase
 */
export declare function decrypt(backup: VaultysBackup, passphrase: string): Promise<Buffer | null>;
/**
 * Encrypts data using a passphrase
 */
export declare function encrypt(mnemonic: string, plaintext: BufferSource): Promise<VaultysBackup | undefined>;
