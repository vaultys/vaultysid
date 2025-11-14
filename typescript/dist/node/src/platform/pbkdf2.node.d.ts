import * as crypto from "crypto";
import { VaultysBackup } from "./abstract";
import { Buffer } from "buffer/";
export declare function getKeyMaterial(mnemonic: string): Promise<crypto.KeyObject>;
export declare function getKey(keyMaterial: crypto.KeyObject, salt: Buffer): Promise<Buffer>;
/**
 * Node-compatible decrypt function
 */
export declare function decrypt(backup: VaultysBackup, passphrase: string): Promise<Buffer | null>;
/**
 * Node-compatible encrypt function
 */
export declare function encrypt(mnemonic: string, plaintext: Buffer): Promise<VaultysBackup | undefined>;
