import * as crypto from "crypto";
import { encryptInfo, VaultysBackup } from "./abstract";
import { Buffer } from "buffer/";
import { randomBytes } from "../crypto";

// Node-compatible version of key material import
export function getKeyMaterial(mnemonic: string): Promise<crypto.KeyObject> {
  const key = Buffer.from(mnemonic, "utf-8");
  return Promise.resolve(crypto.createSecretKey(key));
}

// Node-compatible version of key derivation
export function getKey(keyMaterial: crypto.KeyObject, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve) => {
    const derivedKey = crypto.pbkdf2Sync(keyMaterial.export(), salt, encryptInfo.ITERATIONS, encryptInfo.DERIVED_KEY_LENGTH / 8, encryptInfo.HASH.replace("-", "").toLowerCase());
    resolve(Buffer.from(derivedKey));
  });
}

/**
 * Node-compatible decrypt function
 */
export async function decrypt(backup: VaultysBackup, passphrase: string): Promise<Buffer | null> {
  if (!backup.encryptInfo) return backup.data;
  try {
    const keyMaterial = await getKeyMaterial(passphrase);
    const salt = Buffer.from(backup.encryptInfo.salt, "base64");
    const iv = Buffer.from(backup.encryptInfo.iv, "base64");
    const key = await getKey(keyMaterial, salt);

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);

    // In AES-GCM the tag is the last 16 bytes of the data
    const tagLength = 16;
    const ciphertext = backup.data.subarray(0, backup.data.length - tagLength);
    const tag = backup.data.subarray(backup.data.length - tagLength);

    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    return decrypted;
  } catch (error) {
    console.error("Decryption error:", error);
    return null;
  }
}

/**
 * Node-compatible encrypt function
 */
export async function encrypt(mnemonic: string, plaintext: Buffer): Promise<VaultysBackup | undefined> {
  if (!mnemonic) return;

  const salt = randomBytes(16);
  const iv = randomBytes(12);

  const keyMaterial = await getKeyMaterial(mnemonic);
  const key = await getKey(keyMaterial, salt);

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  // Get the auth tag and append it to the ciphertext
  const tag = cipher.getAuthTag();
  const fullEncrypted = Buffer.concat([encrypted, tag]);

  const backup: VaultysBackup = {
    version: 1,
    encryptInfo: {
      ...encryptInfo,
      iv: iv.toString("base64"),
      salt: salt.toString("base64"),
    },
    data: fullEncrypted,
  };

  return backup;
}
