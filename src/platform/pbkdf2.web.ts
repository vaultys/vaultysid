import { encryptInfo, VaultysBackup } from "./abstract";
import { Buffer } from "buffer/";
// PIN-specific config with higher iterations for enhanced security
export const pinEncryptInfo = {
  ALG: "PBKDF2",
  ITERATIONS: 100000, // Less iterations for PIN as it's used more frequently
  DERIVED_KEY_TYPE: "AES-GCM",
  DERIVED_KEY_LENGTH: 256,
  HASH: "SHA-256",
  SALT_LENGTH: 16,
  IV_LENGTH: 12,
};

/**
 * Imports key material from a string
 */
export function getKeyMaterial(mnemonic: string) {
  const enc = new TextEncoder();
  return window.crypto.subtle.importKey("raw", enc.encode(mnemonic), encryptInfo.ALG, false, ["deriveBits", "deriveKey"]);
}

/**
 * Derives a key from key material and salt
 */
export function getKey(keyMaterial: CryptoKey, salt: BufferSource) {
  return window.crypto.subtle.deriveKey(
    {
      name: encryptInfo.ALG,
      salt: salt,
      iterations: encryptInfo.ITERATIONS,
      hash: encryptInfo.HASH,
    },
    keyMaterial,
    { name: encryptInfo.DERIVED_KEY_TYPE, length: encryptInfo.DERIVED_KEY_LENGTH },
    true,
    ["encrypt", "decrypt"],
  );
}

/**
 * Decrypts data using a passphrase
 */
export async function decrypt(backup: VaultysBackup, passphrase: string) {
  if (!backup.encryptInfo) return backup.data;
  try {
    const keyMaterial = await getKeyMaterial(passphrase);
    const key = await getKey(keyMaterial, Buffer.from(backup.encryptInfo.salt, "base64"));
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: backup.encryptInfo.DERIVED_KEY_TYPE,
        iv: Buffer.from(backup.encryptInfo.iv, "base64"),
      },
      key,
      backup.data,
    );

    return Buffer.from(decrypted);
  } catch (error) {
    console.error(error);
    return null;
  }
}

/**
 * Encrypts data using a passphrase
 */
export async function encrypt(mnemonic: string, plaintext: BufferSource) {
  if (!mnemonic) return;
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const keyMaterial = await getKeyMaterial(mnemonic);
  const key = await window.crypto.subtle.deriveKey(
    {
      name: encryptInfo.ALG,
      salt,
      iterations: encryptInfo.ITERATIONS,
      hash: encryptInfo.HASH,
    },
    keyMaterial,
    { name: encryptInfo.DERIVED_KEY_TYPE, length: encryptInfo.DERIVED_KEY_LENGTH },
    true,
    ["encrypt", "decrypt"],
  );

  const data = await window.crypto.subtle.encrypt({ name: encryptInfo.DERIVED_KEY_TYPE, iv }, key, plaintext);
  const backup: VaultysBackup = {
    version: 1,
    encryptInfo: { ...encryptInfo, iv: Buffer.from(iv).toString("base64"), salt: Buffer.from(salt).toString("base64") },
    data: Buffer.from(data),
  };

  return backup;
}
