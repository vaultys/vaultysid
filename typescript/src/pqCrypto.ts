/**
 * Post-Quantum Cryptography Operations
 *
 * This file contains implementations for post-quantum cryptographic algorithms
 * starting with DILITHIUM for digital signatures.
 */

import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { Buffer } from "buffer/";
import { hash, randomBytes, secureErase } from "./crypto";

/**
 * COSE algorithm identifiers for post-quantum algorithms
 * Note: These values are provisional and may need to be updated as standards evolve
 */
export const PQ_COSE_ALG = {
  // DILITHIUM variants (using negative values as per COSE convention for new algorithms)
  DILITHIUM2: -46, // Level 2 (128-bit security)
  DILITHIUM3: -47, // Level 3 (192-bit security)
  DILITHIUM5: -48, // Level 5 (256-bit security)
};

/**
 * COSE key type for DILITHIUM
 */
export const PQ_COSE_KEY_TYPE = {
  DILITHIUM: 4, // Custom key type for DILITHIUM
};

/**
 * COSE key parameter identifiers for DILITHIUM
 */
export const PQ_COSE_KEY_PARAMS = {
  DILITHIUM_MODE: -100, // Mode parameter (2, 3, or 5)
  DILITHIUM_PK: -101, // Public key
  DILITHIUM_SK: -102, // Secret key
};

/**
 * Generate a DILITHIUM Level 2 key pair
 * @returns Promise resolving to an object containing the key pair
 */
export function generateDilithiumKeyPair(seed?: Buffer): {
  publicKey: Buffer;
  secretKey: Buffer;
} {
  if (!seed) seed = randomBytes(32);
  const keyPair = ml_dsa87.keygen(seed);
  return {
    publicKey: Buffer.from(keyPair.publicKey),
    secretKey: Buffer.from(keyPair.secretKey),
  };
}

/**
 * Sign a message using DILITHIUM Level 2
 * @param message - The message to sign
 * @param privateKey - The DILITHIUM private key
 * @returns Promise resolving to signature as Uint8Array
 */
export function signDilithium(message: Uint8Array | Buffer, secretKey: Uint8Array | Buffer): Buffer {
  return Buffer.from(ml_dsa87.sign(message, secretKey));
}

/**
 * Verify a DILITHIUM Level 2 signature
 * @param message - The original message
 * @param signature - The signature to verify
 * @param publicKey - The DILITHIUM public key
 * @returns Promise resolving to boolean indicating if signature is valid
 */
export function verifyDilithium(message: Uint8Array | Buffer, signature: Uint8Array | Buffer, publicKey: Uint8Array | Buffer): boolean {
  return ml_dsa87.verify(signature, message, publicKey);
}

/**
 * Create a COSE key representation for a DILITHIUM public key
 * @param publicKey - The DILITHIUM public key
 * @returns Map representing the COSE key
 */
export function createDilithiumCoseKey(publicKey: Uint8Array | Buffer): Map<number, any> {
  const coseKey = new Map();

  // Standard COSE key parameters
  coseKey.set(1, PQ_COSE_KEY_TYPE.DILITHIUM); // kty: Key Type
  coseKey.set(3, PQ_COSE_ALG.DILITHIUM5); // alg: Algorithm

  // DILITHIUM-specific parameters
  coseKey.set(PQ_COSE_KEY_PARAMS.DILITHIUM_MODE, 5); // Level 2
  coseKey.set(PQ_COSE_KEY_PARAMS.DILITHIUM_PK, publicKey);

  return coseKey;
}

/**
 * Get key size information for DILITHIUM
 * @returns Object with key size information
 */
export function getDilithiumKeyInfo(): {
  publicKeySize: number;
  secretKeySize: number;
  signatureSize: number;
} {
  return {
    publicKeySize: 2592, // Size in bytes for DILITHIUM2 public key
    secretKeySize: 4896, // Size in bytes for DILITHIUM5 private key
    signatureSize: 4627, // Size in bytes for DILITHIUM2 signature
  };
}

// ML-KEM-768 (FIPS 203), used by post-quantum identities (rfc/PQ-ENCRYPTION.md).
export const MLKEM768_PK_LENGTH = 1184;
export const MLKEM768_CT_LENGTH = 1088;

const MLKEM_KEYGEN_LABEL = Buffer.from("VAULTYS_MLKEM768_KEYGEN", "ascii");
const PRF_KEY_LABEL = Buffer.from("VAULTYS_PRF_KEY", "ascii");

/**
 * Derive the ML-KEM-768 key pair of a post-quantum identity from its full
 * 64-byte key-manager seed: dz = SHA-512(label || seed), KeyGen_internal(d, z).
 */
export function deriveMlKemKeyPair(seed: Uint8Array): { publicKey: Buffer; secretKey: Buffer } {
  const dz = hash("sha512", Buffer.concat([MLKEM_KEYGEN_LABEL, Buffer.from(seed)]));
  try {
    const keyPair = ml_kem768.keygen(dz);
    return { publicKey: Buffer.from(keyPair.publicKey), secretKey: Buffer.from(keyPair.secretKey) };
  } finally {
    secureErase(dz);
  }
}

/** PRF/HMAC key of a post-quantum identity: SHA-512(label || seed)[0:32]. */
export function derivePrfKey(seed: Uint8Array): Buffer {
  const digest = hash("sha512", Buffer.concat([PRF_KEY_LABEL, Buffer.from(seed)]));
  const key = Buffer.from(digest.subarray(0, 32));
  secureErase(digest);
  return key;
}

/** `m` pins the 32-byte encapsulation randomness, for test vectors only. */
export function mlKemEncapsulate(publicKey: Uint8Array, m?: Uint8Array): { cipherText: Buffer; sharedSecret: Buffer } {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey, m);
  return { cipherText: Buffer.from(cipherText), sharedSecret: Buffer.from(sharedSecret) };
}

export function mlKemDecapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Buffer {
  return Buffer.from(ml_kem768.decapsulate(cipherText, secretKey));
}
