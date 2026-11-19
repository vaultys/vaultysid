import Challenger from "./src/Challenger";
import IdManager, { File, FileSignature, StoredApp, StoredContact } from "./src/IdManager";
import KeyManager from "./src/KeyManager";
import VaultysId from "./src/VaultysId";
import { Channel, MemoryChannel, StreamChannel, convertWebReadableStreamToNodeReadable, convertWebWritableStreamToNodeWritable } from "./src/MemoryChannel";
import { MemoryStorage, Store, LocalStorage } from "./src/MemoryStorage";
import GameOfLifeIcon from "./src/GameOfLifeIcon";
import CryptoChannel from "./src/cryptoChannel";
import { migrateVaultysId, migrateIdManager } from "./src/utils/migration";
import DeprecatedKeyManager from "./src/KeyManager/DeprecatedKeyManager";
import { enableSoftCredentials, isSoftCredentialsEnabled, configureWebAuthn } from "./src/platform/softCredentialsConfig";
import { dhiesV2Encrypt as dhiesV2EncryptWith, dhiesV2Decrypt, dhiesV3Encrypt as dhiesV3EncryptWith, dhiesV3Decrypt, type StaticDiffieHellman } from "./src/KeyManager/dhies";

//utils
import * as crypto from "./src/crypto";
const Buffer = crypto.Buffer;

// The package exports DHIES encryption WITHOUT the `testing` parameter: a fixed ephemeral key, nonce or ML-KEM
// randomness would reuse keys and nonces. Vector generators import src/KeyManager/dhies directly.
const dhiesV2Encrypt = (message: string | Uint8Array, senderDH: StaticDiffieHellman, senderPublicKey: Uint8Array, recipientPublicKey: Uint8Array) => dhiesV2EncryptWith(message, senderDH, senderPublicKey, recipientPublicKey);
const dhiesV3Encrypt = (message: string | Uint8Array, senderDH: StaticDiffieHellman, senderPublicKey: Uint8Array, recipientPublicKey: Uint8Array, recipientKemPublicKey: Uint8Array) => dhiesV3EncryptWith(message, senderDH, senderPublicKey, recipientPublicKey, recipientKemPublicKey);

if (typeof Symbol.dispose === "undefined") {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  Symbol.dispose = Symbol("Symbol.dispose");
}

export { crypto, Buffer, VaultysId, Challenger, MemoryChannel, MemoryStorage, StreamChannel, convertWebReadableStreamToNodeReadable, convertWebWritableStreamToNodeWritable, LocalStorage, IdManager, KeyManager, GameOfLifeIcon, CryptoChannel, DeprecatedKeyManager, migrateVaultysId, migrateIdManager, enableSoftCredentials, isSoftCredentialsEnabled, configureWebAuthn, dhiesV2Encrypt, dhiesV2Decrypt, dhiesV3Encrypt, dhiesV3Decrypt };

export type { Channel, Store, File, StoredApp, StoredContact, FileSignature };
export { createPassportAAReader } from "./src/passport/reader";
export type { PassportAAReader } from "./src/passport/reader";
export type { PassportAAOptions } from "./src/KeyManager/PassportAAManager";
export type { Ed25519Signer } from "./src/Ed25519Signer";

export type ChallengeType = {
  protocol: string;
  service: string;
  timestamp: number;
  pk1?: Buffer;
  pk2?: Buffer;
  nonce?: Buffer;
  sign1?: Buffer;
  sign2?: Buffer;
  metadata?: Buffer;
  state: number;
  error: string;
};

export interface FilePayload {
  challenge: Buffer;
  signature?: Buffer;
  name?: string;
  hash?: string | null;
  timestamp?: number | null;
}

export type IdMetadata = {
  name?: string;
  firstname?: string;
  email?: string;
  phone?: string;
};
