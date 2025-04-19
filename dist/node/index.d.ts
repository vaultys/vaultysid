import Challenger from "./src/Challenger";
import IdManager, { File, FileSignature, StoredApp, StoredContact } from "./src/IdManager";
import KeyManager from "./src/KeyManager";
import VaultysId from "./src/VaultysId";
import { Channel, MemoryChannel, StreamChannel, convertWebReadableStreamToNodeReadable, convertWebWritableStreamToNodeWritable } from "./src/MemoryChannel";
import { MemoryStorage, Store, LocalStorage } from "./src/MemoryStorage";
import GameOfLifeIcon from "./src/GameOfLifeIcon";
import CryptoChannel from "./src/cryptoChannel";
import * as crypto from "./src/crypto";
declare const Buffer: typeof crypto.Buffer;
export { crypto, Buffer, VaultysId, Challenger, MemoryChannel, MemoryStorage, StreamChannel, convertWebReadableStreamToNodeReadable, convertWebWritableStreamToNodeWritable, LocalStorage, IdManager, KeyManager, GameOfLifeIcon, CryptoChannel };
export type { Channel, Store, File, StoredApp, StoredContact, FileSignature };
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
