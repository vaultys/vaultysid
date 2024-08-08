import Challenger from "./src/Challenger";
import IdManager from "./src/IdManager";
import KeyManager from "./src/KeyManager";
import VaultysId from "./src/VaultysId";
import { Channel, MemoryChannel } from "./src/MemoryChannel";
import { MemoryStorage, Store } from "./src/MemoryStorage";
import GameOfLifeIcon from "./src/GameOfLifeIcon";
import CryptoChannel from "./src/cryptoChannel";

//utils
import * as crypto from "./src/crypto";

export { crypto, VaultysId, Challenger, MemoryChannel, MemoryStorage, IdManager, KeyManager, GameOfLifeIcon, CryptoChannel };

export type { Channel, Store };

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
