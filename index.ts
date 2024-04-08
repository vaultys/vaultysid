import Challenger from "./src/Challenger.js";
import IdManager from "./src/IdManager.js";
import KeyManager from "./src/KeyManager.js";
import VaultysId from "./src/VaultysId.js";
import { MemoryChannel } from "./src/MemoryChannel.js";
import { MemoryStorage } from "./src/MemoryStorage.js";
import GameOfLifeIcon from "./src/GameOfLifeIcon.js";
import CryptoChannel from "./src/cryptoChannel.js";

//utils
import * as crypto from "./src/crypto.js";

export {
  crypto, 
  VaultysId,
  Challenger,
  MemoryChannel,
  MemoryStorage,
  IdManager,
  KeyManager,
  GameOfLifeIcon,
  CryptoChannel
}

export type ChallengeType = {
  protocol: string
  service: string
  timestamp: number
  pk1?: Buffer
  pk2?: Buffer
  nonce?: Buffer
  sign1?: Buffer
  sign2?: Buffer
  metadata?: Buffer
  state:number
  error: string
}


export interface FilePayload { 
  challenge: Buffer;
  signature?: Buffer;
  name?: string;
  hash?: string | null;
  timestamp?: number | null,
}

export type IdMetadata = {
  name?: string
  firstname?: string
  email?: string
  phone?: string
}