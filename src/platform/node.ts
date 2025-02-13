import { IPlatformCrypto } from "./abstract";

export class NodeCrypto implements IPlatformCrypto {
  async getRandomValues(buffer: Uint8Array): Promise<Uint8Array> {
    const crypto = require("crypto");
    return crypto.randomFillSync(buffer);
  }
}
