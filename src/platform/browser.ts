import { IPlatformCrypto } from "./abstract";

export class BrowserCrypto implements IPlatformCrypto {
  async getRandomValues(buffer: Uint8Array): Promise<Uint8Array> {
    return crypto.getRandomValues(buffer);
  }
}
