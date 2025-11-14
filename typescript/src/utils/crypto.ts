import { isNode } from "./environment";
import { Buffer } from "buffer/";

export class CryptoUtils {
  static async getRandomValues(buffer: Buffer): Promise<Buffer> {
    if (isNode) {
      const crypto = require("crypto");
      return crypto.randomFillSync(buffer);
    } else {
      return Buffer.from(crypto.getRandomValues(buffer));
    }
  }

  // Add other crypto functions that need different implementations
}
