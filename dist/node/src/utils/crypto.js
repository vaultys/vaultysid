"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CryptoUtils = void 0;
const environment_1 = require("./environment");
const buffer_1 = require("buffer/");
class CryptoUtils {
    static async getRandomValues(buffer) {
        if (environment_1.isNode) {
            const crypto = require("crypto");
            return crypto.randomFillSync(buffer);
        }
        else {
            return buffer_1.Buffer.from(crypto.getRandomValues(buffer));
        }
    }
}
exports.CryptoUtils = CryptoUtils;
