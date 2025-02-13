"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BrowserCrypto = void 0;
class BrowserCrypto {
    async getRandomValues(buffer) {
        return crypto.getRandomValues(buffer);
    }
}
exports.BrowserCrypto = BrowserCrypto;
