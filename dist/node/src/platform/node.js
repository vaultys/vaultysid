"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NodeCrypto = void 0;
class NodeCrypto {
    async getRandomValues(buffer) {
        const crypto = require("crypto");
        return crypto.randomFillSync(buffer);
    }
}
exports.NodeCrypto = NodeCrypto;
