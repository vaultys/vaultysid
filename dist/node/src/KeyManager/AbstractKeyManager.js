"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class KeyManager {
    constructor() {
        // Abstract class - properties will be initialized by concrete implementations
    }
    static createFromEntropy(entropy, swapIndex) {
        throw new Error("Method must be implemented by concrete class");
    }
    static generate() {
        throw new Error("Method must be implemented by concrete class");
    }
    static fromSecret(secret) {
        throw new Error("Method must be implemented by concrete class");
    }
    static instantiate(obj) {
        throw new Error("Method must be implemented by concrete class");
    }
    static fromId(id) {
        throw new Error("Method must be implemented by concrete class");
    }
    async sign(data) {
        if (this.capability == "public")
            return null;
        return (await this.getSigner()).sign(data);
    }
    /**
     * Static method to perform a Diffie-Hellman key exchange between two KeyManager instances
     * @param keyManager1 First KeyManager instance
     * @param keyManager2 Second KeyManager instance
     * @returns A shared secret that both parties can derive
     */
    static async diffieHellman(keyManager1, keyManager2) {
        return await keyManager1.performDiffieHellman(keyManager2);
    }
    static encrypt(plaintext, recipientIds) {
        throw new Error("Method must be implemented by concrete class");
    }
}
exports.default = KeyManager;
