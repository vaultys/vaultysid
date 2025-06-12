import { Buffer } from "buffer/";
export type KeyPair = {
    publicKey: Buffer;
    secretKey?: Buffer;
};
export type HISCP = {
    newId: Buffer;
    proofKey: Buffer;
    timestamp: number;
    signature: Buffer;
};
/**
 * DHIES (Diffie-Hellman Integrated Encryption Scheme) for KeyManager
 * Provides authenticated encryption using Diffie-Hellman key exchange
 */
export declare class DHIES {
    private keyManager;
    constructor(keyManager: KeyManager);
    /**
     * Encrypts a message for a recipient using DHIES
     *
     * @param message The plaintext message to encrypt
     * @param recipientPublicKey The recipient's public key
     * @returns Encrypted message with ephemeral public key and authentication tag, or null if encryption fails
     */
    encrypt(message: string | Buffer, recipientPublicKey: Buffer): Promise<Buffer | null>;
    /**
     * Decrypts a message encrypted with DHIES
     *
     * @param encryptedMessage The complete encrypted message from the encrypt method
     * @returns Decrypted message as a Buffer, or null if decryption fails
     */
    decrypt(encryptedMessage: Buffer, senderPublicKey: Buffer): Promise<Buffer | null>;
    /**
     * Key Derivation Function: Derives encryption and MAC keys from the shared secret
     */
    private kdf;
    /**
     * Computes MAC for authenticated encryption
     */
    private computeMAC;
    /**
     * Constant-time comparison of two buffers to prevent timing attacks
     */
    private constantTimeEqual;
}
export default class KeyManager {
    level: number;
    version: 0 | 1;
    capability: "private" | "public";
    entropy: Buffer | undefined;
    proof: Buffer;
    proofKey: KeyPair;
    signer: KeyPair;
    cypher: KeyPair;
    authType: string;
    encType: string;
    swapIndex: number;
    constructor();
    static create_Id25519_fromEntropy(entropy: Buffer, swapIndex?: number): Promise<KeyManager>;
    static generate_Id25519(): Promise<KeyManager>;
    get id(): Buffer;
    getCypher(): Promise<{
        hmac: (message: string) => Buffer | undefined;
        signcrypt: (plaintext: string, publicKeys: Buffer[]) => Promise<string>;
        decrypt: (encryptedMessage: string, senderKey?: Buffer | null) => Promise<import("@vaultys/saltpack").DearmorAndDecryptResult>;
        diffieHellman: (publicKey: Buffer) => Promise<Buffer>;
    }>;
    getSigner(): Promise<{
        sign: (data: Buffer) => Promise<Buffer | null>;
    }>;
    getSecret(): Buffer;
    static fromSecret(secret: Buffer): KeyManager;
    static instantiate(obj: any): KeyManager;
    static fromId(id: Buffer): KeyManager;
    sign(data: Buffer): Promise<Buffer | null>;
    verify(data: Buffer, signature: Buffer, userVerificationIgnored?: boolean): boolean;
    cleanSecureData(): void;
    /**
     * Performs a Diffie-Hellman key exchange with another KeyManager instance
     * @param otherKeyManager The other party's KeyManager instance
     * @returns A shared secret that can be used for symmetric encryption
     */
    performDiffieHellman(otherKeyManager: KeyManager): Promise<Buffer | null>;
    /**
     * Static method to perform a Diffie-Hellman key exchange between two KeyManager instances
     * @param keyManager1 First KeyManager instance
     * @param keyManager2 Second KeyManager instance
     * @returns A shared secret that both parties can derive
     */
    static diffieHellman(keyManager1: KeyManager, keyManager2: KeyManager): Promise<Buffer | null>;
    /**
     * Encrypt a message using DHIES for a recipient
     * @param message Message to encrypt
     * @param recipientId Recipient's KeyManager ID
     * @returns Encrypted message or null if encryption fails
     */
    dhiesEncrypt(message: string | Buffer, recipientId: Buffer): Promise<Buffer | null>;
    /**
     * Decrypt a message encrypted with DHIES
     * @param encryptedMessage Encrypted message from dhiesEncrypt
     * @returns Decrypted message or null if decryption fails
     */
    dhiesDecrypt(encryptedMessage: Buffer, senderId: Buffer): Promise<Buffer | null>;
    static encrypt(plaintext: string, recipientIds: Buffer[]): Promise<string>;
    signcrypt(plaintext: string, recipientIds: Buffer[]): Promise<string>;
    decrypt(encryptedMessage: string, senderId?: Buffer | null): Promise<string>;
    getSecretHash(data: Buffer): Buffer;
}
