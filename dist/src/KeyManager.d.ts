/// <reference types="node" />
import { Buffer } from "buffer";
declare const bip32: any;
export declare const publicDerivePath: (node: InstanceType<typeof bip32.Bip32PublicKey>, path: string) => any;
export declare const privateDerivePath: (node: InstanceType<typeof bip32.Bip32PrivateKey>, path: string) => any;
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
        decrypt: (encryptedMessage: string, senderKey?: Buffer | null) => Promise<import("@samuelthomas2774/saltpack").DearmorAndDecryptResult>;
    }>;
    getSigner(): Promise<any>;
    getSecret(): Buffer;
    static fromSecret(secret: Buffer): KeyManager;
    static instantiate(obj: any): KeyManager;
    static fromId(id: Buffer): KeyManager;
    sign(data: Buffer): Promise<any>;
    verify(data: Buffer, signature: Buffer, userVerificationIgnored?: boolean): boolean;
    createSwapingCertificate(): Promise<HISCP | null>;
    verifySwapingCertificate(hiscp: HISCP): Promise<any>;
    cleanSecureData(): void;
    static encrypt(plaintext: string, recipientIds: Buffer[]): Promise<string>;
    signcrypt(plaintext: string, recipientIds: Buffer[]): Promise<string>;
    decrypt(encryptedMessage: string, senderId?: Buffer | null): Promise<string>;
    getSecretHash(data: Buffer): Buffer;
}
export {};
