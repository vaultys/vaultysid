import { Buffer } from "buffer/";
import KeyManager from "./KeyManager";
export type KeyPair = {
    publicKey: Buffer;
    secretKey?: Buffer;
};
export default class PQManager extends KeyManager {
    constructor();
    static create_PQ_fromEntropy(entropy: Buffer, swapIndex?: number): Promise<PQManager>;
    static generate_PQ(): Promise<PQManager>;
    getCypher(): Promise<{
        hmac: (message: string) => Buffer | undefined;
        signcrypt: (plaintext: string, publicKeys: Buffer[]) => Promise<string>;
        decrypt: (encryptedMessage: string, senderKey?: Buffer | null) => Promise<import("@samuelthomas2774/saltpack").DearmorAndDecryptResult>;
        diffieHellman: (publicKey: Buffer) => Promise<Buffer>;
    }>;
    static fromSecret(secret: Buffer): PQManager;
    static instantiate(obj: any): PQManager;
    static fromId(id: Buffer): PQManager;
    sign(data: Buffer): Promise<Buffer | null>;
    verify(data: Buffer, signature: Buffer, userVerificationIgnored?: boolean): boolean;
}
