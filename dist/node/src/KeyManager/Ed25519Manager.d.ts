import { Buffer } from "buffer/";
import { KeyPair } from "./";
import CypherManager from "./CypherManager";
export default class Ed25519Manager extends CypherManager {
    version: 0 | 1;
    capability: "private" | "public";
    entropy: Buffer | undefined;
    signer: KeyPair;
    constructor();
    static createFromEntropy(entropy: Buffer): Promise<Ed25519Manager>;
    static generate(): Promise<Ed25519Manager>;
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
    static fromSecret(secret: Buffer): Ed25519Manager;
    static instantiate(obj: any): Ed25519Manager;
    static fromId(id: Buffer): Ed25519Manager;
    verify(data: Buffer, signature: Buffer, userVerificationIgnored?: boolean): boolean;
    cleanSecureData(): void;
}
