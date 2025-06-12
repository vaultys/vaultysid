import { Buffer } from "buffer/";
import KeyManager from "./KeyManager";
export type KeyPair = {
    publicKey: Buffer;
    secretKey?: Buffer;
};
export default class PQManager extends KeyManager {
    seed?: Buffer;
    constructor();
    static create_PQ_fromEntropy(entropy: Buffer, swapIndex?: number): Promise<PQManager>;
    static generate_PQ(): Promise<PQManager>;
    getSecret(): Buffer;
    static fromSecret(secret: Buffer): PQManager;
    static instantiate(obj: any): PQManager;
    static fromId(id: Buffer): PQManager;
    sign(data: Buffer): Promise<Buffer | null>;
    verify(data: Buffer, signature: Buffer, userVerificationIgnored?: boolean): boolean;
}
