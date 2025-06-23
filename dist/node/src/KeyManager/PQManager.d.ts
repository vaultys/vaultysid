import { Buffer } from "buffer/";
import CypherManager from "./CypherManager";
export default class PQManager extends CypherManager {
    seed?: Buffer;
    constructor();
    static createFromEntropy(entropy: Buffer, swapIndex?: number): Promise<PQManager>;
    static generate(): Promise<PQManager>;
    getSecret(): Buffer;
    get id(): Buffer;
    static fromSecret(secret: Buffer): PQManager;
    static instantiate(obj: any): PQManager;
    static fromId(id: Buffer): PQManager;
    getSigner(): Promise<{
        sign: (data: Buffer) => Promise<Buffer | null>;
    }>;
    verify(data: Buffer, signature: Buffer, userVerificationIgnored?: boolean): boolean;
}
