import { Buffer } from "buffer/";
import CypherManager from "./CypherManager";
import { KeyPair } from ".";
export default class HybridManager extends CypherManager {
    seed?: Buffer;
    pqSigner?: KeyPair;
    edSigner?: KeyPair;
    constructor();
    static createFromEntropy(entropy: Buffer): Promise<HybridManager>;
    static generate(): Promise<HybridManager>;
    getSecret(): Buffer;
    get id(): Buffer;
    static fromSecret(secret: Buffer): HybridManager;
    static instantiate(obj: any): HybridManager;
    static fromId(id: Buffer): HybridManager;
    getSigner(): Promise<{
        sign: (data: Buffer) => Promise<Buffer | null>;
    }>;
    verify(data: Buffer, signature: Buffer, userVerificationIgnored?: boolean): boolean;
}
