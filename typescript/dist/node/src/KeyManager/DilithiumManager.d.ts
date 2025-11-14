import { Buffer } from "buffer/";
import CypherManager from "./CypherManager";
export default class DilithiumManager extends CypherManager {
    seed?: Buffer;
    constructor();
    static createFromEntropy(entropy: Buffer): Promise<DilithiumManager>;
    static generate(): Promise<DilithiumManager>;
    getSecret(): Buffer;
    get id(): Buffer;
    static fromSecret(secret: Buffer): DilithiumManager;
    static instantiate(obj: any): DilithiumManager;
    static fromId(id: Buffer): DilithiumManager;
    getSigner(): Promise<{
        sign: (data: Buffer) => Promise<Buffer | null>;
    }>;
    verify(data: Buffer, signature: Buffer, userVerificationIgnored?: boolean): boolean;
}
