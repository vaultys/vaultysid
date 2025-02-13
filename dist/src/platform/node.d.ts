import { IPlatformCrypto } from "./abstract";
export declare class NodeCrypto implements IPlatformCrypto {
    getRandomValues(buffer: Uint8Array): Promise<Uint8Array>;
}
