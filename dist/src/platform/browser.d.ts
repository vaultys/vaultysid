import { IPlatformCrypto } from "./abstract";
export declare class BrowserCrypto implements IPlatformCrypto {
    getRandomValues(buffer: Uint8Array): Promise<Uint8Array>;
}
