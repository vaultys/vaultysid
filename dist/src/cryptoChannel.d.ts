/// <reference types="node" />
import { Channel } from "./MemoryChannel";
export declare const encrypt: (buffer: Buffer, key: Buffer) => Buffer;
export declare const decrypt: (messageWithNonce: Buffer, key: Buffer) => Buffer;
declare const _default: {
    decrypt: (messageWithNonce: Buffer, key: Buffer) => Buffer;
    encrypt: (buffer: Buffer, key: Buffer) => Buffer;
    encryptChannel: (channel: Channel, key: Buffer) => Channel;
    generateKey: () => Buffer;
};
export default _default;
