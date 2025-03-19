import { Readable, Stream, Writable } from "stream";
import { Buffer } from "buffer/";
export type Channel = {
    start(): Promise<void>;
    close(): Promise<void>;
    send(data: Buffer): Promise<void>;
    receive(): Promise<Buffer>;
    onConnected(callback: () => void): void;
    getConnectionString(): string;
    fromConnectionString(conn: string, options?: any): Channel | null;
};
export declare function StreamChannel(channel: Channel): {
    getReadStream: () => Readable;
    getWriteStream: () => Stream.Writable;
    upload: (stream: Readable) => Promise<void>;
    uploadData: (data: Buffer) => Promise<void>;
    download: (stream: Writable) => Promise<void>;
    downloadData: () => Promise<Buffer>;
};
export declare function convertWebWritableStreamToNodeWritable(webWritableStream: WritableStream): Stream.Writable;
export declare function convertWebReadableStreamToNodeReadable(webReadableStream: ReadableStream): Readable;
export declare class MemoryChannel implements Channel {
    name?: string;
    lock: boolean;
    otherend?: MemoryChannel;
    receiver?: (data: Buffer) => void;
    logger?: (data: Buffer) => void;
    injector?: (data: Buffer) => Promise<Buffer> | Buffer;
    _onConnected?: () => void;
    setChannel(chan: MemoryChannel, name?: string): void;
    static createBidirectionnal(): MemoryChannel;
    onConnected(callback: () => void): void;
    static createEncryptedBidirectionnal(key?: Buffer): MemoryChannel;
    getConnectionString(): string;
    fromConnectionString(string: string): MemoryChannel | null;
    setLogger(logger: (data: Buffer) => void): void;
    setInjector(injector: (data: Buffer) => Buffer): void;
    start(): Promise<void>;
    send(data: Buffer): Promise<void>;
    receive(): Promise<Buffer>;
    close(): Promise<void>;
}
