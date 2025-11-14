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
/**
 * Pipes two channels together, creating a bidirectional flow where
 * messages sent to one channel are automatically forwarded to the other.
 * @param channel1 The first channel to connect
 * @param channel2 The second channel to connect
 * @returns A Promise that resolves when both channels close
 */
export declare function pipeChannels(channel1: Channel, channel2: Channel): () => Promise<void>;
/**
 * Utility function that stops an active channel pipe
 * @param channel1 The first channel in the pipe
 * @param channel2 The second channel in the pipe
 */
export declare function unpipeChannels(channel1: Channel, channel2: Channel): Promise<void>;
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
    otherend?: MemoryChannel;
    private messageQueue;
    private waitingResolvers;
    private connected;
    private connectedCallbacks;
    private closed;
    logger?: (data: Buffer) => void;
    injector?: (data: Buffer) => Promise<Buffer> | Buffer;
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
    private deliverMessage;
    receive(): Promise<Buffer>;
    close(): Promise<void>;
}
