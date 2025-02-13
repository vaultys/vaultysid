"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MemoryChannel = void 0;
exports.StreamChannel = StreamChannel;
exports.convertWebWritableStreamToNodeWritable = convertWebWritableStreamToNodeWritable;
exports.convertWebReadableStreamToNodeReadable = convertWebReadableStreamToNodeReadable;
const cryptoChannel_1 = __importDefault(require("./cryptoChannel"));
const stream_1 = require("stream");
const buffer_1 = require("buffer/");
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function StreamChannel(channel) {
    const onData = async (callback) => {
        let message = await channel.receive();
        while (message) {
            callback(message);
            if (message.toString("utf-8") === "EOF") {
                return;
            }
            message = await channel.receive();
        }
    };
    const getWriteStream = () => {
        const stream = new stream_1.Stream.Writable({
            write: (chunk, encoding, done) => {
                channel.send(chunk);
                done();
            },
        });
        return stream;
    };
    const upload = async (stream) => {
        return new Promise((resolve) => {
            const writeStream = getWriteStream();
            stream.pipe(writeStream).once("finish", () => {
                channel.send(buffer_1.Buffer.from("EOF", "utf-8"));
                writeStream.end();
                resolve();
            });
        });
    };
    const uploadData = async (data) => {
        const stream = stream_1.Readable.from(data);
        await upload(stream);
    };
    const download = async (stream) => {
        const readStream = getReadStream();
        const result = new Promise((resolve) => readStream.on("end", () => {
            resolve();
        }));
        readStream.pipe(stream);
        await result;
    };
    const downloadData = async () => {
        const readStream = getReadStream();
        const chunks = [];
        const result = new Promise((resolve) => readStream.on("end", () => {
            resolve(buffer_1.Buffer.concat(chunks));
        }));
        const stream = new stream_1.Stream.Writable({
            write: (chunk, encoding, done) => {
                chunks.push(chunk);
                done();
            },
        });
        readStream.pipe(stream);
        return result;
    };
    const getReadStream = () => {
        let push;
        let temp;
        const stream = new stream_1.Stream.Readable({
            read() {
                push = (data) => this.push(data);
            },
        });
        onData((buf) => {
            if (buf.length === 3 && buf.toString("utf-8") === "EOF" && push) {
                temp && push(temp);
                push(null);
                stream.destroy();
            }
            temp = temp ? buffer_1.Buffer.concat([temp, buf]) : buf;
            if (push) {
                !push(temp) && (push = null);
                temp = null;
            }
        });
        return stream;
    };
    return {
        getReadStream,
        getWriteStream,
        upload,
        uploadData,
        download,
        downloadData,
    };
}
function convertWebWritableStreamToNodeWritable(webWritableStream) {
    const writer = webWritableStream.getWriter();
    return new stream_1.Writable({
        async write(chunk, encoding, callback) {
            try {
                // Get a writer from the Web WritableStream
                await writer.write(chunk);
                writer.releaseLock(); // Release the lock on the writer after writing
                callback(); // Signal that the chunk has been processed
            }
            catch (error) {
                callback(); // Signal an error if it occurred
            }
        },
        async final(callback) {
            try {
                // Close the Web WritableStream
                const writer = webWritableStream.getWriter();
                await writer.close();
                writer.releaseLock(); // Release the lock on the writer after closing
                callback(); // Signal that the stream is finished
            }
            catch (error) {
                callback(); // Signal an error if it occurred during close
            }
        },
        async destroy(error, callback) {
            try {
                // Abort the Web WritableStream in case of an error
                const writer = webWritableStream.getWriter();
                await writer.abort(error);
                writer.releaseLock(); // Release the lock on the writer after aborting
                callback(error); // Signal that the stream is destroyed
            }
            catch (abortError) {
                callback(null); // Signal an error if it occurred during abort
            }
        },
    });
}
function convertWebReadableStreamToNodeReadable(webReadableStream) {
    const reader = webReadableStream.getReader();
    return new stream_1.Readable({
        async read() {
            try {
                while (true) {
                    const { done, value } = await reader.read();
                    //console.log(value);
                    if (done) {
                        this.push(null); // Signal the end of the stream
                        break;
                    }
                    this.push(buffer_1.Buffer.from(value)); // Need to convert Uint8Array to Buffer
                }
            }
            catch (error) {
                this.destroy();
            }
        },
    });
}
class MemoryChannel {
    constructor() {
        this.lock = false;
    }
    setChannel(chan, name) {
        this.name = name;
        this.otherend = chan;
    }
    static createBidirectionnal() {
        const input = new MemoryChannel();
        const output = new MemoryChannel();
        input.setChannel(output);
        output.setChannel(input);
        return input;
    }
    static createEncryptedBidirectionnal(key = cryptoChannel_1.default.generateKey()) {
        const input = cryptoChannel_1.default.encryptChannel(new MemoryChannel(), key);
        const output = cryptoChannel_1.default.encryptChannel(new MemoryChannel(), key);
        input.setChannel(output);
        output.setChannel(input);
        return input;
    }
    getConnectionString() {
        return "vaultys://memory";
    }
    fromConnectionString(string) {
        return string === "vaultys://memory" ? new MemoryChannel() : null;
    }
    setLogger(logger) {
        this.logger = logger;
    }
    setInjector(injector) {
        this.injector = injector;
    }
    async start() {
        // noop
    }
    async send(data) {
        // the other end might not listen yet
        while (this.lock || !this.otherend?.receiver) {
            // console.log(this.lock);
            await delay(10);
        }
        this.lock = true;
        const receiver = this.otherend.receiver;
        delete this.otherend.receiver;
        if (this.logger)
            this.logger(data);
        if (this.injector) {
            const injected = await this.injector(data);
            receiver(injected);
        }
        else
            receiver(data);
        this.lock = false;
    }
    async receive() {
        while (this.receiver) {
            console.log(this.lock);
            await delay(10);
        }
        return new Promise((resolve) => (this.receiver = resolve));
    }
    async close() { }
}
exports.MemoryChannel = MemoryChannel;
