"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MemoryChannel = void 0;
exports.pipeChannels = pipeChannels;
exports.unpipeChannels = unpipeChannels;
exports.StreamChannel = StreamChannel;
exports.convertWebWritableStreamToNodeWritable = convertWebWritableStreamToNodeWritable;
exports.convertWebReadableStreamToNodeReadable = convertWebReadableStreamToNodeReadable;
const cryptoChannel_1 = __importDefault(require("./cryptoChannel"));
const stream_1 = require("stream");
const buffer_1 = require("buffer/");
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
/**
 * Pipes two channels together, creating a bidirectional flow where
 * messages sent to one channel are automatically forwarded to the other.
 * @param channel1 The first channel to connect
 * @param channel2 The second channel to connect
 * @returns A Promise that resolves when both channels close
 */
function pipeChannels(channel1, channel2) {
    let running = true;
    // Start both piping directions
    const pipe1to2 = async () => {
        try {
            await channel1.start();
            await channel2.start();
            console.log("pipe1to2");
            while (running) {
                try {
                    const data = await channel1.receive();
                    console.log("pipe1to2", data);
                    if (!running || data.length === 0)
                        break;
                    channel2.send(data);
                }
                catch (error) {
                    if (running)
                        console.error("Error in pipe1to2:", error);
                    break;
                }
            }
        }
        catch (error) {
            console.error("Fatal error in pipe1to2:", error);
        }
    };
    const pipe2to1 = async () => {
        try {
            while (running) {
                console.log("pipe2to1");
                try {
                    const data = await channel2.receive();
                    console.log("pipe2to1", data);
                    if (!running || data.length === 0)
                        break;
                    channel1.send(data);
                }
                catch (error) {
                    if (running)
                        console.error("Error in pipe2to1:", error);
                    break;
                }
            }
        }
        catch (error) {
            console.error("Fatal error in pipe2to1:", error);
        }
    };
    // Start the pipes
    pipe1to2();
    pipe2to1();
    // Return function to stop piping
    return async () => {
        running = false;
        await Promise.all([channel1.close(), channel2.close()]);
    };
}
/**
 * Utility function that stops an active channel pipe
 * @param channel1 The first channel in the pipe
 * @param channel2 The second channel in the pipe
 */
async function unpipeChannels(channel1, channel2) {
    await Promise.all([channel1.close(), channel2.close()]);
}
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
        this.messageQueue = [];
        this.waitingResolvers = [];
        this.connected = false;
        this.connectedCallbacks = [];
        this.closed = false;
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
    onConnected(callback) {
        if (this.connected) {
            callback();
        }
        else {
            this.connectedCallbacks.push(callback);
        }
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
        this.connected = true;
        this.connectedCallbacks.forEach((callback) => callback());
        this.connectedCallbacks = []; // Clear callbacks after calling them
    }
    async send(data) {
        if (this.closed) {
            throw new Error("Cannot send on closed channel");
        }
        if (!this.otherend) {
            throw new Error("No other end connected to this channel");
        }
        // Log the data if a logger is set
        if (this.logger) {
            this.logger(data);
        }
        // Process data through injector if present
        let processedData = data;
        if (this.injector) {
            processedData = await this.injector(data);
        }
        // // Signal that this end is connected
        if (!this.connected) {
            await this.start();
        }
        // Deliver the message to the other end
        this.otherend.deliverMessage(processedData);
    }
    deliverMessage(data) {
        // If there are waiting receivers, deliver directly to the first one
        if (this.waitingResolvers.length > 0) {
            const resolver = this.waitingResolvers.shift();
            resolver(data);
        }
        else {
            // Otherwise queue the message
            this.messageQueue.push(data);
        }
    }
    async receive() {
        if (this.closed) {
            throw new Error("Cannot receive on closed channel");
        }
        //console.log(this);
        // If there are queued messages, return the first one
        if (this.messageQueue.length > 0) {
            return this.messageQueue.shift();
        }
        // Otherwise, wait for a message to arrive
        return new Promise((resolve) => {
            this.waitingResolvers.push(resolve);
        });
    }
    async close() {
        this.closed = true;
        // Clear any waiting receivers with an error
        while (this.waitingResolvers.length > 0) {
            const resolver = this.waitingResolvers.shift();
            // Resolve with empty buffer to indicate channel closed
            resolver(buffer_1.Buffer.alloc(0));
        }
        // Clear the message queue
        this.messageQueue = [];
    }
}
exports.MemoryChannel = MemoryChannel;
