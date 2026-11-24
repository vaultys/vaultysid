import cc from "./cryptoChannel";
import { Readable, Stream, Writable } from "stream";
import { Buffer } from "buffer/";

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

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
export function pipeChannels(channel1: Channel, channel2: Channel): () => Promise<void> {
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
          if (!running || data.length === 0) break;
          channel2.send(data);
        } catch (error) {
          if (running) console.error("Error in pipe1to2:", error);
          break;
        }
      }
    } catch (error) {
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
          if (!running || data.length === 0) break;
          channel1.send(data);
        } catch (error) {
          if (running) console.error("Error in pipe2to1:", error);
          break;
        }
      }
    } catch (error) {
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
export async function unpipeChannels(channel1: Channel, channel2: Channel): Promise<void> {
  await Promise.all([channel1.close(), channel2.close()]);
}

export function StreamChannel(channel: Channel) {
  const onData = async (callback: (data: Buffer) => void) => {
    let message: Buffer = await channel.receive();
    while (message) {
      callback(message);
      if (message.toString("utf-8") === "EOF") {
        return;
      }
      message = await channel.receive();
    }
  };

  const getWriteStream = () => {
    const stream = new Stream.Writable({
      // wait for each send so chunks (and the EOF marker after them) keep their order
      write: (chunk: Buffer, encoding: string, done: (error?: Error | null) => void) => {
        channel.send(chunk).then(() => done(), done);
      },
    });
    return stream;
  };

  const upload = async (stream: Readable) => {
    return new Promise<void>((resolve) => {
      const writeStream = getWriteStream();
      stream.pipe(writeStream).once("finish", async () => {
        await channel.send(Buffer.from("EOF", "utf-8"));
        resolve();
      });
    });
  };

  const uploadData = async (data: Buffer) => {
    // wrap in an array: Readable.from() would iterate a buffer/ shim Buffer byte by byte
    const stream = Readable.from([data], { objectMode: false });
    await upload(stream);
  };

  const download = async (stream: Writable) => {
    const readStream = getReadStream();
    const result = new Promise<void>((resolve) =>
      readStream.on("end", () => {
        resolve();
      }),
    );
    readStream.pipe(stream);
    await result;
  };

  const downloadData = async () => {
    const readStream = getReadStream();
    const chunks: Buffer[] = [];
    const result = new Promise<Buffer>((resolve) =>
      readStream.on("end", () => {
        resolve(Buffer.concat(chunks));
      }),
    );
    const stream = new Stream.Writable({
      write: (chunk: Buffer, encoding: string, done: () => void) => {
        chunks.push(chunk);
        done();
      },
    });

    readStream.pipe(stream);
    return result;
  };

  const getReadStream = () => {
    const pending: Buffer[] = [];
    let flowing = false;
    let eof = false;
    let ended = false;
    const flush = () => {
      while (flowing && pending.length > 0) {
        flowing = stream.push(pending.shift()!);
      }
      if (eof && pending.length === 0 && !ended) {
        ended = true;
        stream.push(null);
      }
    };
    const stream = new Stream.Readable({
      read() {
        flowing = true;
        flush();
      },
    });
    onData((buf: Buffer) => {
      if (ended) return;
      if (buf.length === 3 && buf.toString("utf-8") === "EOF") {
        // EOF marker: never treat it as data; end once pending data is drained
        eof = true;
      } else {
        pending.push(buf);
      }
      flush();
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

export function convertWebWritableStreamToNodeWritable(webWritableStream: WritableStream) {
  // Keep a single writer (and its lock) for the whole lifetime of the Node stream.
  const writer = webWritableStream.getWriter();
  return new Writable({
    async write(chunk, encoding, callback) {
      try {
        await writer.write(chunk);
        callback();
      } catch (error) {
        callback(error as Error);
      }
    },
    async final(callback) {
      try {
        await writer.close();
        writer.releaseLock();
        callback();
      } catch (error) {
        callback(error as Error);
      }
    },
    async destroy(error, callback) {
      try {
        await writer.abort(error);
        writer.releaseLock();
      } catch {
        // stream already closed or errored: nothing more to abort
      }
      callback(error);
    },
  });
}

export function convertWebReadableStreamToNodeReadable(webReadableStream: ReadableStream) {
  const reader = webReadableStream.getReader();

  return new Readable({
    async read() {
      try {
        while (true) {
          const { done, value } = await reader.read();
          //console.log(value);
          if (done) {
            this.push(null); // Signal the end of the stream
            break;
          }
          this.push(Buffer.from(value)); // Need to convert Uint8Array to Buffer
        }
      } catch (error) {
        this.destroy();
      }
    },
  });
}

export class MemoryChannel implements Channel {
  name?: string;
  otherend?: MemoryChannel;
  private messageQueue: Buffer[] = [];
  private waitingResolvers: ((data: Buffer) => void)[] = [];
  private connected = false;
  private connectedCallbacks: (() => void)[] = [];
  private closed = false;
  logger?: (data: Buffer) => void;
  injector?: (data: Buffer) => Promise<Buffer> | Buffer;

  setChannel(chan: MemoryChannel, name?: string) {
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

  onConnected(callback: () => void) {
    if (this.connected) {
      callback();
    } else {
      this.connectedCallbacks.push(callback);
    }
  }

  static createEncryptedBidirectionnal(key: Buffer = cc.generateKey()) {
    const input = cc.encryptChannel(new MemoryChannel(), key) as MemoryChannel;
    const output = cc.encryptChannel(new MemoryChannel(), key) as MemoryChannel;
    input.setChannel(output);
    output.setChannel(input);
    return input;
  }

  getConnectionString() {
    return "vaultys://memory";
  }

  fromConnectionString(string: string) {
    return string === "vaultys://memory" ? new MemoryChannel() : null;
  }

  setLogger(logger: (data: Buffer) => void) {
    this.logger = logger;
  }

  setInjector(injector: (data: Buffer) => Buffer) {
    this.injector = injector;
  }

  async start() {
    this.connected = true;
    this.connectedCallbacks.forEach((callback) => callback());
    this.connectedCallbacks = []; // Clear callbacks after calling them
  }

  async send(data: Buffer) {
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

  private deliverMessage(data: Buffer) {
    // If there are waiting receivers, deliver directly to the first one
    if (this.waitingResolvers.length > 0) {
      const resolver = this.waitingResolvers.shift()!;
      resolver(data);
    } else {
      // Otherwise queue the message
      this.messageQueue.push(data);
    }
  }

  async receive(): Promise<Buffer> {
    if (this.closed) {
      throw new Error("Cannot receive on closed channel");
    }

    //console.log(this);

    // If there are queued messages, return the first one
    if (this.messageQueue.length > 0) {
      return this.messageQueue.shift()!;
    }

    // Otherwise, wait for a message to arrive
    return new Promise<Buffer>((resolve) => {
      this.waitingResolvers.push(resolve);
    });
  }

  async close() {
    this.closed = true;

    // Clear any waiting receivers with an error
    while (this.waitingResolvers.length > 0) {
      const resolver = this.waitingResolvers.shift()!;
      // Resolve with empty buffer to indicate channel closed
      resolver(Buffer.alloc(0));
    }

    // Clear the message queue
    this.messageQueue = [];
  }
}
