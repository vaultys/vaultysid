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
      write: (chunk: Buffer, encoding: string, done: () => void) => {
        channel.send(chunk);
        done();
      },
    });
    return stream;
  };

  const upload = async (stream: Readable) => {
    return new Promise<void>((resolve) => {
      const writeStream = getWriteStream();
      stream.pipe(writeStream).once("finish", () => {
        channel.send(Buffer.from("EOF", "utf-8"));
        writeStream.end();
        resolve();
      });
    });
  };

  const uploadData = async (data: Buffer) => {
    const stream = Readable.from(data);
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
    let push: null | ((data: Buffer | null) => boolean);
    let temp: Buffer | null;
    const stream = new Stream.Readable({
      read() {
        push = (data) => this.push(data);
      },
    });
    onData((buf: Buffer) => {
      if (buf.length === 3 && buf.toString("utf-8") === "EOF" && push) {
        temp && push(temp);
        push(null);
        stream.destroy();
      }
      temp = temp ? Buffer.concat([temp, buf]) : buf;
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

export function convertWebWritableStreamToNodeWritable(webWritableStream: WritableStream) {
  const writer = webWritableStream.getWriter();
  return new Writable({
    async write(chunk, encoding, callback) {
      try {
        // Get a writer from the Web WritableStream
        await writer.write(chunk);
        writer.releaseLock(); // Release the lock on the writer after writing
        callback(); // Signal that the chunk has been processed
      } catch (error) {
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
      } catch (error) {
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
      } catch (abortError) {
        callback(null); // Signal an error if it occurred during abort
      }
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
  lock = false;
  otherend?: MemoryChannel;
  receiver?: (data: Buffer) => void;
  logger?: (data: Buffer) => void;
  injector?: (data: Buffer) => Promise<Buffer> | Buffer;
  _onConnected?: () => void;

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
    this._onConnected = callback;
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
    // noop
  }

  async send(data: Buffer) {
    // the other end might not listen yet
    while (this.lock || !this.otherend?.receiver) {
      // console.log(this.lock);
      await delay(10);
    }
    this.lock = true;
    const receiver = this.otherend.receiver;
    delete this.otherend.receiver;
    this.otherend._onConnected?.();
    delete this.otherend._onConnected;
    if (this.logger) this.logger(data);
    if (this.injector) {
      const injected = await this.injector(data);
      receiver(injected);
    } else receiver(data);
    this.lock = false;
  }

  async receive() {
    while (this.receiver) {
      console.log(this.lock);
      await delay(10);
    }
    return new Promise<Buffer>((resolve) => (this.receiver = resolve));
  }

  async close() {}
}
