import cc from "./cryptoChannel";
import { Readable, Stream, Writable } from "stream";

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export type Channel = {
  start(): Promise<void>;
  close(): Promise<void>;
  send(data: Buffer): void;
  receive(): Promise<Buffer>;
  getConnectionString(): string;
  fromConnectionString(conn: string): Channel | null;
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
    const result = new Promise<void>((resolve) => readStream.on("end", () => resolve()));
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

export class MemoryChannel implements Channel {
  name?: string;
  otherend?: MemoryChannel;
  receiver?: (data: Buffer) => void;
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
    while (!this.otherend?.receiver) {
      await delay(10);
    }
    const receiver = this.otherend.receiver;
    delete this.otherend.receiver;
    if (this.logger) this.logger(data);
    if (this.injector) receiver(await this.injector(data));
    else receiver(data);
  }

  async receive() {
    while (this.receiver) {
      await delay(10);
    }
    return new Promise<Buffer>((resolve) => (this.receiver = resolve));
  }

  async close() {}
}
