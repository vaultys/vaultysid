import cc from "./cryptoChannel";

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export type Channel = {
  start(): Promise<void>;
  close(): Promise<void>;
  send(data: Buffer): void;
  receive(): Promise<Buffer>;
  getConnectionString(): string;
  fromConnectionString(conn: string): Channel | null;
};

export class MemoryChannel {
  name?: string;
  otherend?: MemoryChannel;
  resolver?: (data: Buffer) => void;
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

  static createEncryptedBidirectionnal(key: Buffer) {
    key = key ? key : cc.generateKey();
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
    return new MemoryChannel();
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
    while (!this.otherend?.resolver) {
      await delay(100);
    }
    if (this.logger) this.logger(data);
    if (this.injector) {
      this.otherend?.resolver(await this.injector(data));
    } else {
      this.otherend?.resolver(data);
    }
  }
  async receive() {
    return new Promise<Buffer>((resolve) => (this.resolver = resolve));
  }
  async close() {}
}
