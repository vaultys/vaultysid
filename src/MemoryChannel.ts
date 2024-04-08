import cc from "./cryptoChannel";

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export type Channel = {
  start(): Promise<void>;
  close(): Promise<void>;
  send(data: Buffer): void;
  receive(): Promise<Buffer>;
  getConnectionString(): string;
  fromConnectionString(conn: string): Channel | null;
}

export class MemoryChannel {
  name?: string;
  otherend?: MemoryChannel;
  resolver?: (data: Buffer) =>  void
  
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

  async start() {
    // noop
  }

  async send(data: Buffer) {
    // the other end might not listen yet
    while (!this.otherend?.resolver) {
      await delay(100);
    }
    this.otherend?.resolver(data);
  }
  async receive() {
    return new Promise<Buffer>(resolve => (this.resolver = resolve));
  }
  async close() {}
}
