import cc from "./cryptoChannel.js";

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export class MemoryChannel {
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

  static createEncryptedBidirectionnal(key) {
    key = key ? key : cc.generateKey();
    const input = cc.encryptChannel(new MemoryChannel(), key);
    const output = cc.encryptChannel(new MemoryChannel(), key);
    input.setChannel(output);
    output.setChannel(input);
    return input;
  }

  async send(data) {
    // the other end might not listen yet
    while (!this.otherend.resolver) {
      await delay(100);
    }
    this.otherend.resolver(data);
  }
  async receive() {
    return new Promise((resolve) => (this.resolver = resolve));
  }
  close() {}
}
