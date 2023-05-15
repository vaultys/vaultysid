import cc from "../src/cryptoChannel.js";

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export class ChannelMock {
  setChannel(chan, name) {
    this.name = name;
    this.otherend = chan;
  }

  static createBidirectionnal() {
    const input = new ChannelMock();
    const output = new ChannelMock();
    input.setChannel(output);
    output.setChannel(input);
    return input;
  }

  static createEncryptedBidirectionnal(key) {
    key = key ? key : cc.generateKey();
    const input = cc.encryptChannel(new ChannelMock(), key);
    const output = cc.encryptChannel(new ChannelMock(), key);
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
