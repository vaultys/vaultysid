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

  // sniff all the data passed: logger = (data) => void
  setLogger(logger) {
    this.logger = logger;
  }

  // allow to modify the data passed to inject new data: injector = (data) => newdata
  setInjector(injector) {
    this.injector = injector;
  }

  async send(data) {
    if(this.logger) {
      this.logger(data);
    }
    // the other end might not listen yet
    while (!this.otherend.resolver) {
      await delay(100);
    }
    if(this.injector) {
      this.otherend.resolver(this.injector(data));
    }
    else {
      this.otherend.resolver(data);
    }
  }
  async receive() {
    return new Promise((resolve) => (this.resolver = resolve));
  }
  close() {}
}
