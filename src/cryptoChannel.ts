import { Channel } from "./MemoryChannel";
import { secretbox, toBase64, fromBase64, randomBytes } from "./crypto";

const newNonce = () => randomBytes(secretbox.nonceLength);

export const encrypt = (buffer: Buffer, key: Buffer) => {
  //console.log("encrypting: ", buffer, key)
  const keyUint8Array = key;
  const nonce = newNonce();
  const box = secretbox(Uint8Array.from(buffer), nonce, keyUint8Array);

  const fullMessage = new Uint8Array(nonce.length + box.length);
  fullMessage.set(nonce);
  fullMessage.set(box, nonce.length);

  return Buffer.from(fullMessage);
};

export const decrypt = (messageWithNonce: Buffer, key: Buffer) => {
  //console.log("decrypting: ", messageWithNonce, key)
  const keyUint8Array = key;
  const messageWithNonceAsUint8Array = messageWithNonce;
  const nonce = messageWithNonceAsUint8Array.slice(0, secretbox.nonceLength);
  const message = messageWithNonceAsUint8Array.slice(
    secretbox.nonceLength,
    messageWithNonce.length,
  );

  const decrypted = secretbox.open(message, nonce, keyUint8Array);

  if (!decrypted) {
    throw new Error("Could not decrypt message");
  }
  return Buffer.from(decrypted);
};

// upgrading a channel api with an encrypting layer. The API shoud be
// - send(Buffer):null
// - async receive():Buffer

const encryptChannel = (channel: Channel, key: Buffer) => {
  const sendHandler = {
    apply(target: (data: Buffer) => void, that:any, args: any) {
      return target.call(that, encrypt(args[0], key));
    },
  };
  const receiveHandler = {
    async apply(target: () => Promise<Buffer>, that: any, args: any) {
      const result = await target.call(that);
      return decrypt(result, key);
    },
  };
  channel.send = new Proxy(channel.send, sendHandler);
  channel.receive = new Proxy(channel.receive, receiveHandler);
  return channel;
};

const generateKey = () => randomBytes(32);

export default {
  decrypt,
  encrypt,
  encryptChannel,
  generateKey,
};
