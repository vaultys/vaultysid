import { secretbox, toBase64, fromBase64, randomBytes } from "./crypto.js";

const newNonce = () => randomBytes(secretbox.nonceLength);

export const encrypt = (buffer, key) => {
  const keyUint8Array = key;
  const nonce = newNonce();
  const box = secretbox(Uint8Array.from(buffer), nonce, keyUint8Array);

  const fullMessage = new Uint8Array(nonce.length + box.length);
  fullMessage.set(nonce);
  fullMessage.set(box, nonce.length);

  const base64FullMessage = toBase64(fullMessage);
  return base64FullMessage;
};

export const decrypt = (messageWithNonce, key) => {
  const keyUint8Array = key;
  const messageWithNonceAsUint8Array = fromBase64(messageWithNonce);
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

const encryptChannel = (channel, key) => {
  const sendHandler = {
    apply(target, that, args) {
      return target.call(that, encrypt(args[0], key));
    },
  };
  const receiveHandler = {
    async apply(target, that, args) {
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
