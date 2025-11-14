"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decrypt = exports.encrypt = void 0;
const crypto_1 = require("./crypto");
const buffer_1 = require("buffer/");
const newNonce = () => (0, crypto_1.randomBytes)(crypto_1.secretbox.nonceLength);
const encrypt = (buffer, key) => {
    //console.log("encrypting: ", buffer, key)
    const keyUint8Array = key;
    const nonce = newNonce();
    const box = (0, crypto_1.secretbox)(Uint8Array.from(buffer), nonce, keyUint8Array);
    const fullMessage = new Uint8Array(nonce.length + box.length);
    fullMessage.set(nonce);
    fullMessage.set(box, nonce.length);
    return buffer_1.Buffer.from(fullMessage);
};
exports.encrypt = encrypt;
const decrypt = (messageWithNonce, key) => {
    //console.log("decrypting: ", messageWithNonce, key)
    const keyUint8Array = key;
    const messageWithNonceAsUint8Array = messageWithNonce;
    const nonce = messageWithNonceAsUint8Array.slice(0, crypto_1.secretbox.nonceLength);
    const message = messageWithNonceAsUint8Array.slice(crypto_1.secretbox.nonceLength, messageWithNonce.length);
    const decrypted = crypto_1.secretbox.open(message, nonce, keyUint8Array);
    if (!decrypted) {
        throw new Error("Could not decrypt message");
    }
    return buffer_1.Buffer.from(decrypted);
};
exports.decrypt = decrypt;
// upgrading a channel api with an encrypting layer. The API shoud be
// - send(Buffer):null
// - async receive():Buffer
const encryptChannel = (channel, key) => {
    const sendHandler = {
        apply(target, that, args) {
            return target.call(that, (0, exports.encrypt)(args[0], key));
        },
    };
    const receiveHandler = {
        async apply(target, that, args) {
            const result = await target.call(that);
            return (0, exports.decrypt)(result, key);
        },
    };
    channel.send = new Proxy(channel.send, sendHandler);
    channel.receive = new Proxy(channel.receive, receiveHandler);
    return channel;
};
const generateKey = () => (0, crypto_1.randomBytes)(32);
exports.default = {
    decrypt: exports.decrypt,
    encrypt: exports.encrypt,
    encryptChannel,
    generateKey,
};
