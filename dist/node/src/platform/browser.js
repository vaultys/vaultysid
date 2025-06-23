"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BrowserCrypto = void 0;
const pbkdf2_web_1 = require("./pbkdf2.web");
const webauthn_1 = require("./webauthn");
exports.BrowserCrypto = {
    webauthn: new webauthn_1.BrowserWebAuthn(),
    pbkdf2: {
        encrypt: pbkdf2_web_1.encrypt,
        decrypt: pbkdf2_web_1.decrypt,
    },
};
