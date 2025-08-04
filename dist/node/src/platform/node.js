"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NodeCrypto = void 0;
const pbkdf2_node_1 = require("./pbkdf2.node");
const webauthn_1 = require("./webauthn");
exports.NodeCrypto = {
    webauthn: new webauthn_1.NodeWebAuthn(),
    pbkdf2: {
        encrypt: pbkdf2_node_1.encrypt,
        decrypt: pbkdf2_node_1.decrypt,
    },
};
