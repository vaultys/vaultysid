"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.platformCrypto = void 0;
const environment_1 = require("../utils/environment");
const node_1 = require("./node");
const browser_1 = require("./browser");
exports.platformCrypto = environment_1.isNode ? new node_1.NodeCrypto() : new browser_1.BrowserCrypto();
