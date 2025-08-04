"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CryptoChannel = exports.GameOfLifeIcon = exports.KeyManager = exports.IdManager = exports.LocalStorage = exports.convertWebWritableStreamToNodeWritable = exports.convertWebReadableStreamToNodeReadable = exports.StreamChannel = exports.MemoryStorage = exports.MemoryChannel = exports.Challenger = exports.VaultysId = exports.Buffer = exports.crypto = void 0;
const Challenger_1 = __importDefault(require("./src/Challenger"));
exports.Challenger = Challenger_1.default;
const IdManager_1 = __importDefault(require("./src/IdManager"));
exports.IdManager = IdManager_1.default;
const KeyManager_1 = __importDefault(require("./src/KeyManager"));
exports.KeyManager = KeyManager_1.default;
const VaultysId_1 = __importDefault(require("./src/VaultysId"));
exports.VaultysId = VaultysId_1.default;
const MemoryChannel_1 = require("./src/MemoryChannel");
Object.defineProperty(exports, "MemoryChannel", { enumerable: true, get: function () { return MemoryChannel_1.MemoryChannel; } });
Object.defineProperty(exports, "StreamChannel", { enumerable: true, get: function () { return MemoryChannel_1.StreamChannel; } });
Object.defineProperty(exports, "convertWebReadableStreamToNodeReadable", { enumerable: true, get: function () { return MemoryChannel_1.convertWebReadableStreamToNodeReadable; } });
Object.defineProperty(exports, "convertWebWritableStreamToNodeWritable", { enumerable: true, get: function () { return MemoryChannel_1.convertWebWritableStreamToNodeWritable; } });
const MemoryStorage_1 = require("./src/MemoryStorage");
Object.defineProperty(exports, "MemoryStorage", { enumerable: true, get: function () { return MemoryStorage_1.MemoryStorage; } });
Object.defineProperty(exports, "LocalStorage", { enumerable: true, get: function () { return MemoryStorage_1.LocalStorage; } });
const GameOfLifeIcon_1 = __importDefault(require("./src/GameOfLifeIcon"));
exports.GameOfLifeIcon = GameOfLifeIcon_1.default;
const cryptoChannel_1 = __importDefault(require("./src/cryptoChannel"));
exports.CryptoChannel = cryptoChannel_1.default;
//utils
const crypto = __importStar(require("./src/crypto"));
exports.crypto = crypto;
const Buffer = crypto.Buffer;
exports.Buffer = Buffer;
if (typeof Symbol.dispose === "undefined") {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    Symbol.dispose = Symbol("Symbol.dispose");
}
