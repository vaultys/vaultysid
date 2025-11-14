"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isBrowser = exports.isNode = void 0;
exports.isNode = typeof window === "undefined";
exports.isBrowser = !exports.isNode;
