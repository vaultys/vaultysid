"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.migrateVaultysId = migrateVaultysId;
const msgpack_1 = require("@msgpack/msgpack");
const crypto_1 = require("../crypto");
function migrateVaultysId(oldVid) {
    const data = (0, msgpack_1.decode)(oldVid.slice(1));
    if (data.x?.length === 96)
        data.x = data.x.slice(0, 32);
    data.p = crypto_1.Buffer.from([]);
    return crypto_1.Buffer.concat([oldVid.slice(0, 1), (0, msgpack_1.encode)(data)]);
}
