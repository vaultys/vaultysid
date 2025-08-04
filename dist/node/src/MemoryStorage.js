"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.storagify = exports.MessagePackStore = exports.MemoryStore = exports.MessagePackStorage = exports.LocalStorage = exports.MemoryStorage = exports.deserialize = exports.serialize = void 0;
const msgpack_1 = require("@msgpack/msgpack");
const buffer_1 = require("buffer/");
const replacer = (key, value) => {
    //if(key=="1686045792046") console.log(value);
    if (!value)
        return value;
    // if (key === "entropy") console.log(value, value.constructor.name);
    if (key === "certificate")
        return "_bx_" + buffer_1.Buffer.from(value).toString("base64");
    if (key === "publicKey")
        return "_bx_" + buffer_1.Buffer.from(value).toString("base64");
    if (key === "secretKey")
        return "_bx_" + buffer_1.Buffer.from(value).toString("base64");
    if (value.constructor.name === "Buffer") {
        //console.log("Buffer");
        return "_bx_" + value.toString("base64");
    }
    if (value.type === "Buffer") {
        //console.log(key, "_bx_" + Buffer.from(value.data).toString("base64"));
        return "_bx_" + buffer_1.Buffer.from(value.data).toString("base64");
    }
    if (value.constructor.name === "Array" || value.constructor.name === "Uint8Array") {
        return "_bx_" + buffer_1.Buffer.from(value).toString("base64");
    }
    return value;
};
const reviver = (key, value) => {
    if (typeof value === "string") {
        if (value.startsWith("__C__"))
            return buffer_1.Buffer.from(value.slice(5), "base64");
        if (value.startsWith("_bx_"))
            return buffer_1.Buffer.from(value.slice(4), "base64");
    }
    return value;
};
const serialize = (data) => JSON.stringify(data, replacer);
exports.serialize = serialize;
const deserialize = (string) => JSON.parse(string, reviver);
exports.deserialize = deserialize;
const MemoryStorage = (save) => {
    let data = {};
    if (!save)
        save = () => (0, exports.serialize)(data);
    return (0, exports.storagify)(data, save, () => "");
};
exports.MemoryStorage = MemoryStorage;
const LocalStorage = (key = "vaultysStorage") => {
    let data = {};
    if (!localStorage[key])
        localStorage[key] = "{}";
    else
        data = (0, exports.deserialize)(localStorage[key]);
    return (0, exports.storagify)(data, () => localStorage.setItem(key, (0, exports.serialize)(data)), () => localStorage.removeItem(key));
};
exports.LocalStorage = LocalStorage;
const MessagePackStorage = (key = "vaultysStorage") => {
    let data = {};
    if (!localStorage[key])
        localStorage[key] = buffer_1.Buffer.from((0, msgpack_1.encode)({})).toString("base64");
    else
        data = (0, msgpack_1.decode)(localStorage[key]);
    return (0, exports.storagify)(data, () => localStorage.setItem(key, buffer_1.Buffer.from((0, msgpack_1.encode)(data)).toString("base64")), () => localStorage.removeItem(key));
};
exports.MessagePackStorage = MessagePackStorage;
class IStore {
    constructor(object) {
        this._raw = object;
    }
    save() { }
    destroy() { }
    toString() {
        return buffer_1.Buffer.from((0, msgpack_1.encode)(this._raw)).toString("base64");
    }
    toJSON() {
        return (0, msgpack_1.decode)((0, msgpack_1.encode)(this._raw));
    }
    fromJSON(object, s, d) {
        return new IStore(object);
    }
    fromString(string, s, d) {
        return new IStore((0, msgpack_1.decode)(buffer_1.Buffer.from(string, "base64")));
    }
    set(key, value) {
        this._raw[key] = value;
    }
    delete(key) {
        delete this._raw[key];
    }
    get(key) {
        return this._raw[key];
    }
    list() {
        return Object.keys(this._raw).filter((k) => !k.startsWith("!"));
    }
    listSubstores() {
        return Object.keys(this._raw)
            .filter((k) => k.startsWith("!"))
            .map((k) => k.slice(1));
    }
    deleteSubstore(key) {
        delete this._raw["!" + key];
    }
    renameSubstore(oldname, newname) {
        if (oldname === newname || !!this._raw["!" + newname])
            return;
        this._raw["!" + newname] = this._raw["!" + oldname];
        delete this._raw["!" + oldname];
    }
    substore(key) {
        if (!this._raw["!" + key])
            this._raw["!" + key] = {};
        return new IStore(this._raw["!" + key]);
    }
}
class MemoryStore extends IStore {
}
exports.MemoryStore = MemoryStore;
class MessagePackStore extends IStore {
}
exports.MessagePackStore = MessagePackStore;
const storagify = (jsonObject, save = () => { }, destroy = () => { }) => {
    const result = { _raw: jsonObject };
    return {
        ...result,
        destroy,
        save,
        toString: () => (0, exports.serialize)(result._raw),
        toJSON: () => (0, exports.deserialize)((0, exports.serialize)(result._raw)), // creating a copy
        fromJSON: (object, s, d) => (0, exports.storagify)(object, s, d), // creating a copy
        fromString: (string, s, d) => (0, exports.storagify)((0, exports.deserialize)(string), s, d),
        set: (key, value) => (result._raw[key] = value),
        delete: (key) => delete result._raw[key],
        get: (key) => result._raw[key],
        list: () => Object.keys(result._raw).filter((k) => !k.startsWith("!")),
        listSubstores: () => Object.keys(result._raw)
            .filter((k) => k.startsWith("!"))
            .map((k) => k.slice(1)),
        deleteSubstore: (key) => delete result._raw["!" + key],
        renameSubstore: (oldname, newname) => {
            if (oldname === newname || !!result._raw["!" + newname])
                return;
            result._raw["!" + newname] = result._raw["!" + oldname];
            delete result._raw["!" + oldname];
        },
        substore: (key) => {
            if (!result._raw["!" + key])
                result._raw["!" + key] = {};
            return (0, exports.storagify)(result._raw["!" + key], save, destroy);
        },
    };
};
exports.storagify = storagify;
