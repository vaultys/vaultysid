"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.storagify = exports.LocalStorage = exports.MemoryStorage = exports.deserialize = exports.serialize = void 0;
const buffer_1 = require("buffer/");
const replacer = (key, value) => {
    //if(key=="1686045792046") console.log(value);
    if (!value)
        return value;
    if (key === "certificate")
        return "__C__" + buffer_1.Buffer.from(value).toString("base64");
    if (key === "publicKey")
        return "__C__" + buffer_1.Buffer.from(value).toString("base64");
    if (key === "secretKey")
        return "__C__" + buffer_1.Buffer.from(value).toString("base64");
    if (value.type === "Buffer") {
        return "_bx_" + buffer_1.Buffer.from(value.data).toString("base64");
    }
    if (value.constructor.name === "Array") {
        return "_bx_" + buffer_1.Buffer.from(value).toString("base64");
    }
    return value;
};
const reviver = (key, value) => {
    if (value && (key === "certificate" || key === "publicKey" || key === "secretKey")) {
        if (typeof value === "string" && value.startsWith("__C__")) {
            return buffer_1.Buffer.from(value.slice(5), "base64");
        }
        else
            return buffer_1.Buffer.from(value);
    }
    if (typeof value === "string" && value.startsWith("_bx_")) {
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
    const _id = Math.random();
    //console.log(key);
    if (!localStorage[key])
        localStorage[key] = "{}";
    else
        data = (0, exports.deserialize)(localStorage[key]);
    return (0, exports.storagify)(data, () => {
        //console.log("save !!!!!", key, _id);
        localStorage.setItem(key, (0, exports.serialize)(data));
    }, () => localStorage.removeItem(key));
};
exports.LocalStorage = LocalStorage;
const storagify = (object, save, destroy) => {
    const result = { _raw: object };
    return {
        ...result,
        destroy,
        save,
        toString: () => (0, exports.serialize)(result._raw),
        fromString: (string, s, d) => (0, exports.storagify)((0, exports.deserialize)(string), s, d),
        set: (key, value) => (object[key] = value),
        delete: (key) => delete object[key],
        get: (key) => object[key],
        list: () => Object.keys(object).filter((k) => !k.startsWith("!")),
        listSubstores: () => Object.keys(object)
            .filter((k) => k.startsWith("!"))
            .map((k) => k.slice(1)),
        deleteSubstore: (key) => delete object["!" + key],
        renameSubstore: (oldname, newname) => {
            if (oldname === newname || !!object["!" + newname])
                return;
            object["!" + newname] = object["!" + oldname];
            delete object["!" + oldname];
        },
        substore: (key) => {
            if (!object["!" + key])
                object["!" + key] = {};
            return (0, exports.storagify)(object["!" + key], save, destroy);
        },
    };
};
exports.storagify = storagify;
