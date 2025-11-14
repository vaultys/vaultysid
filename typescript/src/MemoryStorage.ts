import { decode, encode } from "@msgpack/msgpack";
import { Buffer } from "buffer/";

const replacer = (key: string, value: any) => {
  //if(key=="1686045792046") console.log(value);
  if (!value) return value;
  // if (key === "entropy") console.log(value, value.constructor.name);
  if (key === "certificate") return "_bx_" + Buffer.from(value).toString("base64");
  if (key === "publicKey") return "_bx_" + Buffer.from(value).toString("base64");
  if (key === "secretKey") return "_bx_" + Buffer.from(value).toString("base64");
  if (value.constructor.name === "Buffer") {
    //console.log("Buffer");
    return "_bx_" + value.toString("base64");
  }
  if (value.type === "Buffer") {
    //console.log(key, "_bx_" + Buffer.from(value.data).toString("base64"));
    return "_bx_" + Buffer.from(value.data).toString("base64");
  }

  if (value.constructor.name === "Array" || value.constructor.name === "Uint8Array") {
    return "_bx_" + Buffer.from(value).toString("base64");
  }
  return value;
};

const reviver = (key: string, value: any) => {
  if (typeof value === "string") {
    if (value.startsWith("__C__")) return Buffer.from(value.slice(5), "base64");
    if (value.startsWith("_bx_")) return Buffer.from(value.slice(4), "base64");
  }
  return value;
};

export const serialize = (data: any) => JSON.stringify(data, replacer);
export const deserialize = (string: string) => JSON.parse(string, reviver);

export const MemoryStorage = (save?: () => void): Store => {
  let data = {};
  if (!save) save = () => serialize(data);
  return storagify(data, save, () => "");
};

export const LocalStorage = (key = "vaultysStorage"): Store => {
  let data = {};
  if (!localStorage[key]) localStorage[key] = "{}";
  else data = deserialize(localStorage[key]);
  return storagify(
    data,
    () => localStorage.setItem(key, serialize(data)),
    () => localStorage.removeItem(key),
  );
};

export const MessagePackStorage = (key = "vaultysStorage"): Store => {
  let data: object = {};
  if (!localStorage[key]) localStorage[key] = Buffer.from(encode({})).toString("base64");
  else data = decode(localStorage[key]) as object;
  return storagify(
    data,
    () => localStorage.setItem(key, Buffer.from(encode(data)).toString("base64")),
    () => localStorage.removeItem(key),
  );
};

class IStore implements Store {
  _raw: Record<string, object>;

  constructor(object: Record<string, object>) {
    this._raw = object;
  }
  save() {}
  destroy() {}
  toString() {
    return Buffer.from(encode(this._raw)).toString("base64");
  }
  toJSON() {
    return decode(encode(this._raw)) as object;
  }
  fromJSON(object: object, s: () => void, d: () => void) {
    return new IStore(object as Record<string, object>);
  }
  fromString(string: string, s: () => void, d: () => void) {
    return new IStore(decode(Buffer.from(string, "base64")) as Record<string, object>);
  }
  set(key: string, value: any) {
    this._raw[key] = value;
  }
  delete(key: string) {
    delete this._raw[key];
  }
  get(key: string) {
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
  deleteSubstore(key: string) {
    delete this._raw["!" + key];
  }
  renameSubstore(oldname: string, newname: string) {
    if (oldname === newname || !!this._raw["!" + newname]) return;
    this._raw["!" + newname] = this._raw["!" + oldname];
    delete this._raw["!" + oldname];
  }
  substore(key: string) {
    if (!this._raw["!" + key]) this._raw["!" + key] = {};
    return new IStore(this._raw["!" + key] as Record<string, Object>);
  }
}

export class MemoryStore extends IStore {}

export class MessagePackStore extends IStore {}

export const storagify = (jsonObject: Record<string, any>, save = () => {}, destroy = () => {}): Store => {
  const result = { _raw: jsonObject };
  return {
    ...result,
    destroy,
    save,
    toString: () => serialize(result._raw),
    toJSON: () => deserialize(serialize(result._raw)), // creating a copy
    fromJSON: (object: object, s: () => void, d: () => void) => storagify(object, s, d), // creating a copy
    fromString: (string: string, s: () => void, d: () => void) => storagify(deserialize(string), s, d),
    set: (key: string, value: any) => (result._raw[key] = value),
    delete: (key: string) => delete result._raw[key],
    get: (key: string) => result._raw[key],
    list: () => Object.keys(result._raw).filter((k) => !k.startsWith("!")),
    listSubstores: () =>
      Object.keys(result._raw)
        .filter((k) => k.startsWith("!"))
        .map((k) => k.slice(1)),
    deleteSubstore: (key: string) => delete result._raw["!" + key],
    renameSubstore: (oldname: string, newname: string) => {
      if (oldname === newname || !!result._raw["!" + newname]) return;
      result._raw["!" + newname] = result._raw["!" + oldname];
      delete result._raw["!" + oldname];
    },
    substore: (key: string) => {
      if (!result._raw["!" + key]) result._raw["!" + key] = {};
      return storagify(result._raw["!" + key], save, destroy);
    },
  } as Store;
};

export type Store = {
  substore(key: string): Store;
  renameSubstore?(oldname: string, newname: string): void;
  listSubstores(): string[];
  deleteSubstore(key: string): void;
  list(): string[];
  delete(prop: string): void;
  get(prop: string): any;
  set(prop: string, value: any): void;
  save(): void;
  destroy(): void;
  toString(): string;
  toJSON(): object;
  fromString(string: string, save?: () => void, destroy?: () => void): Store;
  fromJSON(object: object, save?: () => void, destroy?: () => void): Store;
};
