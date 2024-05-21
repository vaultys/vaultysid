const replacer = (key: string, value: any) => {
  //if(key=="1686045792046") console.log(value);
  if (!value) return value;
  if (key === "certificate")
    return "__C__" + Buffer.from(value).toString("base64");
  if (value.type === "Buffer") {
    return "_bx_" + Buffer.from(value.data).toString("base64");
  }
  if (value.constructor.name === "Array") {
    return "_bx_" + Buffer.from(value).toString("base64");
  }
  return value;
};

const reviver = (key: string, value: any) => {
  if (value && key === "certificate") {
    if (typeof value === "string" && value.startsWith("__C__")) {
      return Buffer.from(value.slice(5), "base64");
    }
    else return Buffer.from(value);
  }
  if (typeof value === "string" && value.startsWith("_bx_")) {
    return Buffer.from(value.slice(4), "base64")
  }
  return value;
};



export const serialize = (data: any) => JSON.stringify(data, replacer);
export const deserialize = (string: string) => JSON.parse(string, reviver);

export const MemoryStorage = (save: () => void): Store => {
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

const storagify = (object: Record<string, any>, save: () => void, destroy: () => void): Store => {
  return {
    destroy,
    save,
    toString: () => serialize(object),
    fromString: (string: string, s: () => void, d: () => void) => storagify(deserialize(string), s, d),
    _raw: object,
    set: (key: string, value: any) => (object[key] = value),
    delete: (key: string) => delete object[key],
    get: (key: string) => object[key],
    list: () => Object.keys(object).filter((k) => !k.startsWith("!")),
    listSubstores: () =>
      Object.keys(object)
        .filter((k) => k.startsWith("!"))
        .map((k) => k.slice(1)),
    deleteSubstore: (key: string) => delete object["!" + key],
    substore: (key: string) => {
      if (!object["!" + key]) object["!" + key] = {};
      return storagify(object["!" + key], save, destroy);
    }
  } as Store;
};

export type Store = {
  substore(key: string): Store
  listSubstores(): string[]
  deleteSubstore(key: string): void
  list(): string[]
  delete(prop: string): void
  get(prop: string): any
  set(prop: string, value: any): void
  save(): void
  destroy(): void
  toString(): string
  fromString(string: string, save?:  () => void, destroy?: () => void): Store
}
