const replacer = (key, value) => {
  //if(key=="1686045792046") console.log(value);
  if(!value) return value;
  if (key === "certificate")
    return "__C__" + Buffer.from(value).toString("base64");
  if (value.type === "Buffer") {
    return "_bx_" + Buffer.from(value.data).toString("base64");
  }
  if(value.constructor.name === "Array") {
    return "_bx_" + Buffer.from(value).toString("base64");
  }
  return value;
};

const reviver = (key, value) => {
  if (value && key === "certificate") {
    if(typeof value === "string" && value.startsWith("__C__")) {
      return Buffer.from(value.slice(5), "base64");
    }
    else return Buffer.from(value);
  }
  if(typeof value === "string" && value.startsWith("_bx_")) {
    return Buffer.from(value.slice(4), "base64")
  }
  return value;
};

const serialize = (data) => JSON.stringify(data, replacer);
const deserialize = (string) => JSON.parse(string, reviver);

export const MemoryStorage = (save) => {
  let data = {};
  if (!save) save = () => serialize(data);
  return storagify(data, save, () => "");
};

export const LocalStorage = (key = "vaultysStorage") => {
  let data = {};
  if (!localStorage[key]) localStorage[key] = "{}";
  else data = deserialize(localStorage[key]);
  return storagify(
    data,
    () => localStorage.setItem(key, serialize(data)),
    () => localStorage.removeItem(key),
  );
};

const storagify = (object, save, destroy) => {
  return {
    destroy,
    save,
    toString: () => serialize(object),
    fromString: (string, s = ()=>{}, d = ()=>{}) => storagify(deserialize(string), s, d),
    _raw: object,
    set: (key, value) => (object[key] = value),
    delete: (key) => delete object[key],
    get: (key) => object[key],
    list: () => Object.keys(object).filter((k) => !k.startsWith("!")),
    listSubstores: () =>
      Object.keys(object)
        .filter((k) => k.startsWith("!"))
        .map((k) => k.slice(1)),
    deleteSubstore: (key) => delete object["!" + key],
    substore: (key) => {
      if (!object["!" + key]) object["!" + key] = {};
      return storagify(object["!" + key], save, destroy);
    },
  };
};
