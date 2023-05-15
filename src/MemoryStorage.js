const replacer = (key, value) => {
  if(key==="certificate") return "__C__"+Buffer.from(value).toString("hex");
  if (value && value.type === "Buffer") {
    return "0x"+Buffer.from(value.data).toString("hex");
  }
  return value;
}

const reviver = (key, value) => {
  if(key==="certificate") return Buffer.from(value.slice(5), "hex").data;
  typeof value === "string" && value.startsWith("0x") ? Buffer.from(value.slice(2), "hex") : value
}

const serialize = data => JSON.stringify(data, replacer);
const deserialize = string => JSON.parse(string, reviver);

const MemoryStorage = (save) => {
  let data = {}; 
  if(!save) save = () => console.log(serialize(data));
  return storagify(data, save, () => "");
}

const LocalStorage = (key = "vaultysStorage") => {
  let data = {};
  if(!localStorage.getItem(key)) localStorage.setItem(key, "{}")
  else data = deserialize(localStorage.getItem(key));
  return storagify(data, () => localStorage.setItem(key, serialize(data)), () => localStorage.removeItem(key));
}

const storagify =  (object, save, destroy) => {
  return {
    destroy,
    save,
    _raw: object,
    set: (key, value) => object[key] = value,
    delete: key => delete object[key],
    get: key => object[key],
    list: () => Object.keys(object).filter(k => !k.startsWith("!")),
    substores: () => Object.keys(object).filter(k => k.startsWith("!")).map(k => k.slice(1)),
    substore: key => {
      if(!object["!"+key]) object["!"+key] = {};
      return storagify(object["!"+key], save, destroy);
    }
  }
}


export { MemoryStorage, LocalStorage };
