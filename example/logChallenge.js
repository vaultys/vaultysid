import IdManager from "../src/IdManager.js"
import { MemoryChannel } from "../src/MemoryChannel.js";
import { MemoryStorage } from "../src/MemoryStorage.js";
import VaultysId from "../src/VaultysId.js"
import cryptoChannel, { decrypt } from "../src/cryptoChannel.js";
import msgpack from "@ygoe/msgpack";

const createIdManager = async () => {
  const vaultysId = await VaultysId.generateMachine();
  const storage = MemoryStorage();
  return new IdManager(vaultysId, storage)
}

const deserializeData = (data, key) => {
  const decrypted = decrypt(data, key)
  return decrypted;
}


// simple logger. You may want to collect data for statistical analysis.
const logger = (prefix, key) => (data) => {
  const decrypted = deserializeData(data, key);
  const unpacked = msgpack.decode(decrypted);
  console.log(prefix, unpacked);
}

const start = async () => {
  // create 2 ids that will communicate and exchange keys
  const id1 = await createIdManager();
  const id2 = await createIdManager();

  // create an encrypted channel using key
  const key = cryptoChannel.generateKey();
  const channel = MemoryChannel.createEncryptedBidirectionnal(key);

  channel.setLogger(logger("id1 -> ", key));
  channel.otherend.setLogger(logger("id2 -> ", key));

  const contacts = await Promise.all([
    id1.askContact(channel),
    id2.acceptContact(channel.otherend),
  ]);

}

start();
