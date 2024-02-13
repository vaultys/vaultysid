import IdManager from "../src/IdManager.js"
import { MemoryChannel } from "../src/MemoryChannel.js";
import { MemoryStorage } from "../src/MemoryStorage.js";
import VaultysId from "../src/VaultysId.js"
import cryptoChannel, { decrypt, encrypt } from "../src/cryptoChannel.js";
import msgpack from "@ygoe/msgpack";

const createIdManager = async () => {
  const vaultysId = await VaultysId.generateMachine();
  const storage = MemoryStorage();
  return new IdManager(vaultysId, storage)
}

const deserializeData = (data, key) => {
  const decrypted = decrypt(data, key)
  const unpacked = msgpack.decode(decrypted);
  return unpacked;
}

const serializeData = (data, key) => {
  const packed = msgpack.encode(data);
  const encrypted = encrypt(packed, key);
  return encrypted;
}

const logger = (prefix, key) => (data) => {
  const unpacked = deserializeData(data, key);
  console.log(prefix, unpacked);
}

// TODO: Perform some sidechannel attack here.
const injector = (key) => (data) => {
  const unpacked = deserializeData(data, key);
  // unpacked.protocol = "p2pp"; // modifying purpose
  // unpacked.service = "hack"; // modifying purpose
  // unpacked.state = 2; // inject non protocol data
  // unpacked.nonce = cryptoChannel.generateKey(); // tamper with nonce
  unpacked.nonce[0]++; // tamper with nonce
  // unpacked.timestamp = Date.now(); // modifying timestamp for replay?
  // if(unpacked.pk1 && unpacked.pk2) { // mixing with ids
  //   const temp = unpacked.pk1;
  //   unpacked.pk1 = unpacked.pk2;
  //   unpacked.pk2 = temp;
  // }
  return serializeData(unpacked, key);
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


  channel.otherend.setInjector(injector(key));

  const contacts = await Promise.all([
    id1.askContact(channel),
    id2.acceptContact(channel.otherend),
  ]);

}

start();
