import { Buffer } from "buffer/";
import PQManager from "./PQManager";
import Fido2Manager from "./Fido2Manager";
import Fido2PRFManager from "./Fido2PRFManager";
import Ed25519Manager from "./Ed25519Manager";
import KeyManager from "./AbstractKeyManager";
export type KeyPair = {
    publicKey: Buffer;
    secretKey?: Buffer;
};
export type HISCP = {
    newId: Buffer;
    proofKey: Buffer;
    timestamp: number;
    signature: Buffer;
};
export default KeyManager;
export { PQManager, Fido2Manager, Fido2PRFManager, Ed25519Manager };
