import { Buffer } from "../crypto";
import IdManager from "../IdManager";
export declare function migrateVaultysId(oldVid: Buffer): Buffer;
export declare function migrateIdManager(idManager: IdManager): void;
