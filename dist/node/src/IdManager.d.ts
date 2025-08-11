import { Readable, Writable } from "stream";
import Challenger from "./Challenger";
import KeyManager from "./KeyManager";
import { Channel } from "./MemoryChannel";
import { Store } from "./MemoryStorage";
import VaultysId from "./VaultysId";
import { Buffer } from "buffer/";
import DeprecatedKeyManager from "./KeyManager/DeprecatedKeyManager";
export type StoredContact = {
    type: number;
    keyManager: KeyManager | DeprecatedKeyManager;
    certificate: Buffer;
};
export type StoredApp = {
    site: string;
    serverId: string;
    certificate: Buffer;
};
export type FileSignature = {
    challenge: Buffer;
    signature: Buffer;
};
export type File = {
    arrayBuffer: Buffer;
    type: string;
    name?: string;
};
export declare const instanciateContact: (c: StoredContact) => VaultysId;
export declare const instanciateApp: (a: StoredApp) => VaultysId;
export default class IdManager {
    vaultysId: VaultysId;
    store: Store;
    protocol_version: 0 | 1;
    constructor(vaultysId: VaultysId, store: Store);
    setProtocolVersion(version: 0 | 1): void;
    /**
     * Exports the current profile as a backup
     * @param encrypted Whether to encrypt the backup
     * @param passphrase Optional passphrase for encryption (generated if not provided)
     * @returns Object containing backup data and optional passphrase
     */
    exportBackup(passphrase?: string): Promise<Uint8Array>;
    /**
     * Imports a backup file
     * @param backupData The backup file data as Uint8Array
     * @param passphrase Optional passphrase for decryption (only needed for encrypted backups)
     * @returns Promise resolving to import result or null if import failed
     */
    static importBackup(backupData: Uint8Array, passphrase?: string): Promise<IdManager | null>;
    static fromStore(store: Store): Promise<IdManager>;
    merge(otherStore: Store, master?: boolean): void;
    verifyWebOfTrust(): Promise<boolean>;
    isHardware(): boolean;
    signIn(): Promise<boolean>;
    get contacts(): VaultysId[];
    get apps(): VaultysId[];
    getContact(did: string): VaultysId | null;
    getApp(did: string): VaultysId | null;
    setContactMetadata(did: string, name: string, value: any): void;
    getContactMetadata(did: string, name: string): any;
    getContactMetadatas(did: string): any;
    verifyRelationshipCertificate(did: string): Promise<boolean>;
    set name(n: any);
    get name(): any;
    get displayName(): any;
    set phone(n: any);
    get phone(): any;
    set email(n: any);
    get email(): any;
    signChallenge(challenge: Buffer): Promise<Buffer>;
    signFile(file: File): Promise<FileSignature>;
    verifyFile(file: File, fileSignature: FileSignature, contactId: VaultysId, userVerifiation?: boolean): boolean;
    decryptFile(toDecrypt: File, channel?: Channel): Promise<File>;
    encryptFile(toEncrypt: File, channel?: Channel): Promise<File | null>;
    getSignatures(): {
        date: string;
        payload: any;
        challenge: string;
        type: string;
    }[];
    migrate(version: 0 | 1): void;
    verifyChallenge(challenge: Buffer, signature: Buffer): Promise<boolean>;
    upload(channel: Channel, stream: Readable): Promise<void>;
    download(channel: Channel, stream: Writable): Promise<void>;
    requestConnect(channel: Channel, contactdid: string): Promise<Buffer>;
    acceptConnect(channel: Channel, contactdid: string): Promise<void>;
    requestDecrypt(channel: Channel, toDecrypt: Buffer): Promise<Buffer | null | undefined>;
    acceptDecrypt(channel: Channel, accept?: (contact: VaultysId) => Promise<boolean>): Promise<void>;
    requestDecryptFile(channel: Channel, toDecrypt: File): Promise<File>;
    requestEncryptFile(channel: Channel, toEncrypt: File): Promise<File | null>;
    acceptDecryptFile(channel: Channel, accept?: (contact: VaultysId) => Promise<boolean>): Promise<null>;
    acceptEncryptFile: (channel: Channel, accept?: (contact: VaultysId) => Promise<boolean>) => Promise<null>;
    requestSignFile(channel: Channel, file: File): Promise<FileSignature | undefined>;
    acceptSignFile(channel: Channel, accept?: (contact: VaultysId, file: File) => Promise<boolean>): Promise<void>;
    requestPRF(channel: Channel, appid: string, accept?: (contact: VaultysId) => Promise<boolean>): Promise<Buffer | undefined>;
    acceptPRF(channel: Channel, accept?: (contact: VaultysId, appid: string) => Promise<boolean>): Promise<void>;
    /***************************/
    /***************************/
    listCertificates(): any[];
    startSRP(channel: Channel, protocol: string, service: string, metadata?: Record<string, string>, accept?: (contact: VaultysId) => Promise<boolean>): Promise<Challenger>;
    acceptSRP(channel: Channel, protocol: string, service: string, metadata?: Record<string, string>, accept?: (contact: VaultysId) => Promise<boolean>): Promise<Challenger>;
    saveApp(app: VaultysId, name?: string): void;
    saveContact(contact: VaultysId): void;
    askContact(channel: Channel, metadata?: Record<string, string>, accept?: (contact: VaultysId) => Promise<boolean>): Promise<VaultysId>;
    acceptContact(channel: Channel, metadata?: Record<string, string>, accept?: (contact: VaultysId) => Promise<boolean>): Promise<VaultysId>;
}
