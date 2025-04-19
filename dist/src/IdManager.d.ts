import { Readable, Writable } from "stream";
import Challenger from "./Challenger";
import KeyManager from "./KeyManager";
import { Channel } from "./MemoryChannel";
import { Store } from "./MemoryStorage";
import VaultysId from "./VaultysId";
import { Buffer } from "buffer/";
export type StoredContact = {
    type: number;
    keyManager: KeyManager;
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
export default class IdManager {
    vaultysId: VaultysId;
    store: Store;
    constructor(vaultysId: VaultysId, store: Store);
    static fromStore(store: Store): Promise<IdManager>;
    merge(otherStore: Store, master?: boolean): void;
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
    decryptFile(toDecrypt: File): Promise<File>;
    encryptFile(toEncrypt: File): Promise<File | null>;
    getSignatures(): {
        date: string;
        payload: any;
        challenge: string;
        type: string;
    }[];
    migrate(version: 0 | 1): void;
    verifyChallenge(challenge: Buffer, signature: Buffer): Promise<boolean>;
    sync(channel: Channel, initiator?: boolean): Promise<void>;
    upload(channel: Channel, stream: Readable): Promise<void>;
    download(channel: Channel, stream: Writable): Promise<void>;
    requestDecrypt(channel: Channel, toDecrypt: Buffer): Promise<Buffer | null | undefined>;
    acceptDecrypt(channel: Channel, accept?: (contact: VaultysId) => Promise<boolean>): Promise<void>;
    requestDecryptFile(channel: Channel, toDecrypt: File): Promise<File>;
    requestEncryptFile(channel: Channel, toEncrypt: File): Promise<File | null>;
    acceptDecryptFile(channel: Channel, accept?: (contact: VaultysId) => Promise<boolean>): Promise<null>;
    acceptEncryptFile: (channel: Channel, accept?: (contact: VaultysId) => Promise<boolean>) => Promise<null>;
    requestSignFile(channel: Channel, file: File): Promise<FileSignature | undefined>;
    acceptSignFile(channel: Channel, accept?: (contact: VaultysId, file: File) => Promise<boolean>): Promise<void>;
    requestPRF(channel: Channel, appid: string): Promise<Buffer | undefined>;
    acceptPRF(channel: Channel, accept?: (contact: VaultysId, appid: string) => Promise<boolean>): Promise<void>;
    /***************************/
    /***************************/
    listCertificates(): any[];
    startSRP(channel: Channel, protocol: string, service: string, metadata?: Record<string, string>): Promise<Challenger>;
    acceptSRP(channel: Channel, protocol: string, service: string, metadata?: Record<string, string>): Promise<Challenger>;
    saveApp(app: VaultysId, name?: string): void;
    saveContact(contact: VaultysId): void;
    askContact(channel: Channel, metadata?: Record<string, string>): Promise<VaultysId>;
    acceptContact(channel: Channel, metadata?: Record<string, string>): Promise<VaultysId>;
    askMyself(channel: Channel): Promise<boolean>;
    acceptMyself(channel: Channel): Promise<boolean>;
}
