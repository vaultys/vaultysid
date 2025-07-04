export declare const serialize: (data: any) => string;
export declare const deserialize: (string: string) => any;
export declare const MemoryStorage: (save?: () => void) => Store;
export declare const LocalStorage: (key?: string) => Store;
export declare const MessagePackStorage: (key?: string) => Store;
declare class IStore implements Store {
    _raw: Record<string, object>;
    constructor(object: Record<string, object>);
    save(): void;
    destroy(): void;
    toString(): string;
    toJSON(): object;
    fromJSON(object: object, s: () => void, d: () => void): IStore;
    fromString(string: string, s: () => void, d: () => void): IStore;
    set(key: string, value: any): void;
    delete(key: string): void;
    get(key: string): object;
    list(): string[];
    listSubstores(): string[];
    deleteSubstore(key: string): void;
    renameSubstore(oldname: string, newname: string): void;
    substore(key: string): IStore;
}
export declare class MemoryStore extends IStore {
}
export declare class MessagePackStore extends IStore {
}
export declare const storagify: (jsonObject: Record<string, any>, save?: () => void, destroy?: () => void) => Store;
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
export {};
