export declare const serialize: (data: any) => string;
export declare const deserialize: (string: string) => any;
export declare const MemoryStorage: (save: () => void) => Store;
export declare const LocalStorage: (key?: string) => Store;
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
    fromString(string: string, save?: () => void, destroy?: () => void): Store;
};
