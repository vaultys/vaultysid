import KeyManager from "./KeyManager";
import { Buffer } from "buffer/";
type StringifiedBuffer = {
    data: number[];
    type: "Buffer";
};
export default class VaultysId {
    type: number;
    keyManager: KeyManager;
    certificate?: Buffer;
    constructor(keyManager: KeyManager, certificate?: Buffer, type?: number);
    static fromId(id: StringifiedBuffer | Buffer | Uint8Array | string, certificate?: Buffer, encoding?: BufferEncoding): VaultysId;
    static createPublicKeyCredentialCreationOptions: (passkey: boolean) => PublicKeyCredentialCreationOptions;
    static fromEntropy(entropy: Buffer, type: number): Promise<VaultysId>;
    static createWebauthn(passkey?: boolean, onPRFEnabled?: () => Promise<boolean>): Promise<VaultysId | null>;
    static fido2FromAttestation(attestation: PublicKeyCredential, onPRFEnabled?: () => Promise<boolean>): Promise<VaultysId>;
    static machineFromEntropy(entropy: Buffer): Promise<VaultysId>;
    static organizationFromEntropy(entropy: Buffer): Promise<VaultysId>;
    static personFromEntropy(entropy: Buffer): Promise<VaultysId>;
    static fromSecret(secret: string, encoding?: BufferEncoding): VaultysId;
    static generatePerson(): Promise<VaultysId>;
    static generateOrganization(): Promise<VaultysId>;
    static generateMachine(): Promise<VaultysId>;
    get relationshipCertificate(): Buffer | undefined;
    getSecret(encoding?: BufferEncoding): string;
    get fingerprint(): string;
    get did(): string;
    get didDocument(): {
        "@context": string[];
        id: string;
        authentication: {
            id: string;
            type: string;
            controller: string;
            publicKeyMultibase: string;
        }[];
        keyAgreement: {
            id: string;
            type: string;
            controller: string;
            publicKeyMultibase: string;
        }[];
    };
    get id(): Buffer;
    toVersion(v: 0 | 1): this;
    get version(): 0 | 1;
    isHardware(): boolean;
    isMachine(): boolean;
    isPerson(): boolean;
    getOTPHmac(timelock?: number): string;
    getOTP(prefix?: string, timelock?: number): string;
    signChallenge(challenge: Buffer | string): Promise<Buffer>;
    verifyChallenge(challenge: Buffer | string, signature: Buffer | string, userVerification: boolean): boolean;
    signcrypt(plaintext: string, recipientIds: (Buffer | string)[]): Promise<string>;
    static encrypt(plaintext: string, recipientIds: (Buffer | string)[]): Promise<string>;
    encrypt: typeof VaultysId.encrypt;
    decrypt(encryptedMessage: string, senderId?: Buffer | string): Promise<string>;
    hmac(message: string): Promise<Buffer | undefined>;
}
export {};
