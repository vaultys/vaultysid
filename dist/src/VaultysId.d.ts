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
    static createPublicKeyCredentialOptionsPQC: () => PublicKeyCredentialCreationOptions;
    static createPublicKeyCredentialCreationOptions: (passkey: boolean) => PublicKeyCredentialCreationOptions;
    static fromEntropy(entropy: Buffer, type: number, pqc?: boolean): Promise<VaultysId>;
    static createWebauthn(passkey?: boolean, onPRFEnabled?: () => Promise<boolean>): Promise<VaultysId | null>;
    static createPQC(): Promise<VaultysId | null>;
    static fido2FromAttestation(attestation: PublicKeyCredential, onPRFEnabled?: () => Promise<boolean>): Promise<VaultysId>;
    static machineFromEntropy(entropy: Buffer): Promise<VaultysId>;
    static organizationFromEntropy(entropy: Buffer): Promise<VaultysId>;
    static personFromEntropy(entropy: Buffer): Promise<VaultysId>;
    static fromSecret(secret: string, encoding?: BufferEncoding): VaultysId;
    static generatePerson(pqc?: boolean): Promise<VaultysId>;
    static generateOrganization(pqc?: boolean): Promise<VaultysId>;
    static generateMachine(pqc?: boolean): Promise<VaultysId>;
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
    performDiffieHellman(otherVaultysId: VaultysId): Promise<Buffer | null>;
    /**
     * Static method to perform a Diffie-Hellman key exchange between two VaultysId instances
     * @param vaultysId1 First VaultysId instance
     * @param vaultysId2 Second VaultysId instance
     * @returns A shared secret that both parties can derive
     */
    static diffieHellman(vaultysId1: VaultysId, vaultysId2: VaultysId): Promise<Buffer | null>;
    /**
     * Encrypt a message using DHIES for a recipient
     * @param message Message to encrypt
     * @param recipientId Recipient's VaultysId ID
     * @returns Encrypted message or null if encryption fails
     */
    dhiesEncrypt(message: string | Buffer, recipientId: Buffer | string): Promise<Buffer | null>;
    /**
     * Decrypt a message encrypted with DHIES
     * @param encryptedMessage Encrypted message from dhiesEncrypt
     * @returns Decrypted message as Buffer or null if decryption fails
     */
    dhiesDecrypt(encryptedMessage: Buffer, senderId: Buffer | string): Promise<Buffer | null>;
    signChallenge(challenge: Buffer | string): Promise<Buffer>;
    verifyChallenge(challenge: Buffer | string, signature: Buffer | string, userVerification: boolean): boolean;
    signcrypt(plaintext: string, recipientIds: (Buffer | string)[]): Promise<string>;
    static encrypt(plaintext: string, recipientIds: (Buffer | string)[]): Promise<string>;
    encrypt: typeof VaultysId.encrypt;
    decrypt(encryptedMessage: string, senderId?: Buffer | string): Promise<string>;
    hmac(message: string): Promise<Buffer | undefined>;
}
export {};
