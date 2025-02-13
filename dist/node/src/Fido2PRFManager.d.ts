import Fido2Manager from "./Fido2Manager";
import { Buffer } from "buffer/";
declare global {
    interface Window {
        CredentialUserInteractionRequest: () => Promise<void>;
    }
}
export default class Fido2PRFManager extends Fido2Manager {
    prfsalt: Buffer;
    constructor();
    static createFromAttestation(attestation: PublicKeyCredential): Promise<Fido2PRFManager>;
    getSecret(): Buffer;
    static fromSecret(secret: Buffer): Fido2PRFManager;
    cleanSecureData(): void;
    getCypher(): Promise<{
        hmac: (message: string) => Buffer | undefined;
        signcrypt: (plaintext: string, publicKeys: Buffer[]) => Promise<string>;
        decrypt: (encryptedMessage: string, senderKey?: Buffer | null) => Promise<import("@samuelthomas2774/saltpack").DearmorAndDecryptResult>;
    }>;
    createRevocationCertificate(): Promise<null>;
}
