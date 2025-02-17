import { WebAuthnProvider } from "./platform/webauthn";
import KeyManager from "./KeyManager";
import { Buffer } from "buffer/";
declare global {
    interface Window {
        CredentialUserInteractionRequest: () => Promise<void>;
    }
}
export default class Fido2Manager extends KeyManager {
    webAuthn: WebAuthnProvider;
    fid: Buffer;
    _transports: number;
    ckey: Buffer;
    constructor();
    get transports(): AuthenticatorTransport[];
    static createFromAttestation(attestation: PublicKeyCredential): Promise<Fido2Manager>;
    get id(): Buffer;
    get id_v0(): Buffer;
    getSecret(): Buffer;
    static fromSecret(secret: Buffer): Fido2Manager;
    static instantiate(obj: any): Fido2Manager;
    static fromId(id: Buffer): Fido2Manager;
    getSigner(): Promise<{
        sign: (data: Buffer) => Promise<Buffer | null>;
    }>;
    verify(data: Buffer, signature: Buffer | Uint8Array, userVerification?: boolean): boolean;
    verifyCredentials(credentials: PublicKeyCredential, userVerification?: boolean): boolean;
    createRevocationCertificate(): Promise<null>;
}
