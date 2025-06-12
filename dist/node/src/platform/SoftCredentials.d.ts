import { Buffer } from "buffer/";
type SoftKeyPair = {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    algorithm?: string;
    isDILITHIUM?: boolean;
};
export default class SoftCredentials {
    signCount: number;
    rawId: Buffer;
    aaguid: Buffer;
    challenge: Buffer;
    options: PublicKeyCredentialCreationOptions;
    rpId: string;
    userHandle: Buffer;
    alg: number;
    keyPair: SoftKeyPair;
    coseKey: Map<number, number | Uint8Array>;
    constructor();
    static createRequest(alg: number, prf?: boolean): CredentialCreationOptions;
    static create(options: CredentialCreationOptions, origin?: string): Promise<PublicKeyCredential>;
    static simpleVerify(COSEPublicKey: Buffer, response: AuthenticatorAssertionResponse, userVerification?: boolean): boolean;
    static getCOSEPublicKey(attestation: PublicKeyCredential): Buffer | undefined;
    static verifyPackedAttestation(attestation: AuthenticatorAttestationResponse, userVerification?: boolean): boolean;
    static verify(attestation: PublicKeyCredential, assertion: PublicKeyCredential, userVerifiation?: boolean): Promise<boolean>;
    static extractChallenge(clientDataJSON: ArrayBuffer): any;
    static get({ publicKey }: {
        publicKey: PublicKeyCredentialRequestOptions;
    }, origin?: string): Promise<PublicKeyCredential>;
}
export {};
