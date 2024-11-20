/// <reference types="node" />
type SoftKeyPair = {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
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
    static getCertificateInfo(response: AuthenticatorAttestationResponse): {
        issuer: string;
        issuerName: string;
        subject: Record<string, string>;
        version: string;
        basicConstraintsCA: boolean;
    } | null;
    static create(options: CredentialCreationOptions, origin?: string): Promise<PublicKeyCredential>;
    static simpleVerify(COSEPublicKey: Buffer, response: AuthenticatorAssertionResponse, userVerification?: boolean): boolean;
    static getCOSEPublicKey(attestation: PublicKeyCredential): Buffer | undefined;
    static verifyPackedAttestation(attestation: AuthenticatorAttestationResponse, userVerification?: boolean): Promise<boolean>;
    static verify(attestation: PublicKeyCredential, assertion: PublicKeyCredential, userVerifiation?: boolean): boolean | undefined;
    static extractChallenge(clientDataJSON: Buffer): any;
    static get({ publicKey }: {
        publicKey: PublicKeyCredentialRequestOptions;
    }, origin?: string): Promise<PublicKeyCredential>;
}
export {};
