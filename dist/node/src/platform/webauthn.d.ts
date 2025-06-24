export interface WebAuthnProvider {
    create(options: PublicKeyCredentialCreationOptions): Promise<PublicKeyCredential>;
    get(options: PublicKeyCredentialRequestOptions): Promise<PublicKeyCredential>;
    isAvailable(): boolean;
}
export declare class BrowserWebAuthn implements WebAuthnProvider {
    private origin;
    constructor(origin?: string);
    isAvailable(): boolean;
    create(options: PublicKeyCredentialCreationOptions): Promise<PublicKeyCredential>;
    get(options: PublicKeyCredentialRequestOptions): Promise<PublicKeyCredential>;
}
export declare class NodeWebAuthn implements WebAuthnProvider {
    #private;
    constructor(origin?: string);
    isAvailable(): boolean;
    create(options: PublicKeyCredentialCreationOptions): Promise<PublicKeyCredential>;
    get(options: PublicKeyCredentialRequestOptions): Promise<PublicKeyCredential>;
}
export declare function getWebAuthnProvider(options?: {
    origin?: string;
}): WebAuthnProvider;
export declare function createCredentialRequest(alg: number, prf?: boolean): CredentialCreationOptions;
