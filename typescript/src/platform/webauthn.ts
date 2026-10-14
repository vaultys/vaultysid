import SoftCredentials from "./SoftCredentials";
import { isSoftCredentialsEnabled } from "./softCredentialsConfig";

export { enableSoftCredentials, isSoftCredentialsEnabled, configureWebAuthn, getWebAuthnExpectations } from "./softCredentialsConfig";

export interface WebAuthnProvider {
  create(options: PublicKeyCredentialCreationOptions): Promise<PublicKeyCredential>;
  get(options: PublicKeyCredentialRequestOptions): Promise<PublicKeyCredential>;
  isAvailable(): boolean;
}

// Browser implementation
export class BrowserWebAuthn implements WebAuthnProvider {
  private origin: string;

  constructor(origin = "test") {
    this.origin = origin;
  }

  isAvailable(): boolean {
    return typeof window !== "undefined" && typeof window.PublicKeyCredential !== "undefined";
  }

  async create(options: PublicKeyCredentialCreationOptions): Promise<PublicKeyCredential> {
    if (!this.isAvailable()) {
      throw new Error("WebAuthn is not available in this environment");
    }
    return (await navigator.credentials.create({ publicKey: options })) as PublicKeyCredential;
  }

  async get(options: PublicKeyCredentialRequestOptions): Promise<PublicKeyCredential> {
    if (!this.isAvailable()) {
      throw new Error("WebAuthn is not available in this environment");
    }
    return (await navigator.credentials.get({ publicKey: options })) as PublicKeyCredential;
  }
}

// Node.js implementation using SoftCredentials
export class NodeWebAuthn implements WebAuthnProvider {
  #origin: string;

  constructor(origin = "test") {
    this.#origin = origin;
  }

  isAvailable(): boolean {
    return true; // Always available in mock mode
  }

  async create(options: PublicKeyCredentialCreationOptions): Promise<PublicKeyCredential> {
    return await SoftCredentials.create(
      {
        publicKey: options,
      },
      this.#origin,
    );
  }

  async get(options: PublicKeyCredentialRequestOptions): Promise<PublicKeyCredential> {
    return await SoftCredentials.get(
      {
        publicKey: options,
      },
      this.#origin,
    );
  }
}

// Factory function
// There is NO silent fallback to the insecure SoftCredentials authenticator:
// outside a browser it is only returned when explicitly enabled with
// enableSoftCredentials(), otherwise this throws.
export function getWebAuthnProvider(options?: { origin?: string }): WebAuthnProvider {
  if (typeof window !== "undefined") {
    return new BrowserWebAuthn();
  }
  if (!isSoftCredentialsEnabled()) {
    throw new Error("WebAuthn is not available in this environment. The insecure SoftCredentials authenticator must be enabled explicitly with enableSoftCredentials()");
  }
  return new NodeWebAuthn(options?.origin);
}

// Helper to create credential request
export function createCredentialRequest(alg: number, prf = false) {
  return SoftCredentials.createRequest(alg, prf);
}
