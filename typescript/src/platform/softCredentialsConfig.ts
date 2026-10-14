/**
 * Runtime configuration for WebAuthn handling.
 *
 * SoftCredentials is an INSECURE software authenticator meant for tests. It is
 * never used implicitly: it must be enabled explicitly with
 * `enableSoftCredentials()`, otherwise every attempt to use it throws.
 */

let softCredentialsEnabled = false;

export type WebAuthnExpectations = {
  /** expected relying party id; when set, assertion rpIdHash must equal SHA-256(rpId) */
  rpId?: string;
  /** expected origin; when set, clientDataJSON.origin must match exactly */
  origin?: string;
};

let expectations: WebAuthnExpectations = {};

/** Explicitly allow the insecure software authenticator (tests / non-browser tooling only). */
export function enableSoftCredentials(enabled = true) {
  softCredentialsEnabled = enabled;
}

export function isSoftCredentialsEnabled() {
  return softCredentialsEnabled;
}

export function assertSoftCredentialsEnabled() {
  if (!softCredentialsEnabled) {
    throw new Error("SoftCredentials is an insecure software authenticator and is disabled. Call enableSoftCredentials() explicitly (tests only) to use it.");
  }
}

/** Configure the expected rpId / origin checked when verifying WebAuthn assertions. */
export function configureWebAuthn(config: WebAuthnExpectations) {
  expectations = { ...config };
}

export function getWebAuthnExpectations(): WebAuthnExpectations {
  return expectations;
}
