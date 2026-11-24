/** An external signer that returns raw Ed25519 public keys and signatures. */
export interface Ed25519Signer {
  getPublicKey(): Promise<Uint8Array>;
  /** Sign the supplied bytes with PureEd25519 as-is, using no extra prehash or context. */
  sign(data: Uint8Array): Promise<Uint8Array>;
}
