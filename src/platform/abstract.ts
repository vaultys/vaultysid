export interface IPlatformCrypto {
  getRandomValues(buffer: Uint8Array): Promise<Uint8Array>;
  // Add other platform-specific methods
}
