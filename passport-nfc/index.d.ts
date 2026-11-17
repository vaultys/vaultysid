export interface PassportNfcHelperOptions {
  /** Path to the native helper. Defaults to vaultys-passport-nfc on PATH. */
  executable?: string;
  /** Deadline per chip operation. Defaults to 20000 milliseconds. */
  timeoutMs?: number;
}

export interface PassportNfcOptions extends PassportNfcHelperOptions {
  /** The complete printed machine-readable zone of the passport. */
  mrz: string;
  /** Exact PC/SC reader name. Optional when there is exactly one reader. */
  readerName?: string;
}

export function listPassportReaders(options?: PassportNfcHelperOptions): Promise<string[]>;

export function readPassportAA(options: PassportNfcOptions): Promise<{
  dg15: Uint8Array;
  dg14?: Uint8Array;
  reader: (challenges: readonly Uint8Array[], responseLength: number) => Promise<readonly Uint8Array[]>;
}>;
