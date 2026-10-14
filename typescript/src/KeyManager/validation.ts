import { decode } from "@msgpack/msgpack";
import { Buffer } from "buffer/";

/**
 * Helpers to parse untrusted serialized ids / secrets without ever throwing
 * anything other than a plain, descriptive Error (no TypeError on undefined, no
 * silent out-of-range slicing).
 */

export const isBytes = (value: unknown): value is Uint8Array => value instanceof Uint8Array;

export const requireBytes = (value: unknown, name: string, length?: number): Buffer => {
  if (!isBytes(value)) throw new Error(`Invalid ${name}: expected bytes`);
  if (length !== undefined && value.length !== length) throw new Error(`Invalid ${name}: expected ${length} bytes, got ${value.length}`);
  return Buffer.from(value);
};

export const decodeRecord = (data: Uint8Array, name: string): Record<string, unknown> => {
  let decoded: unknown;
  try {
    decoded = decode(data);
  } catch (error) {
    throw new Error(`Invalid ${name}: malformed encoding`);
  }
  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded) || isBytes(decoded)) {
    throw new Error(`Invalid ${name}: expected a map`);
  }
  return decoded as Record<string, unknown>;
};

export const readVersion = (value: unknown): 0 | 1 => {
  if (value === undefined || value === null || value === 0) return 0;
  if (value === 1) return 1;
  throw new Error("Invalid version");
};
