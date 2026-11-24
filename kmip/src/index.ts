import { connect } from "node:tls";

const Tag = {
  BatchCount: 0x42000d,
  BatchItem: 0x42000f,
  CryptographicAlgorithm: 0x420028,
  CryptographicParameters: 0x42002b,
  Operation: 0x42005c,
  ProtocolVersion: 0x420069,
  ProtocolVersionMajor: 0x42006a,
  ProtocolVersionMinor: 0x42006b,
  RequestHeader: 0x420077,
  RequestMessage: 0x420078,
  RequestPayload: 0x420079,
  ResponseHeader: 0x42007a,
  ResponseMessage: 0x42007b,
  ResponsePayload: 0x42007c,
  ResultMessage: 0x42007d,
  ResultReason: 0x42007e,
  ResultStatus: 0x42007f,
  UniqueIdentifier: 0x420094,
  Data: 0x4200c2,
  SignatureData: 0x4200c3,
} as const;

const Type = { Structure: 1, Integer: 2, Enumeration: 5, TextString: 7, ByteString: 8 } as const;
const SIGN = 0x21;
const ED25519 = 0x37;
const MAX_RESPONSE_SIZE = 64 * 1024;

function ttlv(tag: number, type: number, value: Uint8Array) {
  const item = Buffer.alloc(8 + Math.ceil(value.length / 8) * 8);
  item.writeUIntBE(tag, 0, 3);
  item[3] = type;
  item.writeUInt32BE(value.length, 4);
  item.set(value, 8);
  return item;
}

function numberItem(tag: number, type: number, number: number) {
  const value = Buffer.alloc(4);
  value.writeUInt32BE(number);
  return ttlv(tag, type, value);
}

function structure(tag: number, ...fields: Buffer[]) {
  return ttlv(tag, Type.Structure, Buffer.concat(fields));
}

function signRequest(keyId: string, data: Uint8Array) {
  const protocol = structure(Tag.ProtocolVersion, numberItem(Tag.ProtocolVersionMajor, Type.Integer, 2), numberItem(Tag.ProtocolVersionMinor, Type.Integer, 1));
  const header = structure(Tag.RequestHeader, protocol, numberItem(Tag.BatchCount, Type.Integer, 1));
  const params = structure(Tag.CryptographicParameters, numberItem(Tag.CryptographicAlgorithm, Type.Enumeration, ED25519));
  const payload = structure(Tag.RequestPayload, ttlv(Tag.UniqueIdentifier, Type.TextString, Buffer.from(keyId)), params, ttlv(Tag.Data, Type.ByteString, data));
  return structure(Tag.RequestMessage, header, structure(Tag.BatchItem, numberItem(Tag.Operation, Type.Enumeration, SIGN), payload));
}

function readItems(bytes: Buffer) {
  const items = new Map<number, { type: number; value: Buffer }>();
  for (let offset = 0; offset < bytes.length;) {
    if (bytes.length - offset < 8) throw new Error("Truncated KMIP TTLV header");
    const tag = bytes.readUIntBE(offset, 3);
    const type = bytes[offset + 3];
    const length = bytes.readUInt32BE(offset + 4);
    const next = offset + 8 + Math.ceil(length / 8) * 8;
    if (next > bytes.length) throw new Error("Truncated KMIP TTLV value");
    if (items.has(tag)) throw new Error("Unexpected duplicate KMIP response field");
    items.set(tag, { type, value: bytes.subarray(offset + 8, offset + 8 + length) });
    offset = next;
  }
  return (tag: number, type: number, optional = false): Buffer => {
    const item = items.get(tag);
    if (!item && optional) return Buffer.alloc(0);
    if (item?.type !== type) throw new Error(`Invalid KMIP response field 0x${tag.toString(16)}`);
    if ((type === Type.Integer || type === Type.Enumeration) && item.value.length !== 4) throw new Error("Invalid KMIP numeric field length");
    return item.value;
  };
}

function readSignature(frame: Buffer, keyId: string) {
  const response = readItems(readItems(frame)(Tag.ResponseMessage, Type.Structure));
  const header = readItems(response(Tag.ResponseHeader, Type.Structure));
  if (header(Tag.BatchCount, Type.Integer).readUInt32BE() !== 1) throw new Error("Expected one KMIP batch item");
  const batch = readItems(response(Tag.BatchItem, Type.Structure));
  const status = batch(Tag.ResultStatus, Type.Enumeration).readUInt32BE();
  if (status !== 0) {
    const reason = batch(Tag.ResultReason, Type.Enumeration, true);
    const message = batch(Tag.ResultMessage, Type.TextString, true).toString();
    throw new Error(`KMIP Sign failed (status ${status}${reason.length ? `, reason 0x${reason.toString("hex")}` : ""})${message ? `: ${message}` : ""}`);
  }
  if (batch(Tag.Operation, Type.Enumeration).readUInt32BE() !== SIGN) throw new Error("Unexpected KMIP response operation");
  const payload = readItems(batch(Tag.ResponsePayload, Type.Structure));
  if (!payload(Tag.UniqueIdentifier, Type.TextString).equals(Buffer.from(keyId))) throw new Error("KMIP response key ID does not match the signing key");
  const signature = payload(Tag.SignatureData, Type.ByteString);
  if (signature.length !== 64) throw new Error("KMIP Sign returned an invalid Ed25519 signature length");
  return Buffer.from(signature);
}

export interface KMIPSignerOptions {
  host: string;
  port?: number;
  /** TLS server name for an endpoint reached by IP or through a proxy. */
  servername?: string;
  cert: string | Buffer;
  key: string | Buffer;
  ca?: string | Buffer;
  timeoutMs?: number;
  /** Unique identifier of the existing KMIP private-key object. */
  keyId: string;
  /** Raw 32-byte Ed25519 public key corresponding to keyId, obtained during provisioning. */
  publicKey: Uint8Array;
}

/** Node.js client for KMIP 2.1 PureEd25519 Sign over mutual TLS. */
export class KMIPSigner {
  #options: KMIPSignerOptions;

  constructor(options: KMIPSignerOptions) {
    if (!options.host || !options.keyId || !options.cert?.length || !options.key?.length) throw new Error("KMIP host, key ID, client certificate and key are required");
    if (!(options.publicKey instanceof Uint8Array) || options.publicKey.length !== 32) throw new Error("Expected a raw 32-byte Ed25519 public key");
    const timeoutMs = options.timeoutMs ?? 10_000;
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2_147_483_647) throw new Error("Invalid KMIP timeout");
    this.#options = { ...options, publicKey: Buffer.from(options.publicKey), timeoutMs };
  }

  async getPublicKey(): Promise<Uint8Array> {
    return Buffer.from(this.#options.publicKey);
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    const { host, port = 5696, servername, cert, key, ca, keyId, timeoutMs } = this.#options;
    const request = signRequest(keyId, data);
    const frame = await new Promise<Buffer>((resolve, reject) => {
      const socket = connect({ host, port, servername, cert, key, ca, minVersion: "TLSv1.2", rejectUnauthorized: true });
      const timer = setTimeout(() => socket.destroy(new Error("KMIP Sign timed out")), timeoutMs);
      const response = Buffer.alloc(MAX_RESPONSE_SIZE);
      let received = 0;
      let frameSize: number | undefined;

      socket.once("secureConnect", () => socket.write(request));
      socket.once("error", reject);
      socket.once("close", () => {
        clearTimeout(timer);
        reject(new Error("KMIP connection closed before a complete response"));
      });
      socket.on("data", (chunk: Buffer) => {
        if (received + chunk.length > response.length) {
          socket.destroy(new Error("KMIP response exceeds the size limit"));
          return;
        }
        chunk.copy(response, received);
        received += chunk.length;
        if (frameSize === undefined && received >= 8) {
          frameSize = 8 + response.readUInt32BE(4);
          if (response.readUIntBE(0, 3) !== Tag.ResponseMessage || response[3] !== Type.Structure || frameSize % 8 !== 0 || frameSize > response.length) {
            socket.destroy(new Error("Invalid KMIP response header"));
            return;
          }
        }
        if (frameSize !== undefined && received >= frameSize) {
          if (received === frameSize) {
            resolve(response.subarray(0, frameSize));
            socket.destroy();
          } else {
            socket.destroy(new Error("Unexpected bytes after KMIP response"));
          }
        }
      });
    });
    return readSignature(frame, keyId);
  }
}
