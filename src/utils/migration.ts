import { decode, encode } from "@msgpack/msgpack";
import { Buffer } from "../crypto";

export function migrateVaultysId(oldVid: Buffer) {
  const data = decode(oldVid.slice(1)) as { p: Buffer; x?: Buffer };
  if (data.x?.length === 96) data.x = data.x.slice(0, 32);
  data.p = Buffer.from([]);
  return Buffer.concat([oldVid.slice(0, 1), encode(data)]);
}
