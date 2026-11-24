import { execFile } from "node:child_process";

const DEFAULT_EXECUTABLE = "vaultys-passport-nfc";

function callHelper({ executable = DEFAULT_EXECUTABLE, timeoutMs = 20_000 }, request) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2_147_483_647) throw new Error("Invalid passport reader timeout");
  return new Promise((resolve, reject) => {
    const child = execFile(executable, [], { timeout: timeoutMs, maxBuffer: 256 * 1024, windowsHide: true }, (error, stdout, stderr) => {
      if (error?.code === "ENOENT") {
        reject(new Error(`Passport NFC helper was not found: ${executable}`));
      } else if (error?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") {
        reject(new Error("Passport NFC helper exceeded the output limit"));
      } else if (error?.killed) {
        reject(new Error("Passport NFC operation timed out"));
      } else if (error) {
        const reason = stderr.trim().slice(0, 300);
        reject(new Error(reason ? `Passport NFC: ${reason}` : "Passport NFC helper failed"));
      } else {
        try {
          resolve(JSON.parse(stdout));
        } catch {
          reject(new Error("Invalid passport NFC helper response"));
        }
      }
    });
    // The process callback reports exit failure if the helper closed stdin.
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(request));
  });
}

function decodeBytes(value, field, maxLength) {
  if (typeof value !== "string" || value.length > Math.ceil(maxLength / 3) * 4) throw new Error(`Invalid passport NFC ${field}`);
  const bytes = Buffer.from(value, "base64");
  if (bytes.length === 0 || bytes.length > maxLength || bytes.toString("base64") !== value) throw new Error(`Invalid passport NFC ${field}`);
  return bytes;
}

export async function listPassportReaders(options = {}) {
  const reply = await callHelper(options, { operation: "list" });
  if (!Array.isArray(reply?.readers) || reply.readers.some((reader) => typeof reader !== "string")) throw new Error("Invalid passport NFC reader list");
  return reply.readers;
}

export async function readPassportAA({ mrz, readerName, executable, timeoutMs }) {
  if (typeof mrz !== "string" || !mrz.trim() || Buffer.byteLength(mrz) > 256) throw new Error("A valid passport MRZ is required");
  const options = { executable, timeoutMs };
  const reply = await callHelper(options, { operation: "read", mrz, reader: readerName });
  const reader = reply?.reader;
  if (typeof reader !== "string" || !reader) throw new Error("Invalid passport NFC reader name");
  const dg15 = decodeBytes(reply.dg15, "DG15", 1024);
  const dg14 = reply.dg14 === undefined ? undefined : decodeBytes(reply.dg14, "DG14", 65_539);
  // Use the same selected reader. Each signature opens a new chip session.
  let pending = Promise.resolve();
  return {
    dg15,
    dg14,
    reader: (challenges, responseLength) => {
      const request = { operation: "sign", mrz, reader, challenges: challenges.map((bytes) => Buffer.from(bytes).toString("base64")), responseLength };
      const operation = pending.then(async () => {
        const result = await callHelper(options, request);
        if (!Array.isArray(result?.signatures) || result.signatures.length !== request.challenges.length) throw new Error("Invalid passport NFC signature count");
        return result.signatures.map((value) => {
          const bytes = decodeBytes(value, "signature", responseLength);
          if (bytes.length !== responseLength) throw new Error("Invalid passport NFC signature length");
          return bytes;
        });
      });
      pending = operation.catch(() => {});
      return operation;
    },
  };
}
