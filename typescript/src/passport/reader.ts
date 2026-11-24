import { Buffer } from "buffer/";

/** Run Active Authentication for each challenge in order in one reader session. */
export type PassportAAReader = (challenges: readonly Uint8Array[], responseLength: number) => Promise<readonly Uint8Array[]>;

/**
 * Adapt a selected passport session to Active Authentication. The transceiver
 * wraps and unwraps secure messaging when needed and handles APDU continuation.
 * It returns the plaintext response data followed by SW1 and SW2.
 */
export function createPassportAAReader(transceive: (command: Uint8Array) => Promise<Uint8Array>, extendedLength = false): PassportAAReader {
  let pending: Promise<unknown> = Promise.resolve();
  return (challenges, responseLength) => {
    const copiedChallenges = challenges.map((challenge) => {
      if (challenge.length !== 8) throw new Error("Passport AA requires eight-byte challenges");
      return Buffer.from(challenge);
    });
    const extended = extendedLength || responseLength > 256;
    const header = Buffer.from(extended ? [0x00, 0x88, 0x00, 0x00, 0x00, 0x00, 0x08] : [0x00, 0x88, 0x00, 0x00, 0x08]);
    const le = Buffer.alloc(extended ? 2 : 1);
    // Serialize access to the session and its secure messaging counters.
    const operation = pending.then(async () => {
      const responses: Uint8Array[] = [];
      for (const challenge of copiedChallenges) {
        const response = Buffer.from(await transceive(Buffer.concat([header, challenge, le])));
        if (response.length < 2) throw new Error("Missing passport AA response status");
        const status = response.readUInt16BE(response.length - 2);
        if (status !== 0x9000) throw new Error(`Passport AA failed (status 0x${status.toString(16)})`);
        if (response.length !== responseLength + 2) throw new Error("Unexpected passport AA response length");
        responses.push(response.subarray(0, -2));
      }
      return responses;
    });
    pending = operation.catch(() => {});
    return operation;
  };
}
