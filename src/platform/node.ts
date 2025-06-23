import { IPlatformCrypto } from "./abstract";
import { decrypt, encrypt } from "./pbkdf2.node";
import { NodeWebAuthn } from "./webauthn";

export const NodeCrypto: IPlatformCrypto = {
  webauthn: new NodeWebAuthn(),
  pbkdf2: {
    encrypt: encrypt,
    decrypt: decrypt,
  },
};
