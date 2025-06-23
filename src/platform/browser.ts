import { IPlatformCrypto } from "./abstract";
import { decrypt, encrypt } from "./pbkdf2.web";
import { BrowserWebAuthn } from "./webauthn";

export const BrowserCrypto: IPlatformCrypto = {
  webauthn: new BrowserWebAuthn(),
  pbkdf2: {
    encrypt: encrypt,
    decrypt: decrypt,
  },
};
