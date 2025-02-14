// Polyfill for Symbol.dispose
if (typeof Symbol.dispose === "undefined") {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  Symbol.dispose = Symbol("Symbol.dispose");
}


// nodejs polyfill
import SoftCredentials from "../src/platform/SoftCredentials";
if (typeof window !== "undefined") {
  window.global = window;
  // @ts-ignore
  window.process = { env: {} };
} else {
  if (global.navigator) {
    // node > 20
    // @ts-ignore
    global.navigator.credentials = SoftCredentials;
  } else {
    // node <= 20
    // @ts-ignore
    global.navigator = {
      // @ts-ignore
      credentials: SoftCredentials,
    };
  }
}

if (!global.atob) global.atob = (str: string) => Buffer.from(str, "base64").toString("latin1");
if (!global.btoa) global.btoa = (str: string) => Buffer.from(str, "latin1").toString("base64");

// @ts-ignore
global.CredentialUserInteractionRequest = () => global.CredentialUserInteractionRequested++;
