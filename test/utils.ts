// nodejs polyfill

import SoftCredentials from "../src/SoftCredentials";

// @ts-ignore
global.navigator = {
  // @ts-ignore
  credentials: SoftCredentials,
};
global.atob = (str: string) => Buffer.from(str, "base64").toString("latin1");
global.btoa = (str: string) => Buffer.from(str, "latin1").toString("base64");

// @ts-ignore
global.CredentialUserInteractionRequest = () => global.CredentialUserInteractionRequested++;
