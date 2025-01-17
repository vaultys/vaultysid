import { isNode } from "../utils/environment";
import { NodeCrypto } from "./node";
import { BrowserCrypto } from "./browser";
import { IPlatformCrypto } from "./abstract";

export const platformCrypto: IPlatformCrypto = isNode ? new NodeCrypto() : new BrowserCrypto();
