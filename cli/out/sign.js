"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.signCommand = signCommand;
const id_1 = require("@vaultys/id");
async function signCommand(argv) {
    const content = argv.content;
    const secret = argv.secret;
    if (typeof content === "string" && typeof secret === "string") {
        try {
            const vid = id_1.VaultysId.fromSecret(secret, "base64");
            console.log((await vid.signChallenge(id_1.crypto.Buffer.from(content, "base64"))).toString("base64"));
        }
        catch (error) {
            throw new Error(`An error occurred while signing the content: ${error}`);
        }
    }
}
