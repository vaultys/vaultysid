"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyCommand = verifyCommand;
const id_1 = require("@vaultys/id");
async function verifyCommand(argv) {
    const content = argv.content;
    const signature = argv.signature;
    const id = argv.id;
    if (typeof content === "string" && typeof id === "string" && typeof signature === "string") {
        try {
            const vid = id_1.VaultysId.fromId(Buffer.from(id, "base64"));
            console.log(vid.verifyChallenge(id_1.crypto.Buffer.from(content, "base64"), id_1.crypto.Buffer.from(signature, "base64"), true));
        }
        catch (error) {
            throw new Error(`An error occurred while signing the content: ${error}`);
        }
    }
}
