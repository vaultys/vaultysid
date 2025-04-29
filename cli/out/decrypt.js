"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decryptCommand = decryptCommand;
const id_1 = require("@vaultys/id");
async function decryptCommand(argv) {
    const encryptedMessage = argv.encryptedMessage;
    const secret = argv.secret;
    if (typeof encryptedMessage === "string" && typeof secret === "string") {
        const vid = id_1.VaultysId.fromSecret(secret, "base64");
        try {
            console.log(await vid.decrypt(encryptedMessage));
        }
        catch (error) {
            throw new Error(`An error occurred while decrypting the message: ${error}`);
        }
    }
}
