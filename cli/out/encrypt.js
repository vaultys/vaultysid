"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.encryptCommand = encryptCommand;
const id_1 = require("@vaultys/id");
async function encryptCommand(argv) {
    const content = argv.content;
    const recipients = argv.recipients;
    if (typeof content === "string" && Array.isArray(recipients)) {
        try {
            const ids = recipients.map((recipient) => id_1.VaultysId.fromId(recipient, undefined, "base64").id);
            console.log(await id_1.VaultysId.encrypt(content, ids));
        }
        catch (error) {
            throw new Error(`An error occurred while encrypting the content: ${error}`);
        }
    }
}
