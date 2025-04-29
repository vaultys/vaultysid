"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.fromSecretCommand = fromSecretCommand;
const id_1 = require("@vaultys/id");
function fromSecretCommand(argv) {
    const secret = argv.secret;
    const display = argv.display;
    if (typeof secret === "string") {
        const vid = id_1.VaultysId.fromSecret(secret, "base64");
        if (vid) {
            switch (display) {
                case "did":
                    console.log(vid.did);
                    break;
                case "id":
                    console.log(vid.id.toString("base64"));
                    break;
                case "fingerprint":
                    console.log(vid.fingerprint);
                    break;
                default:
                    throw new Error("Invalid display option provided. Please specify 'did'.");
                    break;
            }
        }
        else {
            throw new Error("An error occurred while retrieving the ID.");
        }
    }
}
