"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateCommand = generateCommand;
const id_1 = require("@vaultys/id");
async function generateCommand(argv) {
    try {
        let id;
        const type = argv.type;
        switch (type) {
            case "person":
                id = await id_1.VaultysId.generatePerson();
                break;
            case "machine":
                id = await id_1.VaultysId.generateMachine();
                break;
            case "organization":
                id = await id_1.VaultysId.generateOrganization();
                break;
            default:
                throw new Error("Invalid type provided. Please specify 'machine', 'person', or 'organization'.");
        }
        if (id) {
            console.log(id.getSecret("base64"));
        }
        else {
            throw new Error("An error occurred while generating the ID.");
        }
    }
    catch (error) {
        throw new Error(`An error occurred while generating the ID: ${error}`);
    }
}
