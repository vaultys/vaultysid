import { VaultysId } from "@vaultys/id";
import { ArgumentsCamelCase } from "yargs";

export async function generateCommand(argv: ArgumentsCamelCase<{}>): Promise<void> {
  try {
    let id: VaultysId | undefined;
    const type = argv.type as string;
    switch (type) {
      case "person":
        id = await VaultysId.generatePerson();
        break;
      case "machine":
        id = await VaultysId.generateMachine();
        break;
      case "organization":
        id = await VaultysId.generateOrganization();
        break;
      default:
        throw new Error("Invalid type provided. Please specify 'machine', 'person', or 'organization'.");
    }

    if (id) {
      console.log(id.getSecret("base64"));
    } else {
      throw new Error("An error occurred while generating the ID.");
    }
  } catch (error) {
    throw new Error(`An error occurred while generating the ID: ${error}`);
  }
}
