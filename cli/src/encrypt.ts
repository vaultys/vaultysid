import { VaultysId } from "@vaultys/id";
import { ArgumentsCamelCase } from "yargs";

export async function encryptCommand(argv: ArgumentsCamelCase<{}>): Promise<void> {
  const content = argv.content;
  const recipients = argv.recipients;

  if (typeof content === "string" && Array.isArray(recipients)) {
    try {
      const ids = recipients.map((recipient: string) => VaultysId.fromId(recipient, undefined, "base64").id);
      console.log(await VaultysId.encrypt(content, ids));
    } catch (error) {
      throw new Error(`An error occurred while encrypting the content: ${error}`);
    }
  }
}
