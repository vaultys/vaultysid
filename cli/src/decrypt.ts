import { VaultysId } from "@vaultys/id";
import { ArgumentsCamelCase } from "yargs";

export async function decryptCommand(argv: ArgumentsCamelCase<{}>): Promise<void> {
  const encryptedMessage = argv.encryptedMessage;
  const secret = argv.secret;

  if (typeof encryptedMessage === "string" && typeof secret === "string") {
    const vid = VaultysId.fromSecret(secret, "base64");

    try {
      console.log(await vid.decrypt(encryptedMessage));
    } catch (error) {
      throw new Error(`An error occurred while decrypting the message: ${error}`);
    }
  }
}
