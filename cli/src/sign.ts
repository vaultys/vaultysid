import { crypto, VaultysId } from "@vaultys/id";
import { ArgumentsCamelCase } from "yargs";

export async function signCommand(argv: ArgumentsCamelCase<{}>): Promise<void> {
  const content = argv.content;
  const secret = argv.secret;

  if (typeof content === "string" && typeof secret === "string") {
    try {
      const vid = VaultysId.fromSecret(secret, "base64");
      console.log((await vid.signChallenge(crypto.Buffer.from(content, "base64"))).toString("base64"));
    } catch (error) {
      throw new Error(`An error occurred while signing the content: ${error}`);
    }
  }
}
