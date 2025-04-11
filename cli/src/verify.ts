import { crypto, VaultysId } from "@vaultys/id";
import { ArgumentsCamelCase } from "yargs";

export async function verifyCommand(argv: ArgumentsCamelCase<{}>): Promise<void> {
  const content = argv.content;
  const signature = argv.signature;
  const id = argv.id;

  if (typeof content === "string" && typeof id === "string" && typeof signature === "string") {
    try {
      const vid = VaultysId.fromId(Buffer.from(id, "base64"));
      console.log(vid.verifyChallenge(crypto.Buffer.from(content, "base64"), crypto.Buffer.from(signature, "base64"), true));
    } catch (error) {
      throw new Error(`An error occurred while signing the content: ${error}`);
    }
  }
}
