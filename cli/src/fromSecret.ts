import { VaultysId } from "@vaultys/id";
import { ArgumentsCamelCase } from "yargs";

export function fromSecretCommand(argv: ArgumentsCamelCase<{}>): void {
  const secret = argv.secret;
  const display = argv.display;
  if (typeof secret === "string") {
    const vid = VaultysId.fromSecret(secret, "base64");
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
    } else {
      throw new Error("An error occurred while retrieving the ID.");
    }
  }
}
