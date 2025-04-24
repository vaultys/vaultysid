import { Challenger, crypto, VaultysId } from "@vaultys/id";
import { ArgumentsCamelCase } from "yargs";

const replacer = (key: string, value: any) => {
  if (value.type === "Buffer") {
    return Buffer.from(value.data).toString("base64");
  }
  return value;
};

export function deserializeCommand(argv: ArgumentsCamelCase<{}>): void {
  const data = argv.data;
  if (typeof data === "string") {
    const cert = Challenger.deserializeCertificate(crypto.Buffer.from(data, "base64"));
    if (!cert) throw new Error("An error occurred while deserializing the certificate");
    cert.pk1 = cert.pk1 ? VaultysId.fromId(cert.pk1).toVersion(1).id : cert.pk1;
    cert.pk2 = cert.pk2 ? VaultysId.fromId(cert.pk2).toVersion(1).id : cert.pk2;
    console.log(Buffer.from(JSON.stringify(cert, replacer), "utf-8").toString("base64"));
  }
}
