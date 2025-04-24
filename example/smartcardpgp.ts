import VaultysId from "../src/VaultysId";

async function main() {
  console.log("connecting PGP smartcard");

  const vaultysId = await VaultysId.createPIV("123456");
  console.log(vaultysId.fingerprint, vaultysId.didDocument);
  console.log(vaultysId.keyManager);
}

main();
