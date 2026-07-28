/**
 * Helper module to import both v2.x and v3.x versions of the library
 * Used for backward compatibility testing
 */

// Current version (v3.x)
export { default as VaultysIdV3 } from "../src/VaultysId";

// Legacy version (v2.x) imported via alias
export { default as VaultysIdV2 } from "@vaultys/id_2";
