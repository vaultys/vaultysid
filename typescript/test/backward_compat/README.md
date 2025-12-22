# Backward Compatibility Tests

This directory contains tests to ensure compatibility between different versions of the `@vaultys/id` library, specifically testing version 2.4.9 against the current version.

## Setup

1. Install dependencies:
```bash
cd typescript/test/backward_compat
npm install
```

2. Install the old version (2.4.9) for testing:
```bash
npm run setup
```

This will install `@vaultys/id@2.4.9` as a dependency.

3. Build the current version:
```bash
cd ../..
npm run build:node
```

## Running Tests

### Run all compatibility tests:
```bash
npm test
```

### Run specific test suites:
```bash
# Run basic compatibility tests
mocha compatibility.test.ts --require tsx

# Run data format tests
mocha data-format.test.ts --require tsx

# Run SRP challenge tests
mocha srp-compatibility.test.ts --require tsx
```

### Watch mode for development:
```bash
npm run test:watch
```

## Test Structure

### `compatibility.test.ts`
- **ID Generation**: Tests that both versions can generate compatible person, organization, and machine IDs
- **Serialization**: Tests import/export compatibility between versions
- **Signing/Verification**: Tests cross-version signature verification
- **Key Derivation**: Tests that derived keys are consistent across versions
- **Encryption/Decryption**: Tests that data encrypted by one version can be decrypted by another
- **DID Methods**: Tests DID format consistency
- **Algorithm Support**: Tests algorithm compatibility (ed25519, dilithium, etc.)

### `data-format.test.ts`
- **Export Format**: Tests consistency of export data structures
- **JSON Schema**: Tests JSON serialization compatibility
- **Binary Data**: Tests handling of binary data across versions
- **Test Vectors**: Generates and validates test vectors for regression testing
- **Channel Data**: Tests channel structure compatibility
- **Key Paths**: Tests various derivation path formats

### `srp-compatibility.test.ts`
- **Cross-version SRP**: Tests SRP challenges between old and new versions
- **Channel Communication**: Tests encrypted channel communication
- **File Operations**: Tests file encryption/decryption between versions
- **Web of Trust**: Tests trust relationship establishment across versions
- **PRF Operations**: Tests pseudorandom function operations
- **Error Handling**: Tests graceful handling of version mismatches

## Expected Results

The tests will identify:
1. ✅ **Compatible features** that work seamlessly between versions
2. ⚠️ **Minor differences** that may require adaptation
3. ❌ **Breaking changes** that prevent interoperability

### Breaking Changes Log

Any detected breaking changes will be logged at the end of test runs. These should be documented in the main CHANGELOG.

## Adding New Tests

When adding new compatibility tests:

1. Import both versions:
```typescript
import { VaultysId as VaultysIdOld } from "@vaultys/id";
import { VaultysId as VaultysIdCurrent } from "../../dist/node/index.js";
```

2. Test bidirectional compatibility:
   - Old → Current (forward compatibility)
   - Current → Old (backward compatibility)

3. Document any version-specific behavior or limitations

## Troubleshooting

### Module Resolution Issues
If you encounter module resolution errors, ensure:
- The current version is built (`npm run build:node` in the main typescript directory)
- The old version is installed (`npm run setup` in this directory)

### Test Failures
Expected failures may occur for:
- New features not available in v2.4.9
- Changed APIs or data formats
- Security improvements that break backward compatibility

These should be documented as breaking changes.

## Updating Test Version

To test against a different version, update the version in `package.json`:

```json
{
  "dependencies": {
    "@vaultys/id": "2.4.9"  // Change this version
  }
}
```

Then run `npm install` to update the dependency.