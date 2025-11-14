# Publishing VaultysId to crates.io

This guide covers the steps to publish the VaultysId Rust crate to crates.io.

## Pre-Publication Checklist

### 1. Code Quality
- [ ] All tests pass: `cargo test --all-features`
- [ ] No clippy warnings: `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] Code is formatted: `cargo fmt -- --check`
- [ ] Documentation builds: `cargo doc --no-deps --all-features`
- [ ] Examples compile and run: `cargo run --example basic_usage`
- [ ] Benchmarks run: `cargo bench --no-run`

### 2. Security
- [ ] Run security audit: `cargo audit`
- [ ] No sensitive data in code (API keys, passwords, etc.)
- [ ] All debug print statements removed
- [ ] Dependencies are up to date: `cargo update`

### 3. Documentation
- [ ] README.md is up to date
- [ ] CHANGELOG.md entry for new version
- [ ] All public APIs have documentation comments
- [ ] Examples demonstrate key features
- [ ] License file is present and correct

### 4. Version Management
- [ ] Version in Cargo.toml is updated
- [ ] Version follows semantic versioning
- [ ] Breaking changes documented in CHANGELOG.md
- [ ] Git tag matches version (e.g., `rust-v0.1.0` or `v0.1.0`)

### 5. Package Verification
- [ ] Dry run succeeds: `cargo publish --dry-run`
- [ ] Package size is reasonable (check output of dry run)
- [ ] All intended files are included
- [ ] No unnecessary files are included

## Publishing Steps

### 1. Final Verification
```bash
# Navigate to rust directory
cd rust

# Run all tests
cargo test --all-features

# Check formatting
cargo fmt -- --check

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings

# Build documentation
cargo doc --no-deps --all-features --open

# Verify package
cargo package --list
cargo publish --dry-run
```

### 2. Update Version
Edit `Cargo.toml`:
```toml
[package]
version = "0.1.0"  # Update this
```

### 3. Update CHANGELOG.md
Add entry for the new version with:
- Release date
- Added features
- Changed behavior
- Deprecated features
- Removed features
- Fixed bugs
- Security updates

### 4. Commit Changes
```bash
git add Cargo.toml CHANGELOG.md
git commit -m "chore: bump version to v0.1.0"
```

### 5. Create Git Tag
```bash
# For Rust-specific releases
git tag -a rust-v0.1.0 -m "Release version 0.1.0"

# Or for general releases
git tag -a v0.1.0 -m "Release version 0.1.0"

# Push tag to trigger CI/CD
git push origin rust-v0.1.0
```

### 6. Manual Publishing (if CI/CD is not set up)

#### Prerequisites
1. Create account on https://crates.io
2. Login to crates.io: `cargo login`
3. Save your API token securely

#### Publish
```bash
# Final verification
cargo publish --dry-run

# Actual publish
cargo publish
```

### 7. Post-Publication

#### Verify Publication
```bash
# Check it appears on crates.io (may take a few minutes)
cargo search vaultysid

# Test installation in a new project
cargo new test-vaultysid
cd test-vaultysid
echo 'vaultysid = "0.1.0"' >> Cargo.toml
cargo build
```

#### Update Documentation
- [ ] Check docs.rs build: https://docs.rs/vaultysid
- [ ] Update GitHub release notes if using GitHub releases
- [ ] Announce release (if applicable)

## Automated Publishing with GitHub Actions

If GitHub Actions are configured (see `.github/workflows/rust-release.yml`):

1. **Set up secrets in GitHub repository settings:**
   - `CRATES_IO_TOKEN`: Your crates.io API token

2. **Create a release:**
   ```bash
   # Tag and push
   git tag -a rust-v0.1.0 -m "Release version 0.1.0"
   git push origin rust-v0.1.0
   ```

3. **Monitor the release:**
   - Check Actions tab in GitHub
   - Verify release artifacts are uploaded
   - Confirm publication to crates.io

## Troubleshooting

### Common Issues

1. **"crate version already exists"**
   - You cannot republish the same version
   - Bump version number and try again
   - Consider yanking if seriously broken: `cargo yank --vers 0.1.0`

2. **"package size is too large"**
   - Check your `exclude` patterns in Cargo.toml
   - Remove unnecessary files (build artifacts, large test files)
   - Consider moving large assets to a separate repository

3. **"missing required metadata"**
   - Ensure all required fields in Cargo.toml are filled
   - Check: description, license, repository, documentation

4. **Documentation fails to build on docs.rs**
   - Test with: `RUSTDOCFLAGS="--cfg docsrs" cargo doc --all-features`
   - Check feature flags compatibility
   - Ensure all dependencies are available on crates.io

### Yanking a Version

If you need to prevent new users from downloading a broken version:

```bash
# Yank a specific version (existing users can still use it)
cargo yank --vers 0.1.0

# Un-yank if needed
cargo yank --vers 0.1.0 --undo
```

## Version Numbering Guidelines

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0): Incompatible API changes
- **MINOR** (0.1.0): Add functionality (backwards compatible)
- **PATCH** (0.0.1): Bug fixes (backwards compatible)

### Pre-release versions
- Alpha: `0.1.0-alpha.1`
- Beta: `0.1.0-beta.1`
- Release Candidate: `0.1.0-rc.1`

## Maintenance

### Regular Tasks
- **Weekly**: Run `cargo audit` for security vulnerabilities
- **Monthly**: Update dependencies with `cargo update`
- **Quarterly**: Review and update documentation
- **As needed**: Respond to issues and pull requests

### Deprecation Process
1. Mark deprecated items with `#[deprecated]` attribute
2. Document migration path in deprecation notice
3. Maintain for at least 2 minor versions
4. Remove in next major version

## Support

For issues or questions about publishing:
1. Check the [Cargo Book](https://doc.rust-lang.org/cargo/reference/publishing.html)
2. Visit [crates.io help](https://crates.io/help)
3. Open an issue in the repository