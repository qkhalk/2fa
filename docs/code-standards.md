# Code Standards

Last updated: 2026-06-27

## Core Conventions

### Module System
- **Vanilla ES Modules**: The project uses ESM exclusively (no CommonJS, no build frameworks)
- **Shared Domain Logic**: All shared code lives in `lib/` and must be browser-agnostic and extension-agnostic
- **No Framework Dependencies**: The root app and extension are vanilla JavaScript - no React, Vue, or other frameworks

### Build and Bundling
- **esbuild**: Primary build tool for bundling `app.js` → `app.bundle.js` and `extension/popup.js` → `extension/popup.bundle.js`
- **Target Browsers**: Chrome 114+, Safari 16+, Firefox 115+
- **Format**: ESM with no sourcemaps (configured in `scripts/build.mjs`)

## Naming Conventions

### File Naming
- **Kebab-case for files**: `build.mjs`, `generate-icons.mjs`, `otp.test.js`
- **Descriptive names**: Files should clearly indicate their purpose
- **Test files**: Match source with `.test.js` suffix (e.g., `otp.test.js`)

### Code Naming
- **camelCase for functions and variables**: `generateTotp`, `parseOtpAuthUri`, `normalizeEntry`
- **PascalCase for classes**: If classes are introduced, use PascalCase
- **CONSTANTS_UPPER_CASE**: Configuration constants and regex patterns
- **Private prefixes**: Use `_` prefix for internal/private functions

### Storage Keys
- **Descriptive prefixes**: Use app/extension-specific prefixes (`personal_otp_vault_`, `otp_extension_`)
- **Version suffixes**: Always include `_vN` suffix for migration support
- **Clear purpose**: Key name should indicate its content (e.g., `entries_v2`, `encrypted_v1`)

## Lib/ Module Rules

The `lib/` directory contains domain logic shared between the root app and extension. These modules must remain:

### Browser and Extension Agnostic
- **No DOM dependencies**: Cannot rely on browser-specific APIs that differ between contexts
- **No direct storage access**: Must accept storage backend as parameter or use abstracted interface
- **Web Crypto only**: Use Web Crypto API, not Node.js crypto modules
- **No extension-specific APIs**: Avoid `chrome.*` APIs directly

### Export Conventions
- **Named exports**: Use explicit named exports for clarity
- **Single responsibility**: Each module should have a clear, focused purpose
- **Pure functions**: Prefer pure functions that don't rely on external state

### Testing Requirements
- **Unit testable**: All `lib/` code must be testable in Node.js via Vitest
- **No browser-specific mocking**: Tests should not require complex browser environment mocks
- **Clear interfaces**: Functions should have well-defined inputs and outputs

## Storage Backend Abstraction

### Root App (localStorage)
- **Keys**: Prefixed with `personal_otp_vault_`
- **API**: Direct localStorage access
- **Context**: Standard browser environment

### Extension (chrome.storage.local)
- **Keys**: Prefixed with `otp_extension_`
- **API**: Chrome storage API (async, quota-managed)
- **Context**: Extension service worker or popup context

### Shared Pattern
When working with storage in shared code:
- Accept storage interface as parameter
- Use consistent key naming across both platforms
- Handle async differences appropriately
- Maintain version suffixes for migration support

## Adding New Entry Fields

When extending the entry data structure:

1. **Update lib/otp.js**: Modify normalization functions if needed
2. **Update storage version**: Increment the `_vN` suffix in storage keys
3. **Add migration logic**: Handle old → new format conversion
4. **Update tests**: Ensure unit tests cover the new field
5. **Consider extension parity**: Ensure field works in both contexts

## Version Sync Requirements

**Critical**: The project enforces strict version synchronization between `package.json` and `extension/manifest.json`.

### Version Management
- **Single source of truth**: `package.json` version is primary
- **Extension sync**: `extension/manifest.json` version must match exactly
- **Automated verification**: CI fails fast if versions drift
- **Release workflow**: GitHub Actions trigger on extension manifest version change

### Bumping Versions
Use the provided script to bump both files together:
```bash
npm run release:prepare -- <version>
```

### CI/CD Enforcement
- **Build verification**: `.github/workflows/ci.yml` runs version sync check
- **Release gate**: `.github/workflows/release.yml` only triggers on version change
- **Manual trigger**: Can be triggered manually from Actions tab

## Conventional Commits

The project follows Conventional Commits format for all commit messages.

### Format
```
<type>: <description>
```

### Common Types
- `feat`: New feature or functionality
- `fix`: Bug fix or issue resolution
- `docs`: Documentation changes
- `test`: Test additions or modifications
- `build`: Build system or dependency changes
- `chore`: Routine maintenance tasks

### Examples
```
feat: add backup import validation
fix: prevent duplicate OTP entries
docs: update setup instructions
test: add encryption flow coverage
```

### Rules
- **No co-authorship**: Do not include `Co-authored-by:` trailers
- **Present tense**: Use imperative mood ("add" not "added")
- **Lowercase**: Type and description should be lowercase
- **Clear scope**: Description should be specific and concise

## Code Quality Standards

### Web Crypto Usage
- **Always use Web Crypto API**: For all cryptographic operations
- **No external crypto libraries**: Avoid adding crypto dependencies
- **Proper key handling**: Follow best practices for key derivation and storage
- **Algorithm specifications**: Use explicit algorithm parameters (e.g., AES-GCM with specific IV length)

### Error Handling
- **Graceful degradation**: Handle crypto failures appropriately
- **Clear error messages**: Provide actionable error information
- **Validation first**: Validate inputs before processing
- **User feedback**: Show meaningful error messages in UI

### Performance
- **Avoid unnecessary computations**: Cache expensive operations
- **Efficient rendering**: Optimize DOM updates in UI code
- **Reasonable defaults**: Use sensible defaults for algorithms (e.g., PBKDF2 iteration count)

## Contributing Guidelines

### Development Workflow
1. **Create a branch**: From `main` branch
2. **Run tests**: Execute `npm test` before committing
3. **Follow conventions**: Adhere to naming and commit standards
4. **Test thoroughly**: Ensure both unit and E2E tests pass
5. **Document changes**: Update relevant documentation

### Pull Request Requirements
- **Use PR template**: Include required information
- **Screenshots for UI changes**: Provide before/after for visual changes
- **Test coverage**: Ensure new code has appropriate tests
- **Documentation**: Update docs for user-facing changes

### Code Review Principles
- **Maintain shared lib purity**: Keep `lib/` modules agnostic
- **Preserve version sync**: Ensure version fields remain consistent
- **Follow existing patterns**: Match the codebase's established style
- **Consider both contexts**: Ensure changes work in web and extension

## Testing Standards

### Unit Tests (Vitest)
- **Target**: `lib/` modules only
- **Environment**: Node.js with Web Crypto polyfills as needed
- **Coverage**: Focus on domain logic and crypto operations
- **Isolation**: Tests should be independent and deterministic

### E2E Tests (Playwright)
- **Web app**: `tests/e2e/app.spec.js` - core application flows
- **Extension**: `tests/e2e/extension.spec.js` - popup-specific functionality
- **Offline**: `tests/e2e/offline.spec.js` - PWA and service worker behavior
- **Visual**: `tests/e2e/*visual.spec.js` - UI regression testing
- **Safety**: `tests/e2e/app-destructive-backup.spec.js` - backup integrity

### Test Execution
```bash
npm run test:unit    # Vitest unit tests
npm run test:e2e     # Playwright end-to-end tests
npm test            # All tests
```

## Security Considerations

### Cryptographic Standards
- **No custom crypto**: Always use established Web Crypto algorithms
- **Proper parameters**: Use recommended iteration counts and key sizes
- **Secure random**: Use `crypto.getRandomValues()` for randomness
- **No secrets in code**: Never commit keys, passwords, or sensitive data

### Input Validation
- **Strict parsing**: Validate `otpauth://` URIs rigorously
- **Sanitization**: Clean user inputs before processing
- **Length limits**: Enforce reasonable bounds on user data
- **Type checking**: Validate data types before processing

### Storage Security
- **Encryption recommended**: Encourage users to enable encrypted storage
- **Local-first**: No cloud sync or remote storage by design
- **Clear communication**: Explain security implications to users

## Build and Release Standards

### Icon Generation
- **Single source**: `icon.svg` is the source of truth
- **Regenerate after changes**: Run `npm run build:icons` after updating SVG
- **Test outputs**: Verify generated icons in both web and extension contexts

### Release Process
- **Version bump**: Use `npm run release:prepare -- <version>`
- **Automated packaging**: GitHub Actions handles extension packaging
- **Tag creation**: Tags created as `extension-v<version>`
- **GitHub Release**: Automated release with archive attachment

### CI/CD Pipeline
- **Run on PR**: All tests execute on pull requests
- **Main/master protection**: Version checks prevent inconsistent releases
- **Artifact handling**: Playwright reports uploaded on test failures
- **Manual trigger**: Can be initiated from Actions tab for testing

## Documentation Standards

### Code Comments
- **Explain why, not what**: Focus on reasoning, not obvious functionality
- **Keep current**: Update comments when code changes
- **Technical precision**: Use correct terminology for crypto and algorithms
- **No redundancy**: Don't repeat what the code clearly states

### API Documentation
- **Function signatures**: Document parameters, return types, and behavior
- **Examples**: Provide usage examples for complex functions
- **Edge cases**: Document error conditions and special cases
- **References**: Link to relevant specifications (RFC 6238, etc.)

### README and Docs
- **Accurate information**: Keep technical details current
- **Clear instructions**: Provide step-by-step setup guidance
- **Architectural overview**: Explain system design and trade-offs
- **Cross-references**: Link between related documentation files
