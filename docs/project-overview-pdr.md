# Product Overview and Development Requirements

Last updated: 2026-06-27

## Product Purpose

Personal OTP Vault is a local-first, privacy-focused Time-based One-Time Password (TOTP) manager designed for trusted personal devices. It provides secure 2FA code generation without cloud dependencies, emphasizing user privacy, offline capability, and cross-platform accessibility through both a Progressive Web App (PWA) and a Chrome-compatible browser extension.

## Target Users

### Primary User Profile
- **Security-conscious individuals** who prefer local-first solutions over cloud-synced alternatives
- **Privacy-focused users** who want complete control over their 2FA credentials
- **Multi-platform users** who need OTP access across browsers and devices
- **Offline-first users** who require reliable access without internet connectivity

### Use Context
- **Trusted personal devices**: Phones, tablets, computers controlled by the user
- **Personal 2FA management**: Individual use, not team or enterprise sharing
- **Cross-platform workflows**: Desktop browser usage, mobile browser access
- **Backup and recovery**: Users who want encrypted local backups

## Product Goals

### Core Objectives
1. **Privacy-First Architecture**
   - No cloud sync or remote data storage
   - All operations performed locally on the user's device
   - User controls encryption and backup strategies

2. **Local-First Design**
   - Full functionality without internet connectivity
   - Progressive Web App for offline access
   - Service worker caching for instant loading

3. **Dual Platform Support**
   - Full-featured browser PWA with camera scanning
   - Chrome-compatible extension for quick access
   - Shared domain logic between platforms

4. **Security Best Practices**
   - Web Crypto API for all cryptographic operations
   - PBKDF2 key derivation with strong iteration counts
   - AES-256-GCM encryption for vault protection
   - Strict `otpauth://` URI validation

5. **Practical Recovery Flows**
   - Versioned backup format with checksum validation
   - Automatic migration for legacy backup formats
   - Merge/replace strategies for backup restoration

## Non-Goals

### Explicitly Out of Scope
1. **Cloud synchronization**: No cross-device sync or cloud backup
2. **Team sharing**: Not designed for shared or enterprise 2FA management
3. **Multi-user support**: Single-user personal vault only
4. **Mobile apps**: No native iOS or Android applications
5. **Social features**: No sharing, collaboration, or social components
6. **Account management**: No user accounts or authentication system

## Key Product Requirements

### Functional Requirements

#### FR1: TOTP Generation
- **Implementation**: RFC 6238 compliant TOTP generation using HMAC-SHA1
- **Code Parameters**: Support for 6-digit (default) and 8-digit codes
- **Time Period**: Configurable periods between 15-120 seconds (default 30s)
- **Algorithm Support**: SHA1 only (as specified in otpauth standard)
- **Counter Encoding**: 8-byte big-endian counter representation
- **Dynamic Truncation**: RFC 6238 compliant truncation for code generation

#### FR2: Import Methods
- **Manual Entry**: Text input for issuer, account, and secret
- **Clipboard Import**: Parse `otpauth://` URIs from clipboard
- **QR Code Import**: Support for QR image files and URLs
- **Camera Scanning**: Real-time QR code detection with 2-frame confirmation
- **Bulk Import**: Textarea for multiple `otpauth://` URIs
- **Validation**: Strict URI validation to prevent false positives

#### FR3: Entry Management
- **Unique Identification**: Entry IDs as `entry_{timestamp}_{random}`
- **Metadata**: Label, tags, pinning status, manual ordering (`order`; see `resequenceEntries` in `app.js`/`extension/popup.js`)
- **Search**: Real-time filtering by issuer, account, or tags
- **Grouping**: By issuer, tag, or no grouping
- **Sorting**: Root app offers pinned-alphabetical, custom order, recent usage, and period (`index.html`); extension offers A-Z, manual, newest, and fastest timer (`extension/popup.html`)
- **Bulk Operations**: Apply tags, remove entries, bulk actions

#### FR4: Security Features
- **Encryption**: Optional PBKDF2 + AES-256-GCM encrypted storage
- **Key Derivation**: 150,000 iterations, SHA-256, 16-byte salt
- **Encryption Parameters**: 12-byte IV, 16-byte authentication tag
- **Passphrase Requirements**: Minimum 8 characters
- **Privacy Options**: Code blurring, screenshot-safe mode
- **Clipboard Clear**: Optional auto-clear clipboard after copying

#### FR5: Backup and Recovery
- **Export Format**: JSON-based backup format (version 2)
- **Checksum Validation**: SHA-256 checksum for integrity verification
- **Migration Support**: Automatic v1 to v2 backup format migration
- **Import Strategies**: Merge with existing entries or replace vault
- **Duplicate Detection**: Skip duplicate entries during import (entries match when secret, digits, and period are identical; label is not part of the match)
- **Review Dialog**: Preview changes before applying import

#### FR6: User Interface
- **Progressive Web App**: Installable PWA with offline support
- **Visual Feedback**: Urgent indicator when codes expire within 10 seconds
- **Copy History**: Track last 6 copied codes (root app; see `addCopyHistory` in `app.js`)
- **Clipboard Clear**: Optional clear 30 seconds after copy (root app; see `index.html`)
- **Keyboard Shortcuts**: `/` focuses search, `n` focuses the secret input (root app; see `bindEvents` in `app.js`)
- **Toast Notifications**: Feedback for user actions and errors
- **Confirm Dialogs**: Destructive action confirmation
- **Online/Offline Status**: Visual indicator for connectivity state

### Non-Functional Requirements

#### NFR1: Performance
- **Code Generation**: Sub-second TOTP computation
- **UI Responsiveness**: Instant feedback for user interactions
- **Offline Startup**: Service worker caching for instant loading
- **Search Speed**: Real-time filtering without noticeable lag

#### NFR2: Security
- **Cryptographic Standards**: Web Crypto API exclusively
- **No External Dependencies**: No third-party cryptographic libraries
- **Secure Random**: `crypto.getRandomValues()` for all randomness
- **Input Validation**: Strict parsing and validation of all user inputs
- **XSS Prevention**: Proper sanitization of user-generated content

#### NFR3: Compatibility
- **Browser Support**: Chrome 114+, Safari 16+, Firefox 115+
- **Extension Support**: Chrome-compatible MV3 extensions
- **Mobile Support**: Responsive design for mobile browsers
- **PWA Support**: Service worker and manifest standards compliance

#### NFR4: Reliability
- **Data Integrity**: Checksum validation for all backup operations
- **Error Handling**: Graceful degradation for crypto failures
- **Backup Migration**: Automatic handling of legacy formats
- **Offline Resilience**: Full functionality without internet connectivity

#### NFR5: Maintainability
- **Code Organization**: Clear separation of UI, domain logic, and storage
- **Testing Coverage**: Unit tests for domain logic, E2E tests for UI flows
- **Documentation**: Comprehensive technical documentation
- **Version Management**: Strict version synchronization between platforms

## Technical Architecture Requirements

### TAR1: Domain Logic Separation
- **Shared Library**: All OTP and vault logic in `lib/` directory
- **Platform Agnostic**: Domain logic must work in both web and extension contexts
- **No Framework Dependencies**: Vanilla JavaScript with no build frameworks
- **Web Crypto API**: All cryptographic operations use browser native APIs

### TAR2: Storage Abstraction
- **Web Storage**: localStorage for root app (`personal_otp_vault_*` keys)
- **Extension Storage**: chrome.storage.local for extension (`otp_extension_*` keys)
- **Version Convention**: `_vN` suffix for all storage keys to support migration
- **Async Handling**: Proper handling of synchronous vs asynchronous storage APIs

### TAR3: Build System
- **Bundling**: esbuild for both web and extension bundles
- **Target Platforms**: Chrome 114, Safari 16, Firefox 115
- **Icon Generation**: Automated icon generation from single SVG source
- **Version Synchronization**: Automated verification and enforcement of version consistency

### TAR4: Testing Requirements
- **Unit Tests**: Vitest for `lib/` module testing
- **E2E Tests**: Playwright for web app, extension, and offline flows
- **Visual Regression**: Screenshot-based UI testing
- **CI Integration**: Automated test execution on pull requests

## Security Posture Requirements

### SPR1: Cryptographic Implementation
- **No Custom Crypto**: Only use established Web Crypto algorithms
- **Proper Parameters**: Industry-standard iteration counts and key sizes
- **Algorithm Specification**: Explicit algorithm parameters (AES-GCM, PBKDF2)
- **Key Management**: Secure key derivation without persistent key storage

### SPR2: Input Validation
- **URI Parsing**: Strict `otpauth://` format validation
- **Parameter Validation**: Enforce allowed digits (6/8), periods (15-120s)
- **Sanitization**: Clean all user inputs before processing
- **Length Limits**: Enforce reasonable bounds on all data fields

### SPR3: Data Protection
- **Local Storage Only**: No network transmission of secrets
- **Encryption Recommended**: Strong encouragement for encrypted vault usage
- **Backup Safety**: Checksum validation prevents tampering
- **Clear Communication**: Explain security implications to users

## Success Criteria

### Technical Success Metrics
- **Test Coverage**: >90% coverage for `lib/` modules
- **E2E Flows**: All critical user paths covered by Playwright tests
- **Performance**: <100ms for TOTP generation, <500ms for UI updates
- **Compatibility**: Passes all tests on supported browsers and platforms

### User Experience Success Metrics
- **Setup Completeness**: Users can successfully add entries within 2 minutes
- **Import Success Rate**: >95% success rate for QR code imports
- **Backup Recovery**: Successful restore from backup >90% of the time
- **Offline Functionality**: Full feature access without internet connectivity

### Security Success Metrics
- **Encryption Adoption**: >80% of users enable encrypted storage
- **Backup Validation**: 100% checksum verification for backup operations
- **Input Validation**: Zero false positives in `otpauth://` parsing
- **Crypto Standards**: Full compliance with RFC 6238 and Web Crypto best practices

## Development Priorities

### Current Focus (v0.1.x)
- **Stability**: Ensure reliable TOTP generation and vault operations
- **Cross-Platform Parity**: Feature equality between web app and extension
- **Testing**: Comprehensive test coverage for domain logic and UI flows
- **Documentation**: Complete technical documentation and user guides

### Future Enhancements (Proposals)
- **Enhanced QR Support**: Steam Guard format and 8-digit code optimization
- **Backup Format v3**: Enhanced encryption and compression
- **Cross-Device Sync**: Optional encrypted sync with explicit user consent
- **Biometric Unlock**: Platform-specific biometric authentication integration
- **Additional Extension Stores**: Firefox and Safari extension support

## Risk Assessment

### Technical Risks
- **Browser Compatibility**: Web Crypto API variations across browsers
- **Storage Quotas**: LocalStorage limits for large vaults
- **Service Worker Lifecycle**: Cache invalidation and offline fallback
- **Extension Storage**: Chrome storage API quota management

### Security Risks
- **Weak Passphrases**: User choice of weak encryption passphrases
- **Device Compromise**: Physical access to unlocked devices
- **Backup Exposure**: Unencrypted backup file handling
- **Input Injection**: Malicious `otpauth://` URI construction

### Mitigation Strategies
- **Clear Communication**: Educate users on security best practices
- **Secure Defaults**: Encrypted storage by default recommendation
- **Validation Layers**: Strict input validation and sanitization
- **Error Handling**: Graceful failure with clear error messages

## Compliance and Standards

### Cryptographic Standards
- **RFC 6238**: TOTP specification compliance
- **RFC 4226**: HOTP foundation requirements
- **Web Crypto API**: W3C Web Cryptography API usage
- **NIST Guidelines**: PBKDF2 and AES-GCM parameter recommendations

### Privacy Standards
- **Local-First Design**: No personal data transmission
- **Minimal Data Collection**: No analytics or tracking
- **User Control**: Complete user control over data and encryption
- **Transparent Security**: Open-source implementation with clear documentation

## Development Workflow Requirements

### Code Quality Standards
- **Conventional Commits**: Structured commit message format
- **Code Review**: All changes reviewed before merging
- **Testing**: New features require corresponding tests
- **Documentation**: Technical docs updated with code changes

### Release Management
- **Version Synchronization**: `package.json` and `extension/manifest.json` must match
- **Automated Release**: GitHub Actions for extension packaging
- **Tag Management**: Semantic versioning with clear release notes
- **Rollback Planning**: Ability to revert problematic releases

This Product Development Requirements document serves as the foundation for the Personal OTP Vault project, ensuring alignment between technical implementation, user needs, and security requirements throughout the development lifecycle.
