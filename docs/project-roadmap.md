# Project Roadmap

Last updated: 2026-06-27

## Current Status: Version 0.2.0

The Personal OTP Vault is at v0.2.0 with the hardening wave shipped: KDF
parameterization (600k PBKDF2 envelope), auto-lock and unlock throttling,
HOTP + SHA-256/512 support, Google Authenticator migration import, undo-delete
with tombstone, backup reminder, time-drift check, WebAuthn PRF biometric
unlock (two-envelope DEK design), dark mode, drag & drop reorder, per-entry
countdown rings, an accessibility pass, and an i18n framework — in both the
PWA and the Chrome extension.

## Completed Features (Done)

### Core Functionality
- ✅ **TOTP + HOTP Generation**: RFC 6238/4226 compliant, HMAC-SHA1/256/512, 6-8 digits, 15-120s periods
- ✅ **HOTP Counter Semantics**: Counter increments on reveal/copy; entries v3 storage with read-only v2 fallback
- ✅ **Multiple Import Methods**: Manual entry, clipboard, QR file/URL, camera scan, bulk URI import
- ✅ **Google Authenticator Import**: otpauth-migration QR decoding with stitched batches and import preview
- ✅ **Entry Management**: Search, grouping, sorting, tags, bulk operations, pinning, pointer drag & drop reorder
- ✅ **Encrypted Storage**: Parameterized PBKDF2 (600k default) + AES-256-GCM with silent legacy re-encryption
- ✅ **Biometric Unlock**: WebAuthn PRF two-envelope DEK design; passphrase remains the recovery path
- ✅ **Session Hardening**: Auto-lock, unlock throttling with backoff, CSP with vendored fonts and bundled jsqr
- ✅ **Backup System**: Export/import with versioned format and checksum validation; 30-day backup reminder
- ✅ **Data Safety**: Undo delete with 10-minute tombstone, server time-drift check
- ✅ **Migration Support**: Automatic v1 to v2 backup format upgrade
- ✅ **PWA Support**: Service worker caching, offline capability, install prompt
- ✅ **Chrome Extension**: Full-featured MV3 extension with QR import and session-unlock cache
- ✅ **Copy History**: Track last 6 copied codes with optional auto-clear and copy haptics
- ✅ **Privacy Features**: Code blurring, screenshot-safe mode, clipboard clear
- ✅ **Visual Feedback**: Per-entry countdown rings, urgent indicators, dark mode (System/Light/Dark)
- ✅ **Accessibility**: Axe-scanned views (zero criticals), keyboard-reachable controls, announced toasts
- ✅ **i18n Framework**: `lib/i18n.js` English catalog; unlock + settings areas read strings via `t()`

### Testing and Quality Assurance
- ✅ **Unit Tests**: Vitest coverage for `lib/` modules
- ✅ **E2E Tests**: Playwright tests for web app, extension, and offline flows
- ✅ **Visual Regression**: Screenshot-based UI testing
- ✅ **Backup Safety**: Destructive testing for backup integrity
- ✅ **CI/CD**: Automated testing on pull requests
- ✅ **Release Automation**: GitHub Actions for extension packaging

### Documentation
- ✅ **Technical Documentation**: Architecture, code standards, system design
- ✅ **User Documentation**: README with setup and usage instructions
- ✅ **Offline Compatibility**: Safari/iOS PWA behavior documentation
- ✅ **Contributing Guidelines**: Development workflow and contribution process

## In Progress (None Confirmed)

No confirmed in-progress items at this time. The project is in maintenance mode for v0.1.x while gathering user feedback and usage patterns.

## Future Themes (Proposals)

Deferred ideas recorded during the 0.2.0 cycle (not scheduled): 2FAS/Aegis
export import, single-entry QR export, an extension keyboard shortcut, and a
keyed (HMAC) backup checksum v3 for authenticity rather than integrity-only.

### Enhanced QR Code Support (Future Proposal)
**Rationale**: Current QR parsing focuses on standard `otpauth://` URIs. Some services use custom QR formats or Steam Guard's special encoding.

**Proposed Enhancements**:
- Steam Guard format support (non-standard base32 variant)
- Enhanced 8-digit code optimization
- Improved error messages for unsupported QR formats
- QR code format detection and user guidance

**Implementation Considerations**:
- Would require updates to `lib/otp.js` parsing logic
- Extension may need enhanced BarcodeDetector configuration
- E2E tests for Steam Guard format compatibility
- Documentation updates for supported formats

### Backup Format v3 (Future Proposal)
**Rationale**: Current v2 format uses JSON with SHA-256 checksum. Future enhancements could improve compression, encryption options, and metadata.

**Proposed Enhancements**:
- Optional backup encryption with separate passphrase
- Compression for large vaults
- Enhanced metadata (export device info, app version)
- Incremental backup support
- Cloud backup options (with explicit user consent)

**Implementation Considerations**:
- New major version requiring migration path from v2
- Backward compatibility requirements
- Storage impact assessment
- Security review of additional encryption layer

### Cross-Device Sync (Future Proposal - Non-Goal Caveat)
**Rationale**: Users frequently request sync across devices. This is currently a non-goal due to privacy and complexity concerns.

**Proposed Approach** (if ever pursued):
- End-to-end encrypted sync with user-controlled keys
- Optional feature (opt-in, not default)
- No central server - peer-to-peer or user-provided cloud storage
- Clear communication of security implications
- Fallback to current backup/export methods

**Significant Caveats**:
- **Major Privacy Implications**: Moves away from strict local-first design
- **Complexity**: Requires key management, conflict resolution, sync orchestration
- **Security Surface**: Introduces new attack vectors and data exposure risks
- **User Expectations**: May create expectations for continuous sync availability

### Additional Browser Extension Stores (Future Proposal)
**Rationale**: Currently supports Chrome-compatible browsers. Could expand to Firefox Add-ons and Safari App Store.

**Proposed Enhancements**:
- Firefox WebExtension API adaptation
- Safari extension App Store submission
- Store-specific optimization and testing
- Platform-specific feature support

**Implementation Considerations**:
- Firefox WebExtension API differences
- Safari extension App Store review process
- Additional testing infrastructure
- Documentation and support for multiple stores

### Biometric Unlock (SHIPPED in 0.2.0)
Implemented via the WebAuthn `prf` extension with a two-envelope DEK design:
vault data is encrypted under a random DEK, wrapped once under the passphrase
key (recovery) and once under an HKDF-derived KEK from the authenticator's PRF
output. `userVerification: "required"` gates every ceremony; the passphrase
path always remains, and backups export passphrase-encrypted so they restore on
any version. Remaining follow-up: manual hardware matrix across Windows Hello /
Touch ID profiles (the runtime capability probe handles unsupported
authenticators).

### Enhanced Visual Design (SHIPPED in 0.2.0)
Shipped: tokenized design tokens with a dark theme default and a
System/Light/Dark toggle, vendored Space Grotesk + IBM Plex Mono fonts,
per-entry countdown rings, drag & drop reorder, and an axe-core accessibility
pass with zero critical violations. Remaining follow-up ideas: additional
themes and motion refinements (both respect `prefers-reduced-motion`).
- Dark mode optimization
- Customizable themes

**Implementation Considerations**:
- Impact on visual regression tests
- Performance implications for animations
- Accessibility testing requirements
- User preference migration

### Advanced Search and Filtering (Future Proposal)
**Rationale**: Current search supports basic filtering. Advanced search could improve large vault management.

**Proposed Enhancements**:
- Regular expression search support
- Advanced filtering (date added, usage frequency)
- Search history and saved searches
- Bulk operations based on search results
- Smart categorization suggestions

**Implementation Considerations**:
- Performance optimization for large vaults
- Search result UX design
- Complexity vs. usability balance
- Migration of existing search functionality

### Audit Log and Analytics (Future Proposal)
**Rationale**: Security-conscious users may want visibility into vault access and usage patterns.

**Proposed Enhancements**:
- Optional audit logging (vault access, exports, imports)
- Usage analytics (code generation frequency, popular services)
- Security event logging (failed unlock attempts)
- Exportable audit reports
- Local-only analytics (no remote data transmission)

**Implementation Considerations**:
- Privacy implications and user consent
- Storage impact for audit logs
- Performance overhead of logging
- User interface for audit review

## Maintenance Priorities

### Ongoing Maintenance Focus
1. **Security Updates**: Prompt updates for Web Crypto API changes or browser compatibility issues
2. **Bug Fixes**: Priority handling of user-reported issues
3. **Documentation**: Keep docs synchronized with codebase changes
4. **Test Maintenance**: Update tests as browsers and APIs evolve
5. **Dependency Updates**: Regular updates to build tools and testing frameworks

### Platform Monitoring
- **Browser Compatibility**: Monitor for changes in Chrome, Firefox, Safari APIs
- **Extension Store Requirements**: Track changes in Chrome Web Store policies
- **Web Crypto Standards**: Follow updates to Web Cryptography API specifications
- **Security Advisories**: Monitor for relevant security vulnerabilities

### Community Feedback Channels
- **GitHub Issues**: Primary feedback and bug tracking
- **Pull Requests**: Community contributions and improvements
- **Documentation Requests**: Areas needing clarification or expansion
- **Feature Requests**: User-suggested enhancements (evaluated against non-goals)

## Release Strategy

### Version Management
- **Semantic Versioning**: Follow semantic versioning (major.minor.patch)
- **Version Synchronization**: Maintain `package.json` and `extension/manifest.json` consistency
- **Release Notes**: Document user-facing changes and migration requirements
- **Backward Compatibility**: Preserve backup format compatibility when possible

### Release Criteria
- **Testing Completion**: All tests passing for affected components
- **Documentation Updates**: Relevant docs updated for new features
- **Security Review**: Crypto changes reviewed for security implications
- **Performance Validation**: No performance regressions introduced

### Rollback Planning
- **Quick Revert**: Ability to quickly revert problematic releases
- **Migration Support**: Forward and backward migration paths for data formats
- **User Communication**: Clear communication of issues and fixes
- **Testing Infrastructure**: Automated testing of rollback procedures

## Non-Goal Reinforcement

### Explicitly Out of Scope
- **Cloud Synchronization**: No plans for remote sync or cloud backup (remains a non-goal)
- **Multi-User Support**: Single-user personal vault only
- **Mobile Applications**: No native iOS or Android apps planned
- **Social Features**: No sharing, collaboration, or social components
- **Account Management**: No user accounts or authentication system
- **Enterprise Features**: No team management or corporate functionality

### Philosophy
The project maintains a strong focus on local-first, privacy-first design. Future enhancements should reinforce these principles rather than compromise them. Any feature that moves away from local-only operation requires careful consideration of privacy implications and user consent.

## Timeline Considerations

### No Fixed Commitments
This roadmap represents potential future directions, not committed timelines. The project is maintained by a small team and releases are driven by:
- User feedback and bug reports
- Security considerations and best practices
- Platform requirement changes
- Maintainer availability and priorities

### Decision Framework
Feature proposals are evaluated based on:
- **Alignment with Core Principles**: Does this reinforce local-first, privacy-first design?
- **User Demand**: Is there clear user need and benefit?
- **Implementation Complexity**: Can this be implemented reliably within current architecture?
- **Maintenance Burden**: Does this add significant ongoing maintenance requirements?
- **Security Implications**: Does this introduce new security considerations?

## Community Contribution

### Contribution Opportunities
- **Bug Reports**: Testing on different browsers and platforms
- **Documentation**: Improving clarity and coverage of technical docs
- **Testing**: Additional test coverage for edge cases
- **Code Review**: Reviewing proposed changes for quality and security
- **Feature Proposals**: Well-considered enhancement proposals with rationale

### Contribution Guidelines
- Follow conventional commit format
- Include tests for new functionality
- Update relevant documentation
- Consider both web and extension platforms
- Maintain local-first and privacy-first principles

This roadmap will be updated as the project evolves and user feedback shapes priorities. The focus remains on providing a secure, private, local-first OTP management solution without compromising on core principles.
