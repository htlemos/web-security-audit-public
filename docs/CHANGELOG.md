# Changelog

## 1.0.3

### Added

- GitHub Actions release validation
- GitHub Actions security scanning
- GitHub Actions quality checks
- Bandit policy configuration

### Changed

- CI/CD workflow
- Public repository governance model
- Release validation process

### Fixed

- Release package validation
- Security workflow stability
- Gitleaks execution model
- Bandit false positives handling

## 1.0.2

### Fixed

- install.sh adapted to the new repository structure.
- README examples updated for profiles/ and config/.
- build-release.sh SHA256 validation corrected.
- build-release.sh now archives releases automatically.
- release package validation added.
- renderer compatibility fixes (VERSION, VISIBLE, slug, css_class).

### Improved

- release packaging workflow.
- installation validation process.
- documentation consistency.

## 1.0.1

### Changed

- Consolidated into a single engine.
- Removed runtime dependency on historical audit versions.
- Introduced profile-web-security-external.
- Removed organization-specific references.
- Maintained Technical Debt / Compliance / Exposure scoring.

### Restored

- V12.4 HTML reporting experience.
- V12.4 audit summary console output.
- Metadata project support.
- HTTP/80 exception support.