# Contributing to Security Research Labs

Thank you for considering contributing. This document explains how to propose changes and what we expect.

## How to contribute

### Reporting bugs or suggesting features

- **Issues:** Open an [issue](https://github.com/guardzcom/security-research-labs/issues) and use the appropriate template if available.
- **Security:** Do not open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md).

### Code and documentation

1. **Fork** the repository and clone your fork.
2. **Create a branch** from `main` (e.g. `feature/openclaw-export` or `fix/m365-docs`).
3. **Make your changes** and keep commits focused and well-described.
4. **Test** your changes where applicable (e.g. run scripts in a safe environment).
5. **Push** to your fork and open a **Pull Request** against `main`.

In your PR:

- Describe what changed and why.
- Reference any related issues.
- For new scripts or tools: add or update README/docs in the relevant folder.

### What we welcome

- New security checks or analyzers (e.g. for OpenClaw or other configs).
- M365/Entra/SharePoint/OneDrive scripts with clear, safe usage notes.
- Documentation improvements, usage examples, and README updates.
- Bug fixes and small refactors that don’t change behavior without need.

### What we avoid

- Scripts or tools that are clearly intended only for malicious use.
- Hardcoded credentials, tokens, or sensitive data.
- Contributions that violate our [Code of Conduct](CODE_OF_CONDUCT.md).

### Legal and safety

- Only contribute code you are allowed to license under MIT.
- For M365/red-team style scripts: include clear warnings that they are for **authorized testing only** and that users must have permission before use.

## Questions

If you’re unsure about anything, open an issue with the question and we’ll respond when we can.

Thanks for helping make Security Research Labs useful for the community.
