# OpenClaw Security Analyzer

A comprehensive security configuration analyzer for [OpenClaw](https://openclaw.ai) deployments. Analyze your `openclaw.json` and related configuration files to identify security risks and get actionable hardening recommendations.

![OpenClaw Security Analyzer](https://img.shields.io/badge/OpenClaw-Security%20Analyzer-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Web-green?style=for-the-badge)

## Features

- **Configuration Analysis** - Import and analyze OpenClaw JSON configuration files
- **Risk Detection** - Automatically identify Critical, High, Medium, Low, and Info severity issues
- **68-Point Security Checklist** - Comprehensive hardening recommendations across 5 categories:
  - Network & Socket Security
  - Identity & Secret Integrity
  - Execution & Sandbox
  - Supply Chain & Skill Security
  - Behavioral & Forensic Monitoring
- **Attack Path Visualization** - Visual exposure graph showing potential attack vectors
- **Multi-File Support** - Import and analyze multiple configuration files simultaneously
- **Dark/Light Mode** - Toggle between dark and light themes
- **Rich Tooltips** - Detailed implementation instructions with code examples
- **Offline Capable** - Single HTML file, no server required

## Supported File Types

| File | Path | Description |
|------|------|-------------|
| Main Config | `~/.openclaw/openclaw.json` | Primary configuration |
| Credentials | `~/.openclaw/credentials/*.json` | Channel credentials |
| Auth Profiles | `agents/*/auth-profiles.json` | Authentication profiles |
| Session Logs | `agents/*/sessions/*.jsonl` | Session transcripts |
| DM Allowlist | `*-allowFrom.json` | DM access control |
| Jobs | `~/.openclaw/jobs.json` | Scheduled tasks |
| Device Auth | `~/.openclaw/device-auth.json` | Device authentication |
| Agent Config | `agents/*/agent.json` | Per-agent settings |
| Settings | `~/.openclaw/settings.json` | User settings |

## Quick Start

### Option 1: Direct Download

1. Download `openclaw-analyzer.html`
2. Open in any modern browser
3. Click "Import" or drag & drop your configuration file

### Option 2: Clone Repository

```bash
git clone https://github.com/yourusername/openclaw-security-analyzer.git
cd openclaw-security-analyzer
open openclaw-analyzer.html  # macOS
# or
start openclaw-analyzer.html  # Windows
# or
xdg-open openclaw-analyzer.html  # Linux
```

## Usage

### Analyzing Configuration

1. **Import Configuration**
   - Click a file type button in the right panel, or
   - Use the "Import" button in the header, or
   - Select multiple files at once for combined analysis

2. **Review Findings**
   - Potential risks are displayed by severity (Critical → Info)
   - Filter by severity using the tags
   - Click on findings to see affected configuration paths

3. **Apply Recommendations**
   - Browse the 68-point security checklist
   - Filter by category (Network, Identity, Sandbox, Supply Chain, Monitoring)
   - Hover over recommendations for implementation details
   - Check off completed items

### Analysis Checks

Toggle these checks in the Options panel:

- **Exposed secrets & tokens** - Hardcoded credentials detection
- **Network & gateway binding** - Network exposure analysis
- **Authentication & access** - Auth configuration review
- **Sandbox & tool policies** - Execution isolation checks
- **Channel & DM policies** - Messaging access control
- **Discovery & mDNS** - Service broadcast analysis

## Security Risks Detected

### Critical
- Hardcoded authentication tokens
- Unauthenticated gateway exposure
- Public DM/Group exposure
- Uncontrolled shell access

### High
- Browser control remote access
- Plugin code execution risks
- Session transcript exposure
- Weak model selection

### Medium
- Group chat always-on mode
- mDNS information disclosure
- Cross-user context leakage
- Static token authentication

### Low
- Tailscale disabled
- NPM package manager usage
- Missing plugin allowlist

## Hardening Recommendations

The analyzer provides 68 security recommendations organized into categories:

| Category | Count | Focus Area |
|----------|-------|------------|
| Network | 10 | Binding, TLS, firewalls, VPN |
| Identity | 10 | Secrets, OAuth, MFA, isolation |
| Sandbox | 15 | Docker, capabilities, approvals |
| Supply Chain | 15 | Skills, dependencies, prompts |
| Monitoring | 18 | Logging, detection, recovery |

Each recommendation includes:
- Risk description
- Implementation difficulty (Easy/Medium/Hard)
- Step-by-step instructions
- Code examples
- Relevant tags

## Example Configuration

Minimal hardened `openclaw.json`:

```json
{
  "gateway": {
    "bind": "loopback",
    "port": 18789,
    "auth": {
      "mode": "password",
      "password": "${OPENCLAW_GATEWAY_PASSWORD}"
    }
  },
  "channels": {
    "whatsapp": {
      "dmPolicy": "pairing",
      "groups": {
        "*": { "requireMention": true }
      }
    }
  },
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "all",
        "workspaceAccess": "ro"
      }
    }
  },
  "discovery": {
    "mdns": { "mode": "off" }
  }
}
```

## Browser Compatibility

| Browser | Supported |
|---------|-----------|
| Chrome 90+ | ✅ |
| Firefox 88+ | ✅ |
| Safari 14+ | ✅ |
| Edge 90+ | ✅ |

## Privacy

- **100% Client-Side** - No data is sent to any server
- **No Tracking** - No analytics or telemetry
- **No Storage** - Configuration is not persisted (refreshing clears data)
- **Offline Capable** - Works without internet connection

## Development

### File Structure

```
openclaw-security-analyzer/
├── openclaw-analyzer.html    # Main application (single file)
├── sample-openclaw.json      # Example configuration for testing
└── README.md                 # This file
```

### Customization

The analyzer is a single HTML file with embedded CSS and JavaScript. To customize:

1. **Add new risk checks** - Extend the `analyzeConfig()` function
2. **Add recommendations** - Update the `RECOMMENDATIONS` object
3. **Modify styling** - Edit CSS variables in `:root` and `[data-theme]` selectors
4. **Add file types** - Add buttons in the "Import Configuration Files" section

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Commit your changes (`git commit -am 'Add new security check'`)
4. Push to the branch (`git push origin feature/new-check`)
5. Open a Pull Request

### Ideas for Contribution

- [ ] Additional security checks
- [ ] Export findings as JSON/PDF
- [ ] Configuration fix suggestions
- [ ] Integration with `openclaw security audit`
- [ ] Comparison between configurations

## Related Resources

- [OpenClaw Documentation](https://docs.openclaw.ai)
- [OpenClaw Security Guide](https://docs.openclaw.ai/gateway/security)
- [OpenClaw GitHub](https://github.com/openclaw)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Credits

- Built with vanilla HTML, CSS, and JavaScript
- Security checklist based on [OpenClaw Security Documentation](https://docs.openclaw.ai/gateway/security)
- Guardz branding and design elements

---

**Disclaimer:** This tool provides security recommendations based on configuration analysis. It does not guarantee complete security. Always follow security best practices and consult the official OpenClaw documentation.
