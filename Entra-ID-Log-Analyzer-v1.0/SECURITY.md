# Security Policy

## Supported Versions

We actively support the following versions of Entra ID Log Analyzer:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in the Entra ID Log Analyzer, please report it responsibly.

### How to Report

**Please do NOT create a public GitHub issue for security vulnerabilities.**

Instead, please send an email to: **security@guardz.com**

Include the following information:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Any suggested fixes (if available)

### What to Expect

1. **Acknowledgment**: We will acknowledge receipt of your report within 48 hours
2. **Initial Assessment**: We will provide an initial assessment within 5 business days
3. **Investigation**: We will investigate and work on a fix
4. **Resolution**: We will notify you when the vulnerability is resolved
5. **Disclosure**: We will coordinate responsible disclosure timing with you

### Security Best Practices

When using the Entra ID Log Analyzer:

1. **Data Handling**
   - Process logs in a secure environment
   - Ensure log files are encrypted in transit and at rest
   - Regularly delete processed log files that are no longer needed

2. **Access Control**
   - Limit access to the application to authorized personnel only
   - Use strong authentication mechanisms
   - Implement proper session management

3. **Network Security**
   - Deploy behind proper network security controls
   - Use HTTPS in production environments
   - Implement proper firewall rules

4. **Regular Updates**
   - Keep the application updated to the latest version
   - Monitor for security advisories
   - Update dependencies regularly

### Known Security Considerations

1. **Client-Side Processing**: This application processes logs entirely on the client side. Ensure your environment is secure.

2. **Data Persistence**: The application uses browser storage for analysis results. Clear sensitive data when appropriate.

3. **File Upload**: Only upload log files from trusted sources. Validate file contents before processing.

### Security Features

The Entra ID Log Analyzer includes several security-focused features:

- **Local Processing**: All analysis happens locally in your browser
- **No External Dependencies**: No data is sent to external services
- **Secure Storage**: Uses browser's secure storage mechanisms
- **Input Validation**: Validates all input data before processing

### Reporting Non-Security Issues

For general bugs and issues that are not security-related, please use our [GitHub Issues](https://github.com/your-username/entra-id-log-analyzer/issues) page.

## Contact

For any security-related questions or concerns:
- Email: security@guardz.com
- Website: https://guardz.com

Thank you for helping keep Entra ID Log Analyzer secure!