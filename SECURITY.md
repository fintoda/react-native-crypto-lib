# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.9.x   | :white_check_mark: |
| < 0.9   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in `@fintoda/react-native-crypto-lib`, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please use [GitHub Security Advisories](https://github.com/fintoda/react-native-crypto-lib/security/advisories/new) to report the vulnerability privately.

Alternatively, you can email [support@fintoda.com](mailto:support@fintoda.com) with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact assessment

### What to expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 5 business days
- **Fix or mitigation plan** communicated within 10 business days

### Scope

The following are considered in scope for this cryptographic library:

- Memory leaks of secret key material (private keys, seeds, master secrets, ECDH shared secrets)
- Incorrect cryptographic output (wrong hash, invalid signature, broken derivation)
- Timing side-channels in security-sensitive operations
- Buffer overflows or out-of-bounds reads in C++ native code
- Weak or predictable random number generation
- Padding oracle or authentication bypass in AES operations

The following are **out of scope**:

- Vulnerabilities in the upstream React Native framework
- Issues that require physical access to the device
- Denial of service through large input sizes (documented limits exist)
