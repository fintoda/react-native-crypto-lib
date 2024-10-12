# Overview

This module is a native wrapper for cryptographic functions, leveraging **Trezor Crypto** and **secp256k1** libraries written in C. It is designed for use with **React Native**, providing highly efficient and secure cryptographic operations directly on mobile devices. This module is especially useful for blockchain-based applications and cryptocurrency wallets.

## Features

- **Hash Functions**:
  - SHA1, SHA256, SHA512
  - SHA3-256, SHA3-512
  - KECCAK-256, KECCAK-512
  - RIPEMD160
  - HASH256 (double SHA-256)
  - HASH160 (SHA-256 followed by RIPEMD-160)

- **HMAC**:
  - HMAC SHA256
  - HMAC SHA512

- **PBKDF2**:
  - PBKDF2 with SHA256
  - PBKDF2 with SHA512

- **AES Encryption**:
  - AES-256-CBC: Encrypt and decrypt data using AES with 256-bit keys in CBC mode.

- **BIP Standards**:
  - BIP32: Hierarchical Deterministic (HD) wallets.
  - BIP39: Mnemonic phrases for deterministic key generation.

- **Digital Signatures**:
  - ECDSA: Sign and verify messages using the secp256k1 curve.
  - Schnorr Signatures: More compact and efficient signatures with support for signature aggregation.

- **ECC Interface for `bitcoinlib-js`**: 
  - Provides an interface for using native ECC operations with the `bitcoinlib-js` library.

## Why Use This Module?

- **Performance**: High performance through native C implementations of cryptographic algorithms.
- **Security**: Based on reliable and secure industry-standard libraries.
- **Compatibility**: Works seamlessly with various Bitcoin standards and integrates with `bitcoinlib-js`.
- **Cross-Platform**: Supports both iOS and Android with a unified JavaScript interface.

## Installation

```sh
npm install @fintoda/react-native-crypto-lib
# or
yarn add @fintoda/react-native-crypto-lib
```

## Usage


```js
import { Buffer } from 'buffer';
import { digest } from '@fintoda/react-native-crypto-lib';

// ...

const data = new Uint8Array(
  Buffer.from(
    'ab7615a6cb35f59c2c0a2e9d51d2bf2f20366b0fc1e27a30e3e25cfd65b5f5c3',
    'hex'
  )
);

const result = digest.createHash(digest.HASH.SHA256, data);
```


## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)
