# BitVMX Key Manager

BitVMX Key Manager is a comprehensive Rust library designed for managing cryptographic keys used in BitVMX protocol transactions. It offers robust methods for generating, importing, and deriving keys, as well as signing messages using ECDSA, Schnorr, Winternitz, and MuSig2 algorithms. The library ensures secure storage of keys, making it a reliable choice for blockchain and cryptographic applications.

## ⚠️ Disclaimer

This library is currently under development and may not be fully stable.
It is not production-ready, has not been audited, and future updates may introduce breaking changes without preserving backward compatibility.

A random mnemonic will be auto generated and stored, is no one is provided by configuration, and if it's not already found at the keystore. Make sure to back it up securely!

## Features

- 🔑 **Key Generation and Storage**: Generate new keys and store them securely.
- 📥 **Key Importing**: Import existing private keys into the keystore.
- 🌐 **Key Derivation**: Derive keys using BIP32 hierarchical deterministic wallets.
- ✍️ **Message Signing**: Sign messages using ECDSA, Schnorr, Winternitz, and MuSig2 algorithms.
- ✅ **Signature Verification**: Verify signatures for ECDSA, Schnorr, Winternitz, and MuSig2.

## Usage

### [Creating a KeyManager](examples/create.rs)

### [Key Importing](examples/key_import.rs)

### [Key Generation & Derivation](examples/key_gen.rs)
*Internally the key manager generates a key pair, stores the private key and the corresponding public key in the encrypted keystore. The public key is later used to select the corresponding private key for signing.*

*`next_keypair` is always the preferred way to get a new keypair, as it manages the derivation index automatically.*

### [Signing and verifying a message using ECDSA](examples/sign_verify_ecdsa.rs)

### [Signing and verifying a message using Schnorr & Taproot Signatures](examples/sign_verify_schnorr_taproot.rs)
*The `KeyManager` supports both Taproot **script path spends** and **key path spends** (with or without tweaking). These methods use Schnorr signatures and are compatible with BIP-340/341 Taproot usage in Bitcoin.*

### [Deriving Winternitz OTS keys](examples/deriving_winternitz.rs)
*The key manager supports Winternitz one-time keys. Winternitz keys can be generated using SHA-256 or RIPEMD-160 hash functions. As with the ECDSA keys, a key pair is generated and only the public key is returned. The public key can later be used to select the corresponding private key for signing.*

### [Signing and verifying a message using Winternitz](examples/sign_verify_winternitz.rs)


## Development Setup

1. Clone the repository
2. Install dependencies: `cargo build`
3. Run tests: `cargo test -- --test-threads=1`

## Examples
- **[keymanager_usage:](examples/keymanager_usage.rs)**
    1. run with `cargo run --example keymanager_usage`


## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License.

