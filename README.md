# BitVMX Key Manager

BitVMX Key Manager is a comprehensive Rust library designed for managing cryptographic keys used in BitVMX protocol transactions. It offers robust methods for generating, importing, and deriving keys, as well as signing messages using ECDSA, Schnorr, Winternitz, and MuSig2 algorithms. The library ensures secure storage of keys, making it a reliable choice for blockchain and cryptographic applications.

## ⚠️ Disclaimer

This library is currently under development and may not be fully stable.
It is not production-ready, has not been audited, and future updates may introduce breaking changes without preserving backward compatibility.

A random mnemonic will be auto generated and stored, is no one is provided by configuration, and if it's not already found at the keystore. Make sure to back it up securely!

## Features

- 🔑 **Key Generation and Storage**: Generate new keys and store them securely.
- 📥 **Key Importing**: Import existing private keys into the keystore.
- 🌐 **Key Derivation**: Derive keys using BIP39, BIP44 hierarchical deterministic wallets.
- ✍️ **Message Signing**: Sign messages using ECDSA, Schnorr, Winternitz, and MuSig2 algorithms.
- ✅ **Signature Verification**: Verify signatures for ECDSA, Schnorr, Winternitz, and MuSig2.

## DESIGN

### Key Derivation and Storage Strategy

The BitVMX Key Manager implements different strategies for key derivation and storage based on the cryptographic algorithm and practical considerations:

#### Bitcoin Keys (ECDSA/Schnorr)

- **HD Derivation**: Bitcoin keys are derived using hierarchical deterministic (HD) derivation following BIP39/BIP44 standards from a master seed/mnemonic
- **Storage**: Both private and public keys are stored in the encrypted keystore for persistent access
- **Rationale**: Standard Bitcoin practice enabling deterministic key generation and wallet recovery

#### Winternitz One-Time Signature Keys

- **HD Derivation**: Winternitz keys are HD derived from the same master seed for consistency
- **Storage**: Keys are **not stored** in the keystore - they are regenerated on-demand each time they're needed
- **Rationale**: Storage scalability - Winternitz signatures require large key sets that would significantly bloat storage requirements. Since they can be deterministically regenerated from the HD seed, we prioritize storage efficiency

#### RSA Keys

- **Fresh Entropy**: RSA keys are generated using fresh entropy provided by the user, with **no correlation** to the HD mnemonic
- **Storage**: Private and public keys are stored in the encrypted keystore
- **Rationale**: While HD derivation of RSA keys is theoretically possible (as explored in [research](https://ethresear.ch/t/an-rsa-deterministic-key-generation-scheme-algorithm-and-security-analysis/19745)), we deliberately choose fresh entropy generation to:
  - Align with RSA industry standards and best practices
  - Provide stronger security guarantees independent of the HD seed
  - Acknowledge that users must backup the keystore anyway due to key importing features

#### Imported Keys

- **No HD Correlation**: Imported keys have no relationship to the master HD mnemonic by design
- **Storage**: Stored in the encrypted keystore alongside generated keys
- **Rationale**: Preserves the original entropy and properties of externally generated keys

**Important**: Since the key manager supports importing external keys and uses fresh entropy for RSA keys, users must backup the entire encrypted keystore in addition to the HD mnemonic. The mnemonic alone is insufficient for complete wallet recovery.

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

### [Generating keys, Signing and verifying a message using RSA](examples/rsa.rs)

### [Signing and verifying Multi-Signatures with MuSig2](examples/sign_verify_musig2.rs)

The `KeyManager` supports MuSig2 multi-signature schemes, allowing multiple parties to jointly produce a single Schnorr signature. See more details on [MuSig2 for Rust](https://docs.rs/musig2/latest/musig2/).

```rust
// Step 1: Initialize MuSig2 session
let participant_pubkeys = vec![pubkey1, pubkey2, pubkey3]; // Public keys must be in the same order for all participants
let aggregated_pubkey = key_manager.new_musig2_session(participant_pubkeys.clone(), my_pubkey)?;

// Step 2: Generate nonces for each message
let message = "Hello, MuSig2!";
let message_id = "msg_1";
let session_id = "session_1";
let tweak = None;

key_manager.generate_nonce(message_id, message.as_bytes().to_vec(), &aggregated_pubkey, session_id, tweak)?;

// Step 3: Exchange public nonces with other participants
let my_pub_nonces = key_manager.get_my_pub_nonces(&aggregated_pubkey, session_id)?;

// Step 4: Aggregate nonces from all participants
let mut nonces_map = HashMap::new();
nonces_map.insert(other_participant_pubkey, other_participant_nonce);
key_manager.aggregate_nonces(&aggregated_pubkey, session_id, nonces_map)?;

// Step 5: Create partial signatures
let my_partial_sigs = key_manager.get_my_partial_signatures(&aggregated_pubkey, session_id)?;

// Step 6: Exchange and save partial signatures
let mut partial_sigs_map = HashMap::new();
partial_sigs_map.insert(other_public_key, other_partial_signatures);
partial_sigs_map.insert(my_pubkey, my_partial_sigs);
key_manager.save_partial_signatures(&aggregated_pubkey, session_id, partial_sigs_map)?;

// Step 7: Get final aggregated signature
let final_signature = key_manager.get_aggregated_signature(&aggregated_pubkey, session_id, message_id)?;

// Verify the final signature
let verification = key_manager.verify_final_signature(message_id, &final_signature, aggregated_pubkey, session_id)?;
assert!(verification);
```

## Development Setup

1. Clone the repository
2. Install dependencies: `cargo build`
3. Run tests: `cargo test -- --test-threads=1`

## Examples

- **[create:](examples/create.rs)**
run with `cargo run --example create`
- **[key_gen:](examples/key_gen.rs)**
run with `cargo run --example key_gen`
- **[key_import:](examples/key_import.rs)**
run with `cargo run --example key_import`
- **[deriving_winternitz:](examples/deriving_winternitz.rs)**
run with `cargo run --example deriving_winternitz`
- **[sign_verify_ecdsa:](examples/sign_verify_ecdsa.rs)**
run with `cargo run --example sign_verify_ecdsa`
- **[sign_verify_schnorr_taproot:](examples/sign_verify_schnorr_taproot.rs)**
run with `cargo run --example sign_verify_schnorr_taproot`
- **[sign_verify_winternitz:](examples/sign_verify_winternitz.rs)**
run with `cargo run --example sign_verify_winternitz`
- **[rsa:](examples/rsa.rs)**
run with `cargo run --example rsa`


## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 🧩 Part of the BitVMX Ecosystem

This repository is a component of the **BitVMX Ecosystem**, an open platform for disputable computation secured by Bitcoin.  
You can find the index of all BitVMX open-source components at [**FairgateLabs/BitVMX**](https://github.com/FairgateLabs/BitVMX).

---
