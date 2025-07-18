# BitVMX Key Manager

BitVMX Key Manager is a comprehensive Rust library designed for managing cryptographic keys used in BitVMX protocol transactions. It offers robust methods for generating, importing, and deriving keys, as well as signing messages using ECDSA, Schnorr, Winternitz, and MuSig2 algorithms. The library ensures secure storage of keys, making it a reliable choice for blockchain and cryptographic applications.

## Features

- 🔑 **Key Generation and Storage**: Generate new keys and store them securely.
- 📥 **Key Importing**: Import existing private keys into the keystore.
- 🌐 **Key Derivation**: Derive keys using BIP32 hierarchical deterministic wallets.
- ✍️ **Message Signing**: Sign messages using ECDSA, Schnorr, Winternitz, and MuSig2 algorithms.
- ✅ **Signature Verification**: Verify signatures for ECDSA, Schnorr, Winternitz, and MuSig2.

## Usage

### Creating a KeyManager 
```rust
let network = Network::Regtest;
let password = "secret password".to_string();
let keystore_path = "/some_path/keystore.db"
let key_derivation_seed = random_bytes();
let key_derivation_path = "m/101/1/0/0/";
let winternitz_seed = random_bytes();

let config = StorageConfig::new(keystore_path, Some(password));
let store = Rc::new(Storage::new(&config).unwrap());
let keystore = KeyStore::new(store);

let manager = KeyManager::new(
    network, 
    key_derivation_path, 
    key_derivation_seed, 
    winternitz_seed, 
    keystore, 
)?;
```

### Key Importing
```rust
use bitcoin::secp256k1::SecretKey;

let mut manager = KeyManager::new();

let secret_key = SecretKey::from_slice(&[0xcd; 32])?;
manager.import_private_key(secret_key);

let private_key: Vec::<String>() = ...;
let secret_key: Vec::<String>() = ...;
manager.import_partial_private_keys(private_key);
manager.import_partial_secret_keys(secret_key);
```

### Key Generation & Derivation
Internally the key manager generates a key pair, stores the private key and the corresponding public key in the encrypted keystore. The public key is later used to select the corresponding private key for signing.

```rust
let mut rng = secp256k1::rand::thread_rng();
// Generate a keypair
let keypair = manager.generate_keypair(&mut thread_rng());

// Derive a child keypair (e.g., for indexed wallets)
let derived = manager.derive_keypair(0);

// Derive public key only
let pubkey = manager.derive_public_key(master_xpub, 1);

// Generate a master extended x public key
let master_xpub = manager.master_xpub();

// BIP32-like hardened path
let path = manager.key_derivation_path(42);
```

#### Deriving Winternitz OTS keys
The key manager supports Winternitz one-time keys. Winternitz keys can be generated using SHA-256 or RIPEMD-160 hash functions. As with the ECDSA keys, a key pair is generated and only the public key is returned. The public key can later be used to select the corresponding private key for signing.

```rust
// Key size in bytes. A Winternitz key needs to be of the same size as the message that will be signed with it.
let key_size = 32;
let index = 0; 
let winternitz_key = key_manager.derive_winternitz(key_size, WinternitzType::SHA256, index)?;
```

### Signing and verifying a message using ECDSA

```rust
// Create a random Message.
let mut digest = [0u8; 32];
rng.fill_bytes(&mut digest);
let message = Message::from_digest(digest);

// Create a key pair
let public_key = key_manager.generate_key(&mut rng).unwrap();

// Create an ECDSA signature of the random Message by selecting the private associated to the public key passed as parameter 
let signature = key_manager.sign_ecdsa_message(&message, public_key);

// Verify the signature
signature_verifier.verify_ecdsa_signature(&signature, &message, pk);

// Recover signature
let recoverable_sig = manager.sign_ecdsa_recoverable_message(&message, pk);
```

### Signing and verifying a message using Schnorr
```rust
// Create a random Message.
let mut digest = [0u8; 32];
rng.fill_bytes(&mut digest);
let message = Message::from_digest(digest);

// Create a key pair
let public_key = key_manager.generate_key(&mut rng).unwrap();

// Create a Schnorr signature of the random Message by selecting the private associated to the public key passed as parameter 
let signature = key_manager.sign_schnorr_message(&message, &pk).unwrap();

// Verify the signature
let signature_verifier = SignatureVerifier::new();
signature_verifier.verify_schnorr_signature(&signature, &message, pk);
```

### Signing and verifying a message using Winternitz
```rust
// Create a random Message.
let mut digest = [0u8; 32];
rng.fill_bytes(&mut digest);
let message = Message::from_digest(digest);

// Create a Winternitz signature. Internally a Winternitz key pair for the derivation index 0 is created using the SHA-256 hash function
let signature = key_manager.sign_winternitz_message(&message[..], WinternitzType::SHA256, 0).unwrap();

// Get the Winternitz public key for the index 0 using the SHA-256 hash function
let winternitz_key = key_manager.derive_winternitz(message[..].len(), WinternitzType::SHA256, 0).unwrap();

// Verify the signature
let signature_verifier = SignatureVerifier::new();
signature_verifier.verify_winternitz_signature(&signature, &message[..], &winternitz_key);
```

### Schnorr & Taproot Signatures

The `KeyManager` supports both Taproot **script path spends** and **key path spends** (with or without tweaking). These methods use Schnorr signatures and are compatible with BIP-340/341 Taproot usage in Bitcoin.

```rust
// Sign with Taproot Script Path
let signature = manager.sign_schnorr_message(&msg, &pubkey)?;

// Sign with Taproot Key Spend (Optional Merkle Root)
let (sig, tweaked_pubkey) = manager.sign_schnorr_message_with_tap_tweak(&msg, &pubkey, merkle_root)?;

// Sign with Custom Tweak
let (sig, tweaked_pubkey) = manager.sign_schnorr_message_with_tweak(&msg, &pubkey, &tweak)?;
```

## Development Setup

1. Clone the repository
2. Install dependencies: `cargo build`
3. Run tests: `cargo test`

## Contributing
Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License
This project is licensed under the MIT License.

