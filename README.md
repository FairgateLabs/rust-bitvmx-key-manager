# BitVMX Key Manager

A Rust library for managing a collection of keys for BitVMX transactions. This project provides methods for generating, importing, and deriving keys, as well as signing messages using ECDSA and Schnorr algorithms. The project also includes a secure storage mechanism to store keys.

## Features

- Generate new keys and securely store them
- Import existing private keys
- Derive keys using BIP32
- Sign messages using ECDSA, Schnorr and Winternitz
- Verify ECDSA, Schnorr and Winternitz signatures

## Usage

### Generating a key

```rust
const DERIVATION_PATH: &str = "101/1/0/0/";
const STORAGE_PATH: &str = "secure_storage.db";

let mut seed = [0u8; 32];
secp256k1::rand::thread_rng().fill_bytes(&mut seed);

let storage_password = b"secret password".to_vec();

let mut key_manager = KeyManager::new(Network::Regtest, DERIVATION_PATH.to_string(), STORAGE_PATH.to_string(), storage_password, &seed);

// Internally the key manager generates a key pair, stores the private key in an encrypted storage along the "my_key" 
// label and the corresponding public key to allow selecting the private key for signing by using the label or the 
// public key.
let public_key = key_manager.generate_key("my_key");
```

### Signing a message

```rust
// Create a random Message.
let mut digest = [0u8; 32];
secp256k1::rand::thread_rng().fill_bytes(&mut digest);
Message::from_digest(digest);

// Create an ECDSA signature of the  Message by selecting the private associated to the public key passed as parameter 
// to the sign_ecdsa_message() function.
let signature = key_manager.sign_ecdsa_message(&message, public_key);
```

### Verify a signature

```rust
let signature_verifier = SignatureVerifier::new();
signature_verifier.veriy_ecdsa_signature(&signature, &message, public_key);
```

## Contributing
Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License
This project is licensed under the MIT License.

