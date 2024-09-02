# BitVMX Key Manager

A Rust library for managing a collection of keys for BitVMX transactions. This project provides methods for generating, importing, and deriving keys, as well as signing messages using ECDSA and Schnorr algorithms. The project also includes a secure storage mechanism to store keys.

## Features

- Generate new keys and securely store them
- Import existing private keys
- Derive keys using BIP32
- Sign messages using ECDSA, Schnorr and Winternitz
- Verify ECDSA, Schnorr and Winternitz signatures

## Usage

### Creating a KeyManager 
```rust
let network = Network::Regtest;
let keystore_path = "/some_path/keystore.db"
let keystore_password =  b"secret password".to_vec();
let key_derivation_seed = random_bytes();
let key_derivation_path = "m/101/1/0/0/";
let winternitz_seed = random_bytes();

// A key manager can use a file based keystore:
// let keystore = FileKeyStore::new(keystore_path, keystore_password, network);

// Or a database based keystore:
let keystore = DatabaseKeyStore::new(keystore_path, keystore_password, network);

let key_manager = KeyManager::new(
    network, 
    key_derivation_path, 
    key_derivation_seed, 
    winternitz_seed, 
    keystore, 
)?;
```

### Generating an ECDSA key
Internally the key manager generates a key pair, stores the private key and the corresponding public key in the encrypted keystore. The public key is later used to select the corresponding private key for signing.

```rust
let mut rng = secp256k1::rand::thread_rng();
let pk = key_manager.generate_key(&mut rng).unwrap();
```

### Deriving ECDSA keys using BIP32

```rust
let public_key_1 = key_manager.derive_bip32().unwrap();
let public_key_2 = key_manager.derive_bip32().unwrap();
```

### Deriving Winternitz OTS keys
The key manager supports Winternitz one-time keys. Winternitz keys can ge generated using SHA-256 or RIPEMD-160 hash functions. As with the ECDSA keys, a key pair is generated and only the public key is returned. The public key can later be used to select the corresponding private key for signing.

```rust
// Key size in bytes. A Winternitz key needs to be of the same size as the message that will be signed with it.
let key_size = 32;
let winternitz_key = key_manager.derive_winternitz(key_size, WinternitzType::SHA256, 0).unwrap();
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
let signature_verifier = SignatureVerifier::new();
signature_verifier.verify_ecdsa_signature(&signature, &message, pk);
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

## Contributing
Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License
This project is licensed under the MIT License.

