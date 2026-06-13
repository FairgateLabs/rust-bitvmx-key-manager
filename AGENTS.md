# AGENTS.md

Guidance for coding agents working on `rust-bitvmx-key-manager`.

## Project overview

`bitvmx-key-manager` is a Rust library and CLI for managing cryptographic keys used by the BitVMX protocol. It supports:

- Bitcoin key management for `P2pkh`, `P2shP2wpkh`, `P2wpkh`, and `P2tr` key types.
- BIP39/BIP32/BIP44-style deterministic key derivation from a mnemonic and optional passphrase.
- ECDSA and Schnorr/Taproot signing for Bitcoin keys.
- Winternitz one-time signatures (WOTS), derived on demand from a stored seed.
- Lamport one-time signatures, including derived and imported keys.
- RSA key generation/import, signing, verification, encryption, and decryption.
- MuSig2 multi-signature session management.

The package name is `bitvmx-key-manager`, and the library crate is exposed as `key_manager`.

## Important security/design notes

- This project handles sensitive material. Avoid logging mnemonics, passphrases, private keys, seeds, nonces, or decrypted keystore values.
- The keystore is essential for recovery. The mnemonic alone is not enough because imported keys and RSA keys are stored independently of HD derivation.
- Bitcoin keys are stored in the encrypted storage backend and are also derivable from the mnemonic.
- Winternitz keys are not stored as full key sets; they are regenerated from deterministic seeds to avoid huge storage usage.
- Lamport derived keys are regenerated on demand, but imported Lamport private keys are stored.
- RSA keys are generated with fresh entropy and are not derived from the mnemonic.
- One-time signature reuse is dangerous. Default features enable index-reuse checks for WOTS and Lamport.

## Repository layout

- `src/lib.rs` - crate modules, public re-exports, and `create_key_manager_from_config`.
- `src/key_manager.rs` - main `KeyManager` API: key derivation/import, signing, RSA, Lamport/WOTS, MuSig2 helpers, and many unit tests.
- `src/key_store.rs` - persistence wrapper over `rust-bitvmx-storage-backend`; stores mnemonics, seeds, keypairs, RSA keys, Lamport imports, and index bitmaps.
- `src/key_type.rs` - Bitcoin key type enum and purpose indexes.
- `src/winternitz.rs` - Winternitz key/signature types and algorithms.
- `src/lamport.rs` - Lamport key/signature types, compressed public key IDs, message traits, and algorithms.
- `src/rsa.rs` - RSA keypair wrapper and signing/encryption helpers.
- `src/musig2/` - MuSig2 signer storage/session logic and type helpers.
- `src/verifier.rs` - signature verification helpers.
- `src/cli.rs`, `src/main.rs` - `key-manager` CLI.
- `src/config.rs` - deserializable runtime config.
- `src/errors.rs` - project error types.
- `examples/` - runnable usage examples.
- `tests/examples.rs` - compiles/runs examples as tests with cleanup.
- `benches/` - Criterion benchmarks for Winternitz and MuSig2.
- `config/development.yaml` - sample local config using regtest and `/tmp/storage.db`.

## Common commands

Use these from the repository root.

```bash
cargo fmt
cargo check
cargo test --release -- --test-threads=1
cargo test -- --test-threads=1
cargo run --example create
cargo run --example key_gen
cargo run --bin key-manager -- --configuration config/development.yaml --help
```

Notes:

- Prefer `cargo test --release -- --test-threads=1` for the full suite, as documented in the README.
- Sequential tests are important because examples and some storage-backed tests can share filesystem paths.
- Some examples create `examples/storage` or `test_output`; tests try to clean these up.

## Feature flags

Default features:

- `wots_idx_check` - prevents Winternitz index reuse.
- `lamport_idx_check` - prevents Lamport index reuse.

Optional features:

- `transactional` - wraps selected database updates in transactions for stronger atomicity.
- `strict` - enables additional validation/safety checks where implemented.

Examples:

```bash
cargo test --no-default-features
cargo test --features strict
cargo test --features transactional -- --test-threads=1
```

## Configuration

The CLI and `create_key_manager_from_config` expect:

```yaml
key_manager:
  network: "regtest"
  mnemonic_sentence: "..." # optional; generated and stored if absent
  mnemonic_passphrase: ""  # optional; empty string by default

storage:
  password: "..."
  path: "/tmp/storage.db"
```

`network` is parsed as `bitcoin::Network`. Invalid mnemonics/passphrases or mismatches with existing storage should return typed errors, not panic.

## Development guidance

- Preserve existing public APIs unless the task explicitly requires a breaking change.
- Keep key type rules intact:
  - ECDSA must not sign with `P2tr` keys.
  - Schnorr/Taproot signing should use `P2tr` keys.
- Use `next_keypair`, `next_winternitz`, and `next_lamport` when new keys should advance managed indexes.
- Use explicit `derive_*` APIs only when deterministic index selection is required.
- When adding storage fields, consider backward compatibility with existing keystores.
- Use `Zeroizing`/secret wrappers for sensitive temporary strings/bytes where practical.
- Do not introduce debug prints of secret material. Prefer `tracing` with redacted values.
- Run `cargo fmt` before finishing changes.

## Testing tips

- For focused tests, run a specific name, e.g.:

```bash
cargo test test_rsa_signature -- --test-threads=1
cargo test sign_verify_musig2 -- --test-threads=1
```

- For examples:

```bash
cargo run --example sign_verify_ecdsa
cargo run --example sign_verify_schnorr_taproot
cargo run --example sign_verify_winternitz
cargo run --example sign_verify_lamport
cargo run --example rsa
```

- If a storage-related test fails unexpectedly, remove temporary storage paths used by the test or example and rerun sequentially.
