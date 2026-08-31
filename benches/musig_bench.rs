use std::{
    collections::HashMap,
    env, fs,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use bip39::Mnemonic;
use bitcoin::{key::rand::RngCore, secp256k1, Network, PublicKey};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use key_manager::{errors::KeyManagerError, key_manager::KeyManager, key_type::BitcoinKeyType};
use redact::Secret;
use storage_backend::storage_config::StorageConfig;

const REGTEST: Network = Network::Regtest;

// Utilities ---------------

/// Monotonic counter used to produce unique (session_id, message_id) strings
/// for iterations that reuse pre-created KeyManagers.  Avoids building a new
/// KeyManager on every iteration.
static ITER_ID: AtomicU64 = AtomicU64::new(0);

fn next_id() -> String {
    ITER_ID.fetch_add(1, Ordering::Relaxed).to_string()
}

fn random_bytes() -> [u8; 32] {
    let mut seed = [0u8; 32];
    secp256k1::rand::thread_rng().fill_bytes(&mut seed);
    seed
}

/// Returns a unique path under the OS temp dir so parallel benchmark runs
/// and repeated executions don't collide.
fn temp_path() -> String {
    let dir = env::temp_dir();
    let mut rng = secp256k1::rand::thread_rng();
    let index = rng.next_u64();
    dir.join(format!("musig_bench_{}", index))
        .to_str()
        .unwrap()
        .to_string()
}

/// Creates a fresh KeyManager backed by a temporary SQLite storage and
/// derives the participant public key at BIP-44 index 0.
///
/// The KeyManager constructor does:
///   - mnemonic generation / storage
///   - HD seed derivation and storage
///   - Winternitz & Lamport master seed derivation and storage
///   - a second "plain" storage for MuSig2 nonces
///
/// This is deliberately kept out of measured code paths.
fn new_participant(path: &str) -> Result<(KeyManager, PublicKey), KeyManagerError> {
    let mnemonic = Mnemonic::from_entropy(&random_bytes()).unwrap();
    let config = StorageConfig::new(
        path.to_string(),
        Some(Secret::new("secret password_123__ABC".to_string())),
    );
    let km = KeyManager::new(REGTEST, Some(mnemonic), None, &config)?;
    let pk = km.derive_keypair(BitcoinKeyType::P2wpkh, 0)?;
    Ok((km, pk))
}

/// Removes both the primary encrypted storage and the `-plain` MuSig2
/// storage that KeyManager creates automatically.
fn cleanup_storage(path: &str) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_dir_all(path);
    let plain = format!("{}-plain", path);
    let _ = fs::remove_file(&plain);
    let _ = fs::remove_dir_all(&plain);
}

// Setup helpers (not measured — only used in iter_batched setup closures)

/// Holds all state for a 2-participant signing session.
/// Storage is cleaned up automatically when this struct is dropped.
struct TwoParticipantSession {
    km1: KeyManager,
    pk1: PublicKey,
    path1: String,
    km2: KeyManager,
    pk2: PublicKey,
    path2: String,
    agg_pk: PublicKey,
    /// Unique per-iteration session identifier.
    session_id: String,
}

impl Drop for TwoParticipantSession {
    fn drop(&mut self) {
        cleanup_storage(&self.path1);
        cleanup_storage(&self.path2);
    }
}

/// Creates two fresh participants, initializes a MuSig2 session, generates
/// nonces for `message_id`/`message`, and aggregates them.
///
/// The session is left in the state **ready for partial signing**:
/// both participants' nonces are stored and cross-aggregated.
fn setup_2p_ready_to_sign(message_id: &str, message: &[u8]) -> TwoParticipantSession {
    let path1 = temp_path();
    let path2 = temp_path();
    let (km1, pk1) = new_participant(&path1).unwrap();
    let (km2, pk2) = new_participant(&path2).unwrap();

    let participants = vec![pk1, pk2];
    let session_id = next_id();

    // Step 1 – session initialization
    let agg_pk = km1.new_musig2_session(participants.clone(), pk1).unwrap();
    km2.new_musig2_session(participants.clone(), pk2).unwrap();

    // Step 2 – nonce generation
    km1.generate_nonce(message_id, message.to_vec(), &agg_pk, &session_id, None)
        .unwrap();
    km2.generate_nonce(message_id, message.to_vec(), &agg_pk, &session_id, None)
        .unwrap();

    // Step 3 – nonce exchange and aggregation
    let nonces1 = km1.get_my_pub_nonces(&agg_pk, &session_id).unwrap();
    let nonces2 = km2.get_my_pub_nonces(&agg_pk, &session_id).unwrap();

    let mut n_for_1 = HashMap::new();
    n_for_1.insert(pk2, nonces2);
    km1.aggregate_nonces(&agg_pk, &session_id, n_for_1).unwrap();

    let mut n_for_2 = HashMap::new();
    n_for_2.insert(pk1, nonces1);
    km2.aggregate_nonces(&agg_pk, &session_id, n_for_2).unwrap();

    TwoParticipantSession {
        km1,
        pk1,
        path1,
        km2,
        pk2,
        path2,
        agg_pk,
        session_id,
    }
}

/// Extends `setup_2p_ready_to_sign` by computing and saving all partial
/// signatures.  Leaves the session **ready for final aggregation**.
fn setup_2p_ready_to_aggregate(message_id: &str, message: &[u8]) -> TwoParticipantSession {
    let s = setup_2p_ready_to_sign(message_id, message);

    let sigs1 = s
        .km1
        .get_my_partial_signatures(&s.agg_pk, &s.session_id)
        .unwrap();
    let sigs2 = s
        .km2
        .get_my_partial_signatures(&s.agg_pk, &s.session_id)
        .unwrap();

    let mut all_sigs = HashMap::new();
    all_sigs.insert(s.pk1, sigs1);
    all_sigs.insert(s.pk2, sigs2);

    s.km1
        .save_partial_signatures(&s.agg_pk, &s.session_id, all_sigs.clone())
        .unwrap();
    s.km2
        .save_partial_signatures(&s.agg_pk, &s.session_id, all_sigs)
        .unwrap();

    s
}

// Helper: N-participant full round (reusable across bench functions)

/// Executes the complete MuSig2 signing protocol for `participants` over a
/// single message, using `session_id` as the per-iteration session key.
///
/// Each KeyManager in `participants` must have already been created; the
/// function only exercises the MuSig2 API methods from step 1 to step 8.
/// Using `next_id()` for `session_id` ensures no state collision between
/// consecutive benchmark iterations when the same KeyManagers are reused.
fn full_round_n_participants(
    participants: &[(KeyManager, PublicKey)],
    message_id: &str,
    message: &[u8],
    session_id: &str,
) {
    let pub_keys: Vec<PublicKey> = participants.iter().map(|(_, pk)| *pk).collect();
    let n = participants.len();

    // Step 1 – init session for every participant (idempotent for same pub keys)
    let agg_pk = participants[0]
        .0
        .new_musig2_session(pub_keys.clone(), pub_keys[0])
        .unwrap();
    for i in 1..n {
        participants[i]
            .0
            .new_musig2_session(pub_keys.clone(), pub_keys[i])
            .unwrap();
    }

    // Step 2 – generate one nonce per participant
    for (km, _) in participants.iter() {
        km.generate_nonce(message_id, message.to_vec(), &agg_pk, session_id, None)
            .unwrap();
    }

    // Step 3 – collect and cross-aggregate nonces
    let all_nonces: Vec<_> = participants
        .iter()
        .map(|(km, _)| km.get_my_pub_nonces(&agg_pk, session_id).unwrap())
        .collect();

    for (i, (km, _)) in participants.iter().enumerate() {
        let others: HashMap<PublicKey, _> = pub_keys
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(j, pk_j)| (*pk_j, all_nonces[j].clone()))
            .collect();
        km.aggregate_nonces(&agg_pk, session_id, others).unwrap();
    }

    // Step 4 – partial signing
    let partial_sigs: Vec<_> = participants
        .iter()
        .map(|(km, _)| km.get_my_partial_signatures(&agg_pk, session_id).unwrap())
        .collect();

    // Step 5 – distribute and save all partial signatures
    let all_sigs: HashMap<PublicKey, _> = pub_keys.iter().cloned().zip(partial_sigs).collect();

    for (km, _) in participants.iter() {
        km.save_partial_signatures(&agg_pk, session_id, all_sigs.clone())
            .unwrap();
    }

    // Steps 6–8 – aggregate and verify from participant 0's perspective
    let sig = participants[0]
        .0
        .get_aggregated_signature(&agg_pk, session_id, message_id)
        .unwrap();

    participants[0]
        .0
        .verify_final_signature(message_id, sig, agg_pk, session_id)
        .unwrap();
}

/// Same as `full_round_n_participants` but handles `num_messages` messages in
/// a single session.  Only 2 participants are supported here.
fn full_round_n_messages(
    km1: &KeyManager,
    pk1: PublicKey,
    km2: &KeyManager,
    pk2: PublicKey,
    session_id: &str,
    num_messages: usize,
) {
    let participants = vec![pk1, pk2];

    // Step 1 – session initialisation
    let agg_pk = km1.new_musig2_session(participants.clone(), pk1).unwrap();
    km2.new_musig2_session(participants.clone(), pk2).unwrap();

    // Step 2 – generate nonces for every message
    let message_ids: Vec<String> = (0..num_messages).map(|i| format!("msg_{}", i)).collect();
    for msg_id in &message_ids {
        let payload = msg_id.as_bytes().to_vec();
        km1.generate_nonce(msg_id, payload.clone(), &agg_pk, session_id, None)
            .unwrap();
        km2.generate_nonce(msg_id, payload, &agg_pk, session_id, None)
            .unwrap();
    }

    // Step 3 – nonce aggregation (get_my_pub_nonces returns *all* messages at once)
    let nonces1 = km1.get_my_pub_nonces(&agg_pk, session_id).unwrap();
    let nonces2 = km2.get_my_pub_nonces(&agg_pk, session_id).unwrap();

    let mut n_for_1 = HashMap::new();
    n_for_1.insert(pk2, nonces2);
    km1.aggregate_nonces(&agg_pk, session_id, n_for_1).unwrap();

    let mut n_for_2 = HashMap::new();
    n_for_2.insert(pk1, nonces1);
    km2.aggregate_nonces(&agg_pk, session_id, n_for_2).unwrap();

    // Step 4 – partial signing (signs all messages at once)
    let sigs1 = km1.get_my_partial_signatures(&agg_pk, session_id).unwrap();
    let sigs2 = km2.get_my_partial_signatures(&agg_pk, session_id).unwrap();

    // Step 5 – save partial signatures
    let mut all_sigs = HashMap::new();
    all_sigs.insert(pk1, sigs1);
    all_sigs.insert(pk2, sigs2);
    km1.save_partial_signatures(&agg_pk, session_id, all_sigs.clone())
        .unwrap();
    km2.save_partial_signatures(&agg_pk, session_id, all_sigs)
        .unwrap();

    // Steps 6–8 – aggregate and verify every message
    for msg_id in &message_ids {
        let sig = km1
            .get_aggregated_signature(&agg_pk, session_id, msg_id)
            .unwrap();
        km1.verify_final_signature(msg_id, sig, agg_pk, session_id)
            .unwrap();
    }
}

// 1. Session initialisation

/*  Benchmarks `new_musig2_session` in isolation.

    The operation is idempotent — calling it repeatedly with the same
    participants overwrites the same storage keys, so no state accumulates
    that would affect correctness.  What is measured:
    - Key sorting
    - `KeyAggContext::new` (MuSig2 key aggregation algorithm)
    - Two storage writes (participants list + my_pub_key)
*/
fn bench_session_init(c: &mut Criterion) {
    let mut group = c.benchmark_group("musig2_session_init");
    // 63–265 µs per iter: 5s gives thousands of iterations — more than enough for 100 samples.
    group.measurement_time(Duration::from_secs(5));

    for n in [2_usize, 4, 8] {
        // Participants are created once and reused across all iterations.
        let paths: Vec<String> = (0..n).map(|_| temp_path()).collect();
        let participants: Vec<(KeyManager, PublicKey)> =
            paths.iter().map(|p| new_participant(p).unwrap()).collect();
        let pub_keys: Vec<PublicKey> = participants.iter().map(|(_, pk)| *pk).collect();
        let my_key = pub_keys[0];

        group.bench_function(format!("{} participants", n), |b| {
            b.iter(|| {
                participants[0]
                    .0
                    .new_musig2_session(pub_keys.clone(), my_key)
                    .unwrap();
            })
        });

        for p in &paths {
            cleanup_storage(p);
        }
    }

    group.finish();
}

// 2. Nonce generation

/*  Benchmarks `generate_nonce` for a single message in a 2-participant session.

    The session is initialized once; each iteration uses unique (session_id,
    message_id) strings so nonce storage never conflicts.  What is measured:
    - `get_index` read (nonce replay-protection counter)
    - `generate_nonce_seed` (HKDF-SHA256 on the participant's secret key)
    - `SecNonceBuilder` deterministic nonce generation
    - Several storage writes (message, public nonce, secret nonce, message ids)
*/
fn bench_nonce_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("musig2_nonce_generation");
    // ~50 ms per iter: 15s yields ~300 iterations → 100 samples of 3 each.
    group.measurement_time(Duration::from_secs(15));

    let path1 = temp_path();
    let path2 = temp_path();
    let (km1, pk1) = new_participant(&path1).unwrap();
    let (km2, pk2) = new_participant(&path2).unwrap();

    let participants = vec![pk1, pk2];
    let agg_pk = km1.new_musig2_session(participants.clone(), pk1).unwrap();
    km2.new_musig2_session(participants, pk2).unwrap();

    group.bench_function("single nonce (2 participants)", |b| {
        b.iter(|| {
            // Unique IDs ensure each call creates a brand-new storage entry.
            let session_id = next_id();
            let message_id = next_id();
            km1.generate_nonce(
                &message_id,
                b"benchmark message".to_vec(),
                &agg_pk,
                &session_id,
                None,
            )
            .unwrap();
        })
    });

    group.finish();
    cleanup_storage(&path1);
    cleanup_storage(&path2);
}

// 3. Partial signature computation

/* Benchmarks `get_my_partial_signatures` in isolation (the most
    crypto-intensive step).
    `iter_batched` with `PerIteration` ensures the setup (session init +
    nonce aggregation) runs fresh before every measurement so the secret
    nonce is always available.  What is measured:
    - `get_data_for_partial_signatures` (several storage reads)
    - `sign_partial` (Schnorr partial signature computation)
*/
fn bench_partial_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("musig2_partial_signing");
    // iter_batched(PerIteration): setup creates 2 fresh KeyManagers (~100 ms) + measurement (~52 ms)
    // ≈ 1.5 s per sample total. 20 samples × 1.5 s ≈ 30 s.
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(20);

    group.bench_function("compute partial sigs (2 participants, 1 message)", |b| {
        b.iter_batched(
            || setup_2p_ready_to_sign("msg", b"benchmark message"),
            |s| {
                s.km1
                    .get_my_partial_signatures(&s.agg_pk, &s.session_id)
                    .unwrap();
                // `s` drops here → TwoParticipantSession::drop → cleanup_storage
            },
            BatchSize::PerIteration,
        );
    });

    group.finish();
}

// Final signature aggregation

/*  Benchmarks `get_aggregated_signature` in isolation.

    Partial signatures from both participants are already stored before each
    iteration (via `setup_2p_ready_to_aggregate`).  What is measured:
    - `aggregate_partial_signatures` (musig2 crate — Schnorr aggregation)
    - Storage reads for partial signatures and messages
*/
fn bench_aggregate_final_signature(c: &mut Criterion) {
    let mut group = c.benchmark_group("musig2_aggregate_signature");
    // iter_batched(PerIteration): setup = full protocol up to partial sigs (~150 ms), measurement ~1.2 ms.
    // Setup dominates: 20 samples × ~1.57 s/sample = ~31.4 s. Use 35 s to avoid the off-by-one warning.
    group.measurement_time(Duration::from_secs(35));
    group.sample_size(20);

    group.bench_function(
        "aggregate final signature (2 participants, 1 message)",
        |b| {
            b.iter_batched(
                || setup_2p_ready_to_aggregate("msg", b"benchmark message"),
                |s| {
                    s.km1
                        .get_aggregated_signature(&s.agg_pk, &s.session_id, "msg")
                        .unwrap();
                },
                BatchSize::PerIteration,
            );
        },
    );

    group.finish();
}

// 5. Final signature verification

/*  Benchmarks `verify_final_signature` in isolation.

    The aggregated Schnorr signature is pre-computed in the setup closure
    (itself not measured).  What is measured:
    - `verify_single` (musig2    secp256k1 Schnorr verification)
    - Storage reads for the message and aggregated public key
*/
fn bench_verify_final_signature(c: &mut Criterion) {
    let mut group = c.benchmark_group("musig2_verify_signature");
    // iter_batched(PerIteration): setup = full protocol + get_aggregated_signature (~200 ms), measurement ~1 ms.
    // Criterion reported 30 samples needs 154 s → ~2 s/sample. 15 samples × 2 s ≈ 30 s.
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(15);

    group.bench_function("verify final signature (2 participants, 1 message)", |b| {
        b.iter_batched(
            || {
                let s = setup_2p_ready_to_aggregate("msg", b"benchmark message");
                let sig = s
                    .km1
                    .get_aggregated_signature(&s.agg_pk, &s.session_id, "msg")
                    .unwrap();
                (s, sig)
            },
            |(s, sig)| {
                s.km1
                    .verify_final_signature("msg", sig, s.agg_pk, &s.session_id)
                    .unwrap();
            },
            BatchSize::PerIteration,
        );
    });

    group.finish();
}

// Full signing round – varying number of participants

/*  Benchmarks the complete 8-step MuSig2 protocol with 2 and 4 participants
    signing a single message.
    KeyManagers are created once per participant count and reused across
    iterations.  A unique `session_id` is generated per iteration via
    `next_id()` to prevent `NonceAlreadyExists` / `PartialSignatureAlreadyExists`
    errors from the storage layer.  What is measured:
    - All 8 MuSig2 steps end-to-end (including all storage I/O)
    - Scaling behavior: 2 × O(1) vs 4 × O(1) nonce aggregations
*/
fn bench_full_signing_round(c: &mut Criterion) {
    let mut group = c.benchmark_group("musig2_full_signing_round");
    // 2p ~205 ms, 4p ~420 ms per iter. 50 samples × 420 ms = 21 s — fits within 30 s for both.
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(50);

    for n in [2_usize, 4] {
        let paths: Vec<String> = (0..n).map(|_| temp_path()).collect();
        let participants: Vec<(KeyManager, PublicKey)> =
            paths.iter().map(|p| new_participant(p).unwrap()).collect();

        group.bench_function(format!("{} participants / 1 message", n), |b| {
            b.iter(|| {
                let session_id = next_id();
                full_round_n_participants(&participants, "msg", b"benchmark message", &session_id);
            })
        });

        for p in &paths {
            cleanup_storage(p);
        }
    }

    group.finish();
}

// Full signing round – varying number of messages per session

/*  Benchmarks the complete MuSig2 protocol for 2 participants signing 1, 5,
    and 10 messages in a single session.

    This measures how batch signing (multiple messages in one session) scales
    compared to single message signing, and isolates the per-message overhead
    contributed by nonce generation, partial signing, and aggregation.
*/
fn bench_signing_multi_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("musig2_multi_message_round");
    // Per-iter cost scales with message count: ~200 ms (1 msg), ~1 s (5 msgs), ~2 s (10 msgs).
    // 5-msg case needs ~57 s for 10 samples. 60 s covers all three cases cleanly.
    group.measurement_time(Duration::from_secs(60));
    group.sample_size(10);

    let path1 = temp_path();
    let path2 = temp_path();
    let (km1, pk1) = new_participant(&path1).unwrap();
    let (km2, pk2) = new_participant(&path2).unwrap();

    for num_messages in [1_usize, 5, 10] {
        group.bench_function(format!("2 participants / {} messages", num_messages), |b| {
            b.iter(|| {
                let session_id = next_id();
                full_round_n_messages(&km1, pk1, &km2, pk2, &session_id, num_messages);
            })
        });
    }

    group.finish();
    cleanup_storage(&path1);
    cleanup_storage(&path2);
}

criterion_group!(
    benches,
    bench_session_init,
    bench_nonce_generation,
    bench_partial_signing,
    bench_aggregate_final_signature,
    bench_verify_final_signature,
    bench_full_signing_round,
    bench_signing_multi_messages,
);
criterion_main!(benches);
