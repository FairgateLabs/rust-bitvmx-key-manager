#[cfg(test)]
mod musig2_tests {
    use crate::{
        errors::KeyManagerError,
        key_manager::KeyManager,
        musig2::{errors::Musig2SignerError, musig::MuSig2SignerApi},
        tests::utils::helper::{clear_output, mock_data},
    };
    use bitcoin::PublicKey;
    use musig2::PartialSignature;
    use std::collections::HashMap;

    struct SessionCtx {
        km1: KeyManager,
        km2: KeyManager,
        pk1: PublicKey,
        pk2: PublicKey,
        agg: PublicKey,
        id1: String,
        id2: String,
    }

    fn create_session(message: &str) -> Result<SessionCtx, anyhow::Error> {
        let (km1, pk1) = mock_data()?;
        let (km2, pk2) = mock_data()?;
        let participants = vec![pk1, pk2];
        let id1 = "sid_1".to_string();
        let id2 = "sid_2".to_string();

        let agg = km1.musig2().new_session(participants.clone(), pk1)?;
        km2.musig2().new_session(participants.clone(), pk2)?;

        km1.generate_nonce(message, message.as_bytes().to_vec(), &agg, &id1, None)?;
        km2.generate_nonce(message, message.as_bytes().to_vec(), &agg, &id2, None)?;

        let n1 = km1.musig2().get_my_pub_nonces(&agg, &id1)?;
        let n2 = km2.musig2().get_my_pub_nonces(&agg, &id2)?;

        let mut map1 = HashMap::new();
        map1.insert(pk2, n2);
        km1.musig2().aggregate_nonces(&agg, &id1, map1)?;

        let mut map2 = HashMap::new();
        map2.insert(pk1, n1);
        km2.musig2().aggregate_nonces(&agg, &id2, map2)?;

        Ok(SessionCtx { km1, km2, pk1, pk2, agg, id1, id2 })
    }

    fn create_session_with_partials(
        message: &str,
    ) -> Result<(SessionCtx, Vec<(String, PartialSignature)>, Vec<(String, PartialSignature)>), anyhow::Error>
    {
        let ctx = create_session(message)?;
        let ps1 = ctx.km1.get_my_partial_signatures(&ctx.agg, &ctx.id1)?;
        let ps2 = ctx.km2.get_my_partial_signatures(&ctx.agg, &ctx.id2)?;
        Ok((ctx, ps1, ps2))
    }

    #[test]
    fn test_session_init_order_invariant() -> Result<(), anyhow::Error> {
        let (km, pk1) = mock_data()?;
        let (_, pk2) = mock_data()?;
        let (_, pk3) = mock_data()?;

        let agg_a = km.musig2().new_session(vec![pk1, pk2, pk3], pk1)?;
        let agg_b = km.musig2().new_session(vec![pk3, pk1, pk2], pk1)?;

        assert_eq!(agg_a, agg_b);
        clear_output();
        Ok(())
    }

    #[test]
    fn test_session_init_single_participant() -> Result<(), anyhow::Error> {
        let (km, pk) = mock_data()?;
        let result = km.musig2().new_session(vec![pk], pk);
        assert!(matches!(
            result,
            Err(Musig2SignerError::InvalidNumberOfParticipants)
        ));
        clear_output();
        Ok(())
    }

    #[test]
    fn test_session_init_self_key_not_included() -> Result<(), anyhow::Error> {
        let (km, pk1) = mock_data()?;
        let (_, pk2) = mock_data()?;
        let (_, pk3) = mock_data()?;
        let result = km.musig2().new_session(vec![pk2, pk3], pk1);
        assert!(matches!(
            result,
            Err(Musig2SignerError::InvalidNumberOfParticipants)
        ));
        clear_output();
        Ok(())
    }

    #[test]
    fn test_nonce_determinism_and_uniqueness() -> Result<(), anyhow::Error> {
        let (km1, pk1) = mock_data()?;
        let (km2, pk2) = mock_data()?;
        let (_, pk3) = mock_data()?;
        let id = "det_id";

        let agg_a = km1.musig2().new_session(vec![pk1, pk2], pk1)?;
        km1.generate_nonce("m1", b"m1".to_vec(), &agg_a, id, None)?;

        let nonce_a1 = km1.musig2().get_my_pub_nonces(&agg_a, id)?;
        let nonce_a2 = km1.musig2().get_my_pub_nonces(&agg_a, id)?;
        assert_eq!(nonce_a1, nonce_a2);

        let agg_b = km2.musig2().new_session(vec![pk2, pk3], pk2)?;
        km2.generate_nonce("m1", b"m1".to_vec(), &agg_b, id, None)?;
        let nonce_b = km2.musig2().get_my_pub_nonces(&agg_b, id)?;
        assert_ne!(nonce_a1, nonce_b);

        clear_output();
        Ok(())
    }

    #[test]
    fn test_get_pub_nonces_before_generation() -> Result<(), anyhow::Error> {
        let (km, pk1) = mock_data()?;
        let (_, pk2) = mock_data()?;

        let agg = km.musig2().new_session(vec![pk1, pk2], pk1)?;
        let result = km.musig2().get_my_pub_nonces(&agg, "sid");
        assert!(matches!(result, Err(Musig2SignerError::NoncesNotGenerated)));

        clear_output();
        Ok(())
    }

    #[test]
    fn test_aggregate_nonces_valid() -> Result<(), anyhow::Error> {
        let ctx = create_session("m")?;

        let ps = ctx.km1.get_my_partial_signatures(&ctx.agg, &ctx.id1);
        assert!(ps.is_ok());

        clear_output();
        Ok(())
    }

    #[test]
    fn test_aggregate_nonces_invalid_pubkey() -> Result<(), anyhow::Error> {
        let (km, pk1) = mock_data()?;
        let (_, pk2) = mock_data()?;
        let id = "inv_pk";

        let agg = km.musig2().new_session(vec![pk1, pk2], pk1)?;
        km.generate_nonce("m", b"m".to_vec(), &agg, id, None)?;

        let n1 = km.musig2().get_my_pub_nonces(&agg, id)?;
        let mut map = HashMap::new();
        map.insert(pk1, n1);
        let result = km.musig2().aggregate_nonces(&agg, id, map);

        assert!(matches!(result, Err(Musig2SignerError::InvalidPublicKey)));
        clear_output();
        Ok(())
    }

    #[test]
    fn test_aggregate_nonces_duplicate() -> Result<(), anyhow::Error> {
        let (km, pk1) = mock_data()?;
        let (_, pk2) = mock_data()?;
        let id = "dup_nonce";

        let agg = km.musig2().new_session(vec![pk1, pk2], pk1)?;
        km.generate_nonce("m", b"m".to_vec(), &agg, id, None)?;

        let nonces = km.musig2().get_my_pub_nonces(&agg, id)?;
        let mut map = HashMap::new();
        map.insert(pk2, nonces);

        km.musig2().aggregate_nonces(&agg, id, map.clone())?;
        let result = km.musig2().aggregate_nonces(&agg, id, map);
        assert!(matches!(result, Err(Musig2SignerError::NonceAlreadyExists)));

        clear_output();
        Ok(())
    }

    #[test]
    fn test_partial_signatures_require_nonces() -> Result<(), anyhow::Error> {
        let (km, pk1) = mock_data()?;
        let (_, pk2) = mock_data()?;
        let id = "need_nonces";

        let agg = km.musig2().new_session(vec![pk1, pk2], pk1)?;
        km.generate_nonce("m", b"m".to_vec(), &agg, id, None)?;

        let result = km.get_my_partial_signatures(&agg, id);
        assert!(matches!(
            result,
            Err(KeyManagerError::Musig2SignerError(
                Musig2SignerError::IncompleteParticipantNonces
            ))
        ));

        clear_output();
        Ok(())
    }

    #[test]
    fn test_save_partial_signatures_duplicate() -> Result<(), anyhow::Error> {
        let (ctx, ps1, ps2) = create_session_with_partials("msg_dup")?;

        let mut all = HashMap::new();
        all.insert(ctx.pk1, ps1);
        all.insert(ctx.pk2, ps2);

        ctx.km1.save_partial_signatures(&ctx.agg, &ctx.id1, all.clone())?;

        let result = ctx.km1.save_partial_signatures(&ctx.agg, &ctx.id1, all);
        assert!(matches!(
            result,
            Err(KeyManagerError::Musig2SignerError(
                Musig2SignerError::PartialSignatureAlreadyExists
            ))
        ));

        clear_output();
        Ok(())
    }

    #[test]
    fn test_save_partial_signatures_invalid_message_id() -> Result<(), anyhow::Error> {
        let (ctx, ps1, ps2) = create_session_with_partials("msg_inv")?;

        let bad_ps2: Vec<(String, PartialSignature)> = ps2
            .into_iter()
            .map(|(_, sig)| ("nonexistent_msg".to_string(), sig))
            .collect();

        let mut map = HashMap::new();
        map.insert(ctx.pk1, ps1);
        map.insert(ctx.pk2, bad_ps2);

        let result = ctx.km1.save_partial_signatures(&ctx.agg, &ctx.id1, map);
        assert!(matches!(
            result,
            Err(KeyManagerError::Musig2SignerError(
                Musig2SignerError::InvalidMessageId
            ))
        ));

        clear_output();
        Ok(())
    }

    #[test]
    fn test_verify_partial_signatures_positive() -> Result<(), anyhow::Error> {
        let (ctx, _ps1, ps2) = create_session_with_partials("verify_pos")?;

        let ok = ctx.km1
            .musig2()
            .verify_partial_signatures(&ctx.agg, &ctx.id1, ctx.pk2, ps2)?;
        assert!(ok);

        clear_output();
        Ok(())
    }

    #[test]
    fn test_verify_partial_signatures_tampered() -> Result<(), anyhow::Error> {
        let (ctx, _ps1, ps2) = create_session_with_partials("verify_neg")?;

        let tampered: Vec<(String, PartialSignature)> = ps2
            .into_iter()
            .map(|(mid, sig)| {
                let mut bytes = sig.serialize();
                bytes[0] ^= 0xFF;
                (mid, PartialSignature::from_slice(&bytes).unwrap())
            })
            .collect();

        let result = ctx.km1
            .musig2()
            .verify_partial_signatures(&ctx.agg, &ctx.id1, ctx.pk2, tampered);
        assert!(matches!(
            result,
            Err(Musig2SignerError::InvalidPartialSignature)
        ));

        clear_output();
        Ok(())
    }

    #[test]
    fn test_final_signature_aggregation_and_verify() -> Result<(), anyhow::Error> {
        let msg = "final_sig";
        let (ctx, ps1, ps2) = create_session_with_partials(msg)?;

        let mut all1 = HashMap::new();
        all1.insert(ctx.pk1, ps1.clone());
        all1.insert(ctx.pk2, ps2.clone());

        let mut all2 = HashMap::new();
        all2.insert(ctx.pk1, ps1);
        all2.insert(ctx.pk2, ps2);

        ctx.km1.save_partial_signatures(&ctx.agg, &ctx.id1, all1)?;
        ctx.km2.save_partial_signatures(&ctx.agg, &ctx.id2, all2)?;

        let sig1 = ctx.km1.get_aggregated_signature(&ctx.agg, &ctx.id1, msg)?;
        let sig2 = ctx.km2.get_aggregated_signature(&ctx.agg, &ctx.id2, msg)?;
        assert_eq!(sig1, sig2);

        assert!(ctx.km1.verify_final_signature(msg, sig1, ctx.agg, &ctx.id1)?);
        assert!(ctx.km2.verify_final_signature(msg, sig2, ctx.agg, &ctx.id2)?);

        clear_output();
        Ok(())
    }

    #[test]
    fn test_verify_final_signature_invalid_length() -> Result<(), anyhow::Error> {
        let msg = "inv_len";
        let (ctx, ps1, ps2) = create_session_with_partials(msg)?;

        let mut all = HashMap::new();
        all.insert(ctx.pk1, ps1);
        all.insert(ctx.pk2, ps2);
        ctx.km1.save_partial_signatures(&ctx.agg, &ctx.id1, all)?;

        let valid_sig = ctx.km1.get_aggregated_signature(&ctx.agg, &ctx.id1, msg)?;

        // Truncated (32 bytes)
        let short = &valid_sig.serialize()[..32];
        assert!(bitcoin::secp256k1::schnorr::Signature::from_slice(short).is_err());

        // Extended (65 bytes)
        let mut extended = valid_sig.serialize().to_vec();
        extended.push(0x00);
        assert!(bitcoin::secp256k1::schnorr::Signature::from_slice(&extended).is_err());

        // Valid length but corrupted bytes
        let mut bad_bytes = valid_sig.serialize();
        bad_bytes[0] ^= 0xFF;
        let bad_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&bad_bytes)?;
        let result = ctx.km1.verify_final_signature(msg, bad_sig, ctx.agg, &ctx.id1);
        assert!(matches!(
            result,
            Err(KeyManagerError::Musig2SignerError(
                Musig2SignerError::InvalidFinalSignature
            ))
        ));

        clear_output();
        Ok(())
    }

    #[test]
    fn test_api_aliasing_get_my_public_key_vs_get_pubkey() -> Result<(), anyhow::Error> {
        let (km, pk1) = mock_data()?;
        let (_, pk2) = mock_data()?;

        let agg = km.musig2().new_session(vec![pk1, pk2], pk1)?;

        let from_get_my_public_key = km.get_my_public_key(&agg)?;
        let from_get_pubkey = km.get_pubkey(&agg)?;
        assert_eq!(from_get_my_public_key, from_get_pubkey);

        clear_output();
        Ok(())
    }

    #[test]
    fn test_get_key_pair_for_too_insecure() -> Result<(), anyhow::Error> {
        let (km, pk1) = mock_data()?;
        let (_, pk2) = mock_data()?;

        let agg = km.musig2().new_session(vec![pk1, pk2], pk1)?;

        let (sk, pk) = km.get_key_pair_for_too_insecure(&agg)?;
        assert_eq!(pk, pk1);

        let derived_pk = PublicKey::from_private_key(&bitcoin::secp256k1::Secp256k1::new(), &sk);
        assert_eq!(derived_pk, pk);

        clear_output();
        Ok(())
    }
}
