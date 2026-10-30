#[cfg(test)]
mod tests {
    use crate::key_manager::KeyManager;
    use crate::key_type::BitcoinKeyType;
    use crate::musig2::musig::MuSig2SignerApi;
    use crate::tests::utils::helper::{clear_output, generate_random_string};
    use bip39::Mnemonic;
    use bitcoin::PublicKey;
    use redact::Secret;
    use storage_backend::storage_config::StorageConfig;

    /// Two key managers from one mnemonic, each with its own store.
    ///
    /// `mock_data` generates a random mnemonic, which is right for
    /// every other test here and wrong for this one: the whole
    /// question is whether two signers holding the *same* key derive
    /// the same nonces down two different code paths.
    fn same_signer_twice() -> Result<(KeyManager, KeyManager), anyhow::Error> {
        let phrase = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon about";
        let mut made = Vec::new();
        for _ in 0..2 {
            let path = format!("test_output/{}", generate_random_string());
            let config = StorageConfig::new(
                path,
                Some(Secret::from("secret password_123__ABC".to_string())),
            );
            made.push(KeyManager::new(
                bitcoin::Network::Regtest,
                Some(Mnemonic::parse(phrase)?),
                None,
                &config,
            )?);
        }
        let second = made.pop().expect("two");
        let first = made.pop().expect("two");
        Ok((first, second))
    }

    /// `generate_nonces` produces exactly what `generate_nonce` in a
    /// loop produces.
    ///
    /// Equivalent is not enough. Both sides of a MuSig2 session
    /// normally run the same code, so a batch that derived *different*
    /// nonces would still produce signatures that verify, and no test
    /// that drives one session would notice. What it would break is a
    /// signer that committed through one path and came back through
    /// the other --- which is what upgrading a running node is, and
    /// two nonces for one message is the one thing MuSig2 does not
    /// survive.
    ///
    /// So: one mnemonic, two stores, the same six messages, one path
    /// each.
    #[test]
    fn batched_nonces_match_the_one_at_a_time_path() -> Result<(), anyhow::Error> {
        let (one_at_a_time, all_at_once) = same_signer_twice()?;

        // The same session on both, from the same two participants.
        let other = PublicKey::from_slice(&[
            0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95,
            0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09,
            0xb9, 0x5c, 0x70, 0x9e, 0xe5,
        ])?;
        let id = "a_session";
        let mut aggregated = Vec::new();
        for km in [&one_at_a_time, &all_at_once] {
            let mine = km.derive_keypair(BitcoinKeyType::P2wpkh, 0)?;
            aggregated.push(km.musig2().new_session(vec![mine, other], mine)?);
        }

        let items: Vec<(String, Vec<u8>, Option<musig2::secp256k1::Scalar>)> = (0u8..6)
            .map(|i| (format!("message_{i}"), vec![i; 32], None))
            .collect();

        for (message_id, message, tweak) in &items {
            one_at_a_time.generate_nonce(
                message_id,
                message.clone(),
                &aggregated[0],
                id,
                *tweak,
            )?;
        }
        all_at_once.generate_nonces(&items, &aggregated[1], id)?;

        for (message_id, _, _) in &items {
            assert_eq!(
                one_at_a_time
                    .musig2()
                    .get_my_pub_nonce(&aggregated[0], id, message_id)?
                    .serialize(),
                all_at_once
                    .musig2()
                    .get_my_pub_nonce(&aggregated[1], id, message_id)?
                    .serialize(),
                "{message_id}: the batch must commit to the nonce the loop would have"
            );
        }

        // And they are not all one nonce, which is the one way the
        // assertion above could hold while being catastrophically
        // wrong.
        let first = all_at_once
            .musig2()
            .get_my_pub_nonce(&aggregated[1], id, &items[0].0)?
            .serialize();
        for (message_id, _, _) in &items[1..] {
            assert_ne!(
                all_at_once
                    .musig2()
                    .get_my_pub_nonce(&aggregated[1], id, message_id)?
                    .serialize(),
                first,
                "every message must get its own nonce"
            );
        }

        clear_output();
        Ok(())
    }

    /// Asking twice changes nothing, as asking twice for one message
    /// changes nothing.
    ///
    /// The skip has to happen before an index is taken, or a retried
    /// batch would consume indices for messages it then declines to
    /// write --- harmless in itself, but it is also what keeps the
    /// batch and the loop in step.
    #[test]
    fn a_second_batch_leaves_the_first_alone() -> Result<(), anyhow::Error> {
        let (km, _) = same_signer_twice()?;
        let other = PublicKey::from_slice(&[
            0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95,
            0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09,
            0xb9, 0x5c, 0x70, 0x9e, 0xe5,
        ])?;
        let id = "a_session";
        let mine = km.derive_keypair(BitcoinKeyType::P2wpkh, 0)?;
        let aggregated = km.musig2().new_session(vec![mine, other], mine)?;

        let items: Vec<(String, Vec<u8>, Option<musig2::secp256k1::Scalar>)> = (0u8..3)
            .map(|i| (format!("message_{i}"), vec![i; 32], None))
            .collect();

        km.generate_nonces(&items, &aggregated, id)?;
        let before: Vec<_> = items
            .iter()
            .map(|(message_id, _, _)| {
                km.musig2()
                    .get_my_pub_nonce(&aggregated, id, message_id)
                    .map(|n| n.serialize())
            })
            .collect::<Result<_, _>>()?;

        km.generate_nonces(&items, &aggregated, id)?;
        for ((message_id, _, _), was) in items.iter().zip(before) {
            assert_eq!(
                km.musig2()
                    .get_my_pub_nonce(&aggregated, id, message_id)?
                    .serialize(),
                was,
                "{message_id}: a committed nonce must not be replaced"
            );
        }

        // And the message-id list did not gain duplicates.
        let listed = km.musig2().get_my_pub_nonces(&aggregated, id)?;
        assert_eq!(listed.len(), items.len());

        clear_output();
        Ok(())
    }
}
