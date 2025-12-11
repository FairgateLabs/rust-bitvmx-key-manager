#[cfg(test)]
mod tests {
    use crate::{
        musig2::musig::MuSig2SignerApi,
        tests::utils::helper::{clear_output, mock_data},
    };
    use bitcoin::{hex::prelude::*, Network, PrivateKey, PublicKey};
    use musig2::{
        secp::{MaybePoint, MaybeScalar},
        AggNonce,
    };
    use sha2::{Digest as _, Sha256};
    use std::collections::HashMap;

    #[test]
    fn test_final_signature() -> Result<(), anyhow::Error> {
        // Set up test environment
        let (key_manager_1, pub_key_part_1) = mock_data()?;
        let (key_manager_2, pub_key_part_2) = mock_data()?;
        let musig_1 = key_manager_1.musig2();
        let musig_2 = key_manager_2.musig2();

        let participant_pubkeys = vec![pub_key_part_1, pub_key_part_2];
        let message = "message_1";
        let id = "test_id";
        let id2 = "test_id2";
        let aggregated_pub_key_1 =
            musig_1.new_session(participant_pubkeys.clone(), pub_key_part_1)?;
        let aggregated_pub_key_2 =
            musig_2.new_session(participant_pubkeys.clone(), pub_key_part_2)?;

        key_manager_1.generate_nonce(
            message,
            message.as_bytes().to_vec(),
            &aggregated_pub_key_1,
            id,
            None,
        )?;
        key_manager_2.generate_nonce(
            message,
            message.as_bytes().to_vec(),
            &aggregated_pub_key_2,
            id2,
            None,
        )?;

        // Check if the aggregated pub keys are the same
        assert_eq!(aggregated_pub_key_1, aggregated_pub_key_2);

        // Add nonces
        let nonces_1 = musig_1
            .get_my_pub_nonces(&aggregated_pub_key_1, id)
            .unwrap();
        let nonces_2 = musig_2
            .get_my_pub_nonces(&aggregated_pub_key_2, id2)
            .unwrap();
        let mut nonces_map_1 = HashMap::new();
        let mut nonces_map_2 = HashMap::new();
        nonces_map_1.insert(pub_key_part_1, nonces_1.clone());
        nonces_map_2.insert(pub_key_part_2, nonces_2.clone());

        musig_1.aggregate_nonces(&aggregated_pub_key_1, id, nonces_map_2.clone())?;
        musig_2.aggregate_nonces(&aggregated_pub_key_2, id2, nonces_map_1.clone())?;

        // Get partial signatures
        let my_partial_sigs_1 =
            key_manager_1.get_my_partial_signatures(&aggregated_pub_key_1, id)?;
        let my_partial_sigs_2 =
            key_manager_2.get_my_partial_signatures(&aggregated_pub_key_2, id2)?;

        // Verify partial signatures
        let verification_1 = musig_1.verify_partial_signatures(
            &aggregated_pub_key_1,
            id,
            pub_key_part_2,
            my_partial_sigs_2.clone(),
        )?;
        let verification_2 = musig_2.verify_partial_signatures(
            &aggregated_pub_key_2,
            id2,
            pub_key_part_1,
            my_partial_sigs_1.clone(),
        )?;
        assert!(verification_1);
        assert!(verification_2);

        let mut partial_signatures_mapping_1 = HashMap::new();
        partial_signatures_mapping_1.insert(pub_key_part_2, my_partial_sigs_2.clone());
        key_manager_1.save_partial_signatures_multi(
            &aggregated_pub_key_1,
            id,
            partial_signatures_mapping_1,
        )?;
        let mut partial_signatures_mapping_2 = HashMap::new();
        partial_signatures_mapping_2.insert(pub_key_part_1, my_partial_sigs_1.clone());
        key_manager_2.save_partial_signatures_multi(
            &aggregated_pub_key_2,
            id2,
            partial_signatures_mapping_2,
        )?;

        let signature_1 = musig_1.get_aggregated_signature(&aggregated_pub_key_1, id, message)?;
        let signature_2 = musig_2.get_aggregated_signature(&aggregated_pub_key_2, id2, message)?;
        assert_eq!(signature_1, signature_2);

        let verification_1 =
            musig_1.verify_final_signature(&message, signature_1, aggregated_pub_key_1, id)?;

        let verification_2 =
            musig_2.verify_final_signature(&message, signature_2, aggregated_pub_key_2, id2)?;

        assert!(verification_1);
        assert!(verification_2);

        clear_output();

        Ok(())
    }

    // Test to verify the signatures are the same as the manual calculation
    // This test is used to get valid values for the manual verification at protocols and smart contracts
    #[test]
    fn test_verify_signatures() -> Result<(), anyhow::Error> {
        // Private keys obtained from the Mnemonic: "test test test test test test test test test test test junk"
        // this mnemonic is used by anvil and other EVM tools for testing
        // only using 3 as it takes too long to create the key managers
        let private_keys_hexes = [
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
            // "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
            // "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
            // "47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
            // "8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
            // "92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
            // "4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
            // "dbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
            // "2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
        ];

        let mut key_managers = Vec::new();
        for _ in 0..private_keys_hexes.len() {
            let (key_manager, _) = mock_data()?;
            key_managers.push(key_manager);
        }

        let mut pub_key_parts = Vec::new();
        for i in 0..key_managers.len() {
            let private_key = PrivateKey::from_slice(
                Vec::<u8>::from_hex(private_keys_hexes[i])?.as_slice(),
                Network::Regtest,
            )?;
            pub_key_parts.push(key_managers[i].import_private_key(&private_key.to_wif())?);
        }

        let message = "message_1";
        let id = "test_id";

        // Initialize MuSig2 session for each participant
        // and get aggregated public key
        let mut aggregated_pub_key = None;
        for i in 0..key_managers.len() {
            let aggregated_pub_key_new = key_managers[i]
                .new_musig2_session(pub_key_parts.clone(), pub_key_parts[i].clone())?;
            if i == 0 {
                aggregated_pub_key = Some(aggregated_pub_key_new);
            } else {
                assert_eq!(
                    aggregated_pub_key.as_ref().unwrap(),
                    &aggregated_pub_key_new
                );
            }
        }
        let aggregated_pub_key = aggregated_pub_key.unwrap();

        // Generate nonces for each participant
        for i in 0..key_managers.len() {
            key_managers[i].generate_nonce(
                message,
                message.as_bytes().to_vec(),
                &aggregated_pub_key,
                id,
                None,
            )?;
        }

        // Get nonces for each participant
        let mut nonces = Vec::new();
        for i in 0..key_managers.len() {
            let nonces_part = key_managers[i].get_my_pub_nonces(&aggregated_pub_key, id)?;
            nonces.push(nonces_part.clone());
        }

        // Save other participants nonces for each participant
        for i in 0..key_managers.len() {
            let mut nonces_map = HashMap::new();
            for j in 0..pub_key_parts.len() {
                if i == j {
                    continue;
                }
                nonces_map.insert(pub_key_parts[j].clone(), nonces[j].clone());
            }
            key_managers[i].aggregate_nonces(&aggregated_pub_key, id, nonces_map.clone())?;
        }

        // Get partial signatures for each participant
        let mut partial_sigs_map = HashMap::new();
        for i in 0..key_managers.len() {
            let my_partial_sigs =
                key_managers[i].get_my_partial_signatures(&aggregated_pub_key, id)?;
            partial_sigs_map.insert(pub_key_parts[i].clone(), my_partial_sigs.clone());
        }

        // Save partial signatures for each participant
        for i in 0..key_managers.len() {
            key_managers[i].save_partial_signatures(
                &aggregated_pub_key,
                id,
                partial_sigs_map.clone(),
            )?;
        }

        // Get aggregated signature for each participant
        // check that the signatures are the same
        let mut signature = None;
        for i in 0..key_managers.len() {
            let signature_new =
                key_managers[i].get_aggregated_signature(&aggregated_pub_key, id, message)?;
            if i == 0 {
                signature = Some(signature_new);
            } else {
                assert_eq!(signature.as_ref().unwrap(), &signature_new);
            }
        }

        // ------------------- Manual verification of the aggregated nonce -------------------
        // Print the Musig2 Aggregated context to compare with manual calculation
        // let key_agg_context = key_managers[0].get_key_agg_context(&aggregated_pub_key)?;
        // println!("key_agg_context: {:?}", key_agg_context);

        // ------------------- Session Creation Step -------------------
        // Sort participants by public key
        let mut ordered_pubkeys = pub_key_parts.clone();
        ordered_pubkeys.sort();

        // If all pubkeys are the same, `pk2` will be set to `None`, indicating
        // that every public key `X` should be tweaked with a coefficient `H_agg(L, X)`
        // to prevent collisions (See appendix B of the musig2 paper).
        let sorted_pubkeys = ordered_pubkeys.clone();
        let pk2: Option<&PublicKey> = sorted_pubkeys[1..]
            .iter()
            .find(|pubkey| pubkey != &&sorted_pubkeys[0]);

        // Compute the hash of the public keys
        let keyagg_list_tag_hasher = Sha256::digest("KeyAgg list");
        let mut h = Sha256::new()
            .chain_update(&keyagg_list_tag_hasher)
            .chain_update(&keyagg_list_tag_hasher)
            .clone();
        for i in 0..ordered_pubkeys.len() {
            h = h.chain_update(ordered_pubkeys[i].inner.serialize());
        }
        let pk_list_hash: [u8; 32] = h.finalize().into();

        // Compute the effective pubkeys and key coefficients
        let mut effective_pubkeys_map = HashMap::new();
        let mut effective_pubkeys = Vec::new();
        let mut key_coefficients = Vec::new();
        for i in 0..ordered_pubkeys.len() {
            let key_coefficient = if pk2.is_some_and(|pk2| ordered_pubkeys[i] == *pk2) {
                MaybeScalar::one()
            } else {
                let keyagg_coeff_tag_hasher = Sha256::digest("KeyAgg coefficient");
                let hash: [u8; 32] = Sha256::new()
                    .chain_update(&keyagg_coeff_tag_hasher)
                    .chain_update(&keyagg_coeff_tag_hasher)
                    .chain_update(pk_list_hash)
                    .chain_update(ordered_pubkeys[i].inner.serialize())
                    .finalize()
                    .into();
                MaybeScalar::reduce_from(&hash)
            };
            let effective_pubkey =
                MaybePoint::from_slice(ordered_pubkeys[i].inner.serialize().as_slice()).unwrap()
                    * key_coefficient;
            effective_pubkeys.push(effective_pubkey.clone());
            key_coefficients.push(key_coefficient);
            // store a map with the pubkey and the effective pubkey to easily obtain it for verification
            effective_pubkeys_map.insert(ordered_pubkeys[i].clone(), effective_pubkey.clone());
        }

        // Compute the aggregated pubkey
        let aggregated_pubkey_manual = MaybePoint::sum(&effective_pubkeys).not_inf()?;
        assert_eq!(
            aggregated_pub_key.inner.serialize(),
            aggregated_pubkey_manual.serialize()
        );

        // ------------------- Nonce Aggregation Step -------------------
        // Get the aggregated nonce to check manual calculation
        let aggregated_nonce =
            AggNonce::sum(nonces.iter().flat_map(|v| v.iter().map(|(_, pn)| pn)));

        // Manual calculation of the aggregated nonce (as its a sum no need to be ordered by pubkey)
        let adaptor_point = MaybePoint::Infinity;
        let mut aggregated_nonce_r1 = MaybePoint::Infinity;
        let mut aggregated_nonce_r2 = MaybePoint::Infinity;
        for nonce in nonces.iter().flat_map(|v| v.iter().map(|(_, pn)| pn)) {
            aggregated_nonce_r1 = aggregated_nonce_r1 + nonce.R1;
            aggregated_nonce_r2 = aggregated_nonce_r2 + nonce.R2;
        }
        assert_eq!(aggregated_nonce_r1, aggregated_nonce.R1);
        assert_eq!(aggregated_nonce_r2, aggregated_nonce.R2);

        // ------------------- Nonce Coefficient Step -------------------
        // Compute the nonce coefficient
        let (xonly_aggregated_pub_key, aggregated_pub_key_parity) =
            aggregated_pub_key.inner.x_only_public_key();
        let musig_noncecoef_tag_hasher = Sha256::digest("MuSig/noncecoef");
        let hash: [u8; 32] = Sha256::new()
            .chain_update(&musig_noncecoef_tag_hasher)
            .chain_update(&musig_noncecoef_tag_hasher)
            .chain_update(&aggregated_nonce_r1.serialize())
            .chain_update(&aggregated_nonce_r2.serialize())
            .chain_update(&xonly_aggregated_pub_key.serialize())
            .chain_update(message)
            .finalize()
            .into();

        // b = nonce_coefficient
        let b = MaybeScalar::reduce_from(&hash);
        let final_nonce = aggregated_nonce_r1 + (b * aggregated_nonce_r2);
        let adapted_nonce = final_nonce + adaptor_point;

        // get inidividual pubkey and pubnonce
        let individual_pubkey = pub_key_parts[0].clone();
        let individual_pubnonce = nonces[0].get(0).unwrap().1.clone();
        let mut effective_nonce = individual_pubnonce.R1 + b * individual_pubnonce.R2;

        // if has odd y use the negative point to get even y
        if adapted_nonce.has_odd_y() {
            effective_nonce = -effective_nonce;
        }
        let nonce_x_bytes = adapted_nonce.serialize_xonly();

        // ------------------- Challenge Hash Tweak and Parity Step -------------------
        // compute_challenge_hash_tweak
        let bip0340_challenge_tag_hasher = Sha256::digest("BIP0340/challenge");
        let hash: [u8; 32] = Sha256::new()
            .chain_update(&bip0340_challenge_tag_hasher)
            .chain_update(&bip0340_challenge_tag_hasher)
            .chain_update(&nonce_x_bytes)
            .chain_update(&xonly_aggregated_pub_key.serialize())
            .chain_update(message)
            .finalize()
            .into();
        let e = MaybeScalar::reduce_from(&hash);

        let effective_pubkey = effective_pubkeys_map
            .get(&individual_pubkey)
            .unwrap()
            .clone();

        // s * G == R + (g * gacc * e * a * P)
        let challenge_parity = aggregated_pub_key_parity;
        // if there is a tweak, we should use it to calculate the parity
        // let challenge_parity = aggregated_pub_key_parity ^ key_agg_ctx.parity_acc;
        let mut challenge_point = e * effective_pubkey;
        if challenge_parity == bitcoin::secp256k1::Parity::Odd {
            challenge_point = -challenge_point;
        }

        // ------------------- Verification Step -------------------
        let partial_signature = partial_sigs_map
            .get(&individual_pubkey)
            .unwrap()
            .get(0)
            .unwrap()
            .1;

        assert_eq!(
            partial_signature * musig2::secp::G,
            effective_nonce + challenge_point,
        );

        // ------------------- End of manual verification of the partial signatures -------------------

        clear_output();

        Ok(())
    }
}
