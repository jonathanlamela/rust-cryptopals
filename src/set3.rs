#[cfg(test)]
mod tests {
    use crate::base64::Base64;

    use crate::crypters::CustomCrypter17;
    use crate::cryptovec::CryptoVec;
    use crate::mt19937::{clone_mt19937, untemper, MT19937};
    use crate::usizecrypt::USizeCrypt;

    use rand::Rng;
    use std::fs::File;
    use std::io::prelude::*;
    use std::io::BufReader;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    pub fn challenge_17() {
        // Create an instance of CustomCrypter17
        let crypter = CustomCrypter17::new().unwrap();

        // Block size
        const BLOCK_SIZE: usize = 16;

        // Initialize the key and IV with random 16-byte values
        let key = BLOCK_SIZE.random_block();
        let iv = BLOCK_SIZE.random_block();

        // Get the value to decrypt from position 8 of the tokens obtained from CustomCrypter17
        let clear_value = Base64::from_string(crypter.get_all_tokens().get(8).unwrap().to_string());
        let clear_bytes = clear_value.to_bytes().unwrap();

        // Perform CBC encryption of the bytes with the provided key and IV
        let encrypted_value = clear_bytes.to_vec().ssl_cbc_encrypt(&key, &iv, Some(false));

        match encrypted_value {
            Ok(ciphertext) => {
                // Initialize the cleartext_encrypted vector to hold the encrypted plaintext
                let mut cleartext_encrypted = vec![0; ciphertext.len()];
                let mut prev = iv.clone();

                // Divide the ciphertext into blocks
                let chunks = ciphertext.chunks(BLOCK_SIZE);

                // Iterate over each encrypted block
                for (block_index, block) in chunks.enumerate() {
                    let block_offset = block_index * BLOCK_SIZE;

                    // Iterate backwards within the block
                    for i in (0..BLOCK_SIZE).rev() {
                        let padding = (BLOCK_SIZE - i) as u8;
                        let t = [(padding - 1) ^ padding];
                        let xor_res = prev[i + 1..].to_vec().xor_single(t[0]);
                        prev[i + 1..].copy_from_slice(&xor_res);

                        // Try all possible values for the last byte of the previous block
                        for u in 0u8..=255 {
                            prev[i] ^= u;
                            let value_decrypted =
                                block.to_vec().ssl_cbc_decrypt(&key, &prev, Some(true));

                            // Verify if the value has been decrypted correctly
                            if value_decrypted.is_ok()
                                && (i < BLOCK_SIZE - 1 || {
                                    prev[i - 1] ^= 1;
                                    let result =
                                        block.to_vec().ssl_cbc_decrypt(&key, &prev, Some(true));
                                    prev[i - 1] ^= 1;
                                    result.is_ok()
                                })
                            {
                                // Calculate the new plaintext byte
                                let new_content = padding ^ u;
                                cleartext_encrypted[block_offset + i] = new_content;

                                break;
                            }
                            prev[i] ^= u;
                        }
                    }
                    prev = block.to_vec();
                }

                // Remove padding from decrypted bytes
                let _ = cleartext_encrypted.unpad(16);

                // Decrypt the original bytes and those obtained after the process
                let decrypted_first = clear_bytes.ssl_cbc_decrypt(&key, &iv, Some(false));
                let decrypted_second = cleartext_encrypted.ssl_cbc_decrypt(&key, &iv, Some(false));

                // Verify that the two decrypted texts are equal
                assert_eq!(decrypted_first.unwrap(), decrypted_second.unwrap());
            }
            Err(_) => {}
        }
    }

    #[test]
    pub fn challenge_18() {
        // Base64-encoded ciphertext to decrypt (AES-CTR mode, key: "YELLOW SUBMARINE")
        let ciphertext = Base64::from_string(String::from(
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
        ));

        // Decode the Base64 ciphertext to bytes, then decrypt using AES-CTR with the given key
        let cleartext = ciphertext
            .to_bytes()
            .unwrap()
            .ssl_ctr_decrypt(b"YELLOW SUBMARINE", Some(true))
            .unwrap();

        // Convert the decrypted bytes to a UTF-8 string
        let result = String::from_utf8_lossy(&cleartext);

        // Assert that the decrypted string matches the expected plaintext
        assert_eq!(
            result,
            "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
        )
    }

    #[test]
    pub fn challenge_19() {
        // Block size
        const BLOCK_SIZE: usize = 16;

        // Generate a random key
        let key = BLOCK_SIZE.random_block();

        // Read the file data_19
        let file_path = "./data/data_19.txt";
        let file = File::open(file_path).expect("Unable to read the file");
        let buf_reader = BufReader::new(file);

        let mut results: Vec<Vec<u8>> = Vec::new();

        // Read the file line by line
        for line in buf_reader.lines() {
            // If reading the line was successful
            if line.is_ok() {
                // Get the content of the line
                let unwrapped_line = line.unwrap();
                let line_bytes = Base64::from_string(unwrapped_line);

                if let Ok(bytes) = line_bytes.to_bytes() {
                    if let Ok(encrypt_result) = bytes.nonce_ctr_encrypt(&key, vec![0; 8]) {
                        results.push(encrypt_result);
                    }
                }
            }
        }

        assert!(results.len() != 0);
    }

    #[test]
    pub fn challenge_20() {
        // Block size
        const BLOCK_SIZE: usize = 16;

        // Generate a random key
        let key = BLOCK_SIZE.random_block();

        // Read the file data_19
        let file_path = "./data/data_20.txt";
        let file = File::open(file_path).expect("Unable to read the file");
        let buf_reader = BufReader::new(file);

        let mut results: Vec<Vec<u8>> = Vec::new();

        // Read the file line by line
        for line in buf_reader.lines() {
            // If reading the line was successful
            if line.is_ok() {
                // Get the content of the line
                let unwrapped_line = line.unwrap();

                // Convert the Base64 string to bytes
                let line_bytes = Base64::from_string(unwrapped_line);

                if let Ok(bytes) = line_bytes.to_bytes() {
                    // Encrypt the bytes using AES-CTR with zero nonce
                    if let Ok(encrypt_result) = bytes.nonce_ctr_encrypt(&key, vec![0; 8]) {
                        results.push(encrypt_result);
                    }
                }
            }
        }

        // Get the minimum length of the ciphertext results
        let min = results.iter().map(|c| c.len()).min().unwrap();

        // Truncate all results to the minimum length
        for ciphertext in &mut results {
            ciphertext.truncate(min);
        }

        // Transpose the ciphertext results for a repeated XOR attack
        let mut transposed: Vec<Vec<u8>> = vec![vec![]; min];
        for string in &results {
            for i in 0..string.len() {
                let item = string[i];
                transposed[i].push(item);
            }
        }

        // Initialize a vector for the decryption key.
        let mut k_vec: Vec<u8> = Vec::new();

        // Perform the repeated XOR attack on the data blocks.
        for bl in transposed {
            match bl.evaluate_frequency() {
                // If frequency analysis returns a possible key
                Some((_, key, _)) => k_vec.push(key),
                // Otherwise, continue with the next block
                None => {}
            }
        }

        // Combine all ciphertext results into a single vector
        let flat_result: Vec<u8> = results.into_iter().flat_map(|f| f).collect();

        // Apply the XOR operation with the found decryption key
        let res = flat_result.repeating_key_xor(&k_vec);

        // Convert the decrypted results into a UTF-8 string
        let res_plain = String::from_utf8(res).unwrap();

        // Verify that the decrypted string contains the desired substring
        assert!(res_plain.contains("I'm rated"));
    }

    // Test the MT19937 Mersenne Twister RNG implementation (challenge 21).
    #[test]
    pub fn challenge_21() {
        // Verify that MT19937 with known seed 5489 produces the reference outputs
        let mut mt = MT19937::new(5489);
        let expected = [3499211612u32, 581869302, 3890346734, 3586334585, 545404204];
        for &exp in &expected {
            let val = mt.extract_number();
            assert_eq!(val, exp);
        }

        // Verify that two instances with the same seed produce identical sequences
        let mut mt1 = MT19937::new(0);
        let mut mt2 = MT19937::new(0);
        for _ in 0..100 {
            assert_eq!(mt1.extract_number(), mt2.extract_number());
        }

        // Verify that different seeds produce different sequences
        let mut mt_a = MT19937::new(42);
        let mut mt_b = MT19937::new(43);
        let out_a = mt_a.extract_number();
        let out_b = mt_b.extract_number();
        assert_ne!(out_a, out_b);

        // Verify untemper correctly inverts temper for random values
        let mut mt_check = MT19937::new(12345);
        for _ in 0..10 {
            let tempered = mt_check.extract_number();
            // untemper should recover the internal state value before tempering
            let recovered = untemper(tempered);
            // Re-temper recovered value should give the same output
            let mut y = recovered;
            y ^= (y >> 11) & 0xFFFFFFFF;
            y ^= (y << 7) & 0x9D2C5680;
            y ^= (y << 15) & 0xEFC60000;
            y ^= y >> 18;
            assert_eq!(y, tempered);
        }
    }

    // Test cracking an MT19937 seed from timestamp (challenge 22).
    #[test]
    pub fn challenge_22() {
        let mut rng = rand::thread_rng();

        // Simulate: seed with current unix time after a random wait (40..1000 sec)
        // Without actually sleeping, we pick a seed in the recent past
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let wait1: u32 = rng.gen_range(40..1000);
        let seed = now - wait1;

        // Create MT19937 with the seed and get first output
        let mut mt = MT19937::new(seed);
        let first_output = mt.extract_number();

        // Attacker knows the output and that seed was generated within last 2000 seconds
        let mut cracked_seed: Option<u32> = None;
        for i in 0..2000 {
            let candidate = now - i;
            let mut test_mt = MT19937::new(candidate);
            if test_mt.extract_number() == first_output {
                cracked_seed = Some(candidate);
                break;
            }
        }

        // Verify that the cracked seed matches the original
        assert!(cracked_seed.is_some());
        assert_eq!(cracked_seed.unwrap(), seed);

        // Additional check: simulate second wait and ensure brute force still works with random seed
        let random_seed: u32 = rng.gen_range(0..10000);
        let mut mt2 = MT19937::new(random_seed);
        let out2 = mt2.extract_number();
        let mut found = None;
        for candidate in 0..20000u32 {
            let mut test = MT19937::new(candidate);
            if test.extract_number() == out2 {
                found = Some(candidate);
                break;
            }
        }
        assert_eq!(found.unwrap(), random_seed);
    }

    // Test cloning an MT19937 from its output (challenge 23).
    #[test]
    pub fn challenge_23() {
        // Create a random MT19937 with unknown seed
        let mut rng = rand::thread_rng();
        let seed: u32 = rng.gen();
        let mut original = MT19937::new(seed);

        // Collect 624 consecutive outputs (full state)
        let mut outputs: Vec<u32> = Vec::new();
        for _ in 0..624 {
            outputs.push(original.extract_number());
        }

        // Clone the RNG from the outputs
        let mut cloned = clone_mt19937(&outputs);

        // Verify that the cloned RNG predicts the next outputs correctly
        for _ in 0..100 {
            let expected = original.extract_number();
            let predicted = cloned.extract_number();
            assert_eq!(predicted, expected);
        }

        // Also test with known seed 0 to ensure deterministic cloning
        let mut mt_known = MT19937::new(0);
        let mut known_outputs = Vec::new();
        for _ in 0..624 {
            known_outputs.push(mt_known.extract_number());
        }
        let mut cloned_known = clone_mt19937(&known_outputs);
        for _ in 0..10 {
            assert_eq!(mt_known.extract_number(), cloned_known.extract_number());
        }
    }

    // Test MT19937 stream cipher and its break (challenge 24).
    #[test]
    pub fn challenge_24() {
        let mut rng = rand::thread_rng();

        // Known plaintext suffix (attacker knows this part)
        let known_plaintext = b"AAAAAAAAAAAAAA"; // 14 x 'A' as per challenge description

        // Generate a random 16-bit seed (key) and random prefix length
        let seed: u16 = rng.gen();
        let prefix_len: usize = rng.gen_range(5..20);
        let prefix: Vec<u8> = prefix_len.random_block();

        // Build the plaintext: random prefix + known plaintext
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&prefix);
        plaintext.extend_from_slice(known_plaintext);

        // Encrypt with MT19937 stream cipher
        let mut mt_enc = MT19937::new(seed as u32);
        let ciphertext = mt_enc.encrypt(&plaintext);

        // Attacker: brute force all 2^16 seeds, check for known plaintext at the end
        let mut cracked_seed: Option<u16> = None;
        let mut cracked_plaintext: Option<Vec<u8>> = None;
        for candidate in 0u16..=u16::MAX {
            let mut mt_candidate = MT19937::new(candidate as u32);
            let candidate_plaintext = mt_candidate.encrypt(&ciphertext);
            if candidate_plaintext.ends_with(known_plaintext) {
                cracked_seed = Some(candidate);
                cracked_plaintext = Some(candidate_plaintext);
                break;
            }
        }

        // Verify that the seed was recovered and plaintext matches
        assert!(cracked_seed.is_some());
        assert_eq!(cracked_seed.unwrap(), seed);
        assert_eq!(cracked_plaintext.unwrap(), plaintext);

        // Additional test: encrypt arbitrary data and verify decrypt round-trip
        let seed2: u16 = rng.gen();
        let data = b"Test message for MT19937 stream cipher round-trip";
        let mut enc = MT19937::new(seed2 as u32);
        let ct = enc.encrypt(data);
        let mut dec = MT19937::new(seed2 as u32);
        let pt = dec.encrypt(&ct);
        assert_eq!(pt, data);

        // Test with token reset attack (password reset token seeded with timestamp)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let token_seed = now - rng.gen_range(0..100);
        let mut token_mt = MT19937::new(token_seed);
        let token = token_mt.extract_number();

        // Attacker brute forces last 200 seconds to find token seed
        let mut token_found = None;
        for i in 0..200 {
            let candidate = now - i;
            let mut test_mt = MT19937::new(candidate);
            if test_mt.extract_number() == token {
                token_found = Some(candidate);
                break;
            }
        }
        assert_eq!(token_found.unwrap(), token_seed);
    }
}
