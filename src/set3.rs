#[cfg(test)]
mod tests {
    use crate::base64::Base64;

    use crate::crypters::CustomCrypter17;
    use crate::cryptovec::CryptoVec;
    use crate::usizecrypt::USizeCrypt;

    use std::fs::File;
    use std::io::prelude::*;
    use std::io::BufReader;

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
}
