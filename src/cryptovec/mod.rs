use byteorder::{LittleEndian, WriteBytesExt};
use crypto::{aessafe, symmetriccipher::BlockEncryptor};
use openssl::symm::{Cipher, Crypter, Mode};

use crate::{errors::JlmCryptoErrors, types::SingleXorRow};

pub const LETTER_FREQUENCIES: [f64; 26] = [
    8.34, 1.54, 2.73, 4.14, 12.60, 2.03, 1.92, 6.11, 6.71, 0.23, 0.87, 4.24, 2.53, 6.80, 7.70,
    1.66, 0.09, 5.68, 6.11, 9.37, 2.85, 1.06, 2.34, 0.20, 2.04, 0.06,
];

pub trait CryptoVec {
    fn evaluate_frequency(&self) -> Option<(f64, u8, Vec<u8>)>;
    fn repeating_key_xor(&self, key: &[u8]) -> Vec<u8>;
    fn repeating_xor_attack(&self) -> Result<String, JlmCryptoErrors>;
    fn legacy_cbc_decrypt(&self, key: &[u8], iv: &mut [u8]) -> Result<Vec<u8>, JlmCryptoErrors>;
    fn xor_single(&self, k: u8) -> Vec<u8>;
    fn evaluate_score(&self) -> Option<f64>;
    fn xor(&self, v2: Vec<u8>) -> Vec<u8>;
    fn mutable_xor(&mut self, v2: Vec<u8>);
    fn compute_distance_bytes(&self, bytes_b: &Vec<u8>) -> u32;
    fn find_ks(&self) -> Result<usize, JlmCryptoErrors>;
    fn pad(&mut self, k: u8) -> Result<bool, JlmCryptoErrors>;
    fn unpad(&mut self, k: u8) -> Result<bool, JlmCryptoErrors>;
    fn check_padding_valid(&self, k: u8) -> Result<bool, JlmCryptoErrors>;
    fn ssl_cbc_encrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        pad: Option<bool>,
    ) -> Result<Vec<u8>, JlmCryptoErrors>;
    fn ssl_cbc_decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        pad: Option<bool>,
    ) -> Result<Vec<u8>, JlmCryptoErrors>;
    fn ssl_ecb_encrypt(&self, key: &[u8], pad: Option<bool>) -> Result<Vec<u8>, JlmCryptoErrors>;
    fn ssl_ecb_decrypt(&self, key: &[u8], pad: Option<bool>) -> Result<Vec<u8>, JlmCryptoErrors>;
    fn ssl_ctr_encrypt(&self, key: &[u8], pad: Option<bool>) -> Result<Vec<u8>, JlmCryptoErrors>;
    fn ssl_ctr_decrypt(&self, key: &[u8], pad: Option<bool>) -> Result<Vec<u8>, JlmCryptoErrors>;
    fn nonce_ctr_encrypt(&self, key: &[u8], nonce: Vec<u8>) -> Result<Vec<u8>, JlmCryptoErrors>;
}

impl CryptoVec for Vec<u8> {
    // Function to add PKCS7 padding to a byte vector.
    fn pad(&mut self, k: u8) -> Result<bool, JlmCryptoErrors> {
        // Check if the padding value k is less than 2
        if k < 2 {
            // If k is less than 2, return an error indicating PKCS7 padding failure
            return Err(JlmCryptoErrors::PKCS7PaddingFailed);
        }

        // Calculate the padding value p needed to reach a multiple of k
        let p = k - (self.len() % k as usize) as u8;

        // Add the padding value p to the vector p times
        for _ in 0..p {
            self.push(p);
        }

        Ok(true)
    }

    // Function to remove PKCS7 padding from a byte vector.
    fn unpad(&mut self, k: u8) -> Result<bool, JlmCryptoErrors> {
        // Check if the padding is valid using the check_padding_valid function
        if !self.check_padding_valid(k)? {
            // If the padding is not valid, return an error indicating invalid padding
            return Err(JlmCryptoErrors::InvalidPadding);
        }

        // Calculate the new length of the vector after removing the padding
        let len_new = self.len() - self[self.len() - 1] as usize;

        // Truncate the vector to the new length to remove the padding
        self.truncate(len_new);

        // Return Ok(true) to indicate successful padding removal
        Ok(true)
    }

    // Function to check if PKCS7 padding in a byte vector is valid.
    fn check_padding_valid(&self, k: u8) -> Result<bool, JlmCryptoErrors> {
        // Check if the padding value k is less than 2
        if k < 2 {
            // If k is less than 2, return an error indicating invalid padding
            return Err(JlmCryptoErrors::InvalidPadding);
        }

        // Check if the vector is empty or not a multiple of k
        if self.is_empty() || self.len() % k as usize != 0 {
            // If the vector is empty or not a multiple of k, return false (invalid padding)
            return Err(JlmCryptoErrors::InvalidPadding);
        }

        // Get the last byte of the vector, which indicates the amount of padding
        let padding = self[self.len() - 1];

        // Check if the padding value is within the expected range [1, k]
        if !(1 <= padding && padding <= k) {
            // If the padding value is not within the expected range, return false (invalid padding)
            return Err(JlmCryptoErrors::InvalidPadding);
        }

        // Check if the padding bytes are consistent with the expected value
        // Compare the last `padding` bytes with the padding value
        let is_valid = self[self.len() - padding as usize..]
            .iter()
            .all(|&b| b == padding);

        // Return whether the padding is valid
        if is_valid {
            return Ok(true);
        } else {
            return Err(JlmCryptoErrors::InvalidPadding);
        }
    }

    // Function to find the most likely key size (ks).
    fn find_ks(&self) -> Result<usize, JlmCryptoErrors> {
        // Initialize a variable for the key size (ks) and one for the minimum distance.
        let mut out_keysize: Option<usize> = None;
        let mut out_dist = f64::INFINITY;

        // Iterate over possible key sizes from 2 to 39 (inclusive).
        for ks in 2..40 {
            // Divide the data into chunks of size ks.
            let chunks: Vec<&[u8]> = self.chunks(ks).collect();

            // Extract the first four chunks to calculate the distances between them.
            let block1 = chunks.get(0).unwrap().to_vec();
            let block2 = chunks.get(1).unwrap().to_vec();
            let block3 = chunks.get(2).unwrap().to_vec();
            let block4 = chunks.get(3).unwrap().to_vec();

            // Calculate the normalized distance between all possible pairs of blocks.
            let ds = (&block1.compute_distance_bytes(&block2)
                + &block1.compute_distance_bytes(&block3)
                + &block1.compute_distance_bytes(&block4)
                + &block2.compute_distance_bytes(&block3)
                + &block2.compute_distance_bytes(&block4)
                + &block3.compute_distance_bytes(&block4)) as f64
                / (6.0 * ks as f64);

            // Update the key size (ks) and minimum distance if necessary.
            if out_keysize.is_some() {
                if ds < out_dist {
                    out_dist = ds;
                    out_keysize = Some(ks);
                }
            } else {
                out_dist = ds;
                out_keysize = Some(ks);
            }
        }

        // Return the most likely key size (ks).
        if let Some(ks) = out_keysize {
            Ok(ks)
        } else {
            // If a valid key size cannot be found, return an error.
            Err(JlmCryptoErrors::UnableFindKs)
        }
    }

    // Function to perform an XOR operation between two byte vectors.
    fn xor(&self, v2: Vec<u8>) -> Vec<u8> {
        self.iter().zip(v2.iter()).map(|(&x, &y)| x ^ y).collect()
    }

    fn mutable_xor(&mut self, v2: Vec<u8>) {
        for chunk in self.chunks_mut(v2.len()) {
            let len = chunk.len();
            for (c, &d) in chunk.iter_mut().zip(v2[..len].iter()) {
                *c ^= d;
            }
        }
    }

    // Function to compute the Hamming distance between two byte vectors.
    fn compute_distance_bytes(&self, bytes_b: &Vec<u8>) -> u32 {
        self.iter()
            .zip(bytes_b.iter())
            .fold(0, |acc, (&byte_a, &byte_b)| {
                acc + (byte_a ^ byte_b).count_ones()
            })
    }

    // Function to evaluate the score of a byte vector based on letter frequencies.

    fn evaluate_score(&self) -> Option<f64> {
        // Check if all characters in the string are printable ASCII characters or whitespace.
        if !self
            .iter()
            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        {
            return None;
        }

        // Calculate the score by evaluating the frequencies of letters in the ASCII alphabetic characters.
        Some(self.iter().fold(0.0, |score, b| {
            if b.is_ascii_alphabetic() {
                let i = b.to_ascii_lowercase() - (b'a');
                score + LETTER_FREQUENCIES[usize::from(i)].log10()
            } else {
                score
            }
        }))
    }

    // Function to perform an XOR operation between a byte vector and a single key.
    fn xor_single(&self, k: u8) -> Vec<u8> {
        self.iter().map(|x| x ^ k).collect()
    }

    // Function to perform a repeated XOR attack to break the encryption key.
    fn repeating_xor_attack(&self) -> Result<String, JlmCryptoErrors> {
        // Find the most likely key size (ks).
        let ks = self.find_ks().unwrap();

        // Initialize a transposed matrix for the data blocks.
        let mut transposed: Vec<Vec<u8>> = vec![vec![]; ks];

        // Extract the data blocks from the key size (ks).
        for slice in self.chunks(ks) {
            let s_len = slice.len();
            if s_len == ks {
                for i in 0..s_len {
                    transposed[i].push(slice[i]);
                }
            }
        }

        // Initialize a vector for the decryption key.
        let mut k_vec: Vec<u8> = Vec::new();

        // Perform the repeated XOR attack on the data blocks.
        for bl in transposed {
            match bl.evaluate_frequency() {
                Some((_, key, _)) => k_vec.push(key),
                None => {}
            }
        }

        // If the key has been determined, decrypt the ciphertext and return the result.
        if k_vec.len() > 0 {
            let repeating_key_xor_result = self.repeating_key_xor(&k_vec);

            match &str::from_utf8(&repeating_key_xor_result) {
                Ok(v) => Ok(v.to_string()),
                Err(_) => Err(JlmCryptoErrors::BreakRepeatingKeyAttackFailed),
            }
        } else {
            return Err(JlmCryptoErrors::BreakRepeatingKeyAttackFailed);
        }
    }

    fn repeating_key_xor(&self, key: &[u8]) -> Vec<u8> {
        // Create an empty vector to store the result
        let mut result: Vec<u8> = Vec::new();

        // Create a cyclic iterator for the provided key
        let mut key_iterator = key.into_iter().cycle();

        // Iterate over the elements of the input data
        for i in self.into_iter() {
            // Perform an XOR operation between the data element and the next element of the key
            // and add the result to the result vector
            result.push(key_iterator.next().unwrap() ^ i);
        }

        // Return the resulting vector
        result
    }

    fn evaluate_frequency(&self) -> Option<(f64, u8, Vec<u8>)> {
        // Create a vector to store the results of single XORs
        let mut xors_vector: Vec<SingleXorRow> = Vec::new();

        // Iterate over all possible key values (from 0 to 255)
        for key in 0..=255 {
            // Calculate the single XOR result for the current key
            let item = SingleXorRow {
                key,
                xor_value: self.xor_single(key),
            };
            // Add the single XOR result to the vector
            xors_vector.push(item);
        }

        // Filter the results with positive scores
        let filtered_map = xors_vector.iter().filter_map(|row| {
            row.xor_value
                .evaluate_score()
                .map(|score| (score, row.key, row.xor_value.clone()))
        });

        // Extract the XOR value with the highest score
        let max_value = filtered_map.max_by(|(a, _, _), (b, _, _)| a.partial_cmp(b).unwrap());

        // Return the result with the highest score (if present)
        max_value
    }

    fn legacy_cbc_decrypt(&self, key: &[u8], iv: &mut [u8]) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Define the block size (typically 16 bytes)
        let block_size = 16;

        // Create a vector to hold the decrypted plaintext
        let mut plaintext = Vec::new();

        // Create a vector to hold the previous ciphertext block (initialized with the IV)
        let mut prev_ciphertext_block = iv.to_vec();

        // Iterate over the ciphertext data in blocks of the defined block size
        for chunk in self.chunks(block_size) {
            // Decrypt the current block using the block cipher algorithm (presumably AES-ECB)
            let decrypted_block = chunk.to_vec().ssl_ecb_decrypt(key, Some(false)).unwrap();

            // Perform an XOR operation between the current decrypted block and the previous ciphertext block
            let mut decrypted_block_xor = Vec::with_capacity(block_size);
            for j in 0..block_size {
                // Perform XOR between the bytes of the current block and those of the previous ciphertext block
                decrypted_block_xor.push(decrypted_block[j] ^ prev_ciphertext_block[j]);
            }

            // Update the previous ciphertext block with the current block
            prev_ciphertext_block = chunk.to_vec();

            // Add the result of the XOR operation to the plaintext vector
            plaintext.extend_from_slice(&decrypted_block_xor);
        }

        // Remove padding from the decryption output
        let _ = plaintext.unpad(16);

        // Return the decrypted plaintext
        Ok(plaintext)
    }

    // Execute encryption using the AES algorithm in CBC mode.
    fn ssl_cbc_encrypt(
        &self,
        key: &[u8],        // Encryption key
        iv: &[u8],         // Initialization vector (IV)
        pad: Option<bool>, // Padding option (optional, default: true)
    ) -> Result<Vec<u8>, JlmCryptoErrors> {
        let cipher = Cipher::aes_128_cbc(); // Use AES algorithm in CBC mode

        let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv)).unwrap();
        crypter.pad(pad.unwrap_or(true)); // Enable padding if specified

        // Create a vector to hold the encrypted ciphertext
        let mut encrypted = vec![0; &self.len() + cipher.block_size()];

        // Perform the encryption
        let count = crypter.update(&self, &mut encrypted).unwrap();

        match crypter.finalize(&mut encrypted[count..]) {
            Ok(final_count_value) => {
                // Truncate the ciphertext vector to the actual length
                encrypted.truncate(count + final_count_value);

                // Return the resulting ciphertext
                Ok(encrypted)
            }
            Err(_) => Err(JlmCryptoErrors::InvalidPadding),
        }
    }

    // Execute encryption using the AES algorithm in ECB mode.
    fn ssl_ecb_encrypt(
        &self,
        key: &[u8],        // Encryption key
        pad: Option<bool>, // Padding option (optional, default: true)
    ) -> Result<Vec<u8>, JlmCryptoErrors> {
        let cipher = Cipher::aes_128_ecb(); // Use AES algorithm in ECB mode
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, None).unwrap();
        crypter.pad(pad.unwrap_or(true)); // Enable padding if specified

        // Create a vector to hold the encrypted ciphertext
        let mut encrypted = vec![0; &self.len() + cipher.block_size()];

        // Perform the encryption
        let count = crypter.update(&self, &mut encrypted).unwrap();
        let final_count = crypter.finalize(&mut encrypted[count..]).unwrap();

        // Truncate the ciphertext vector to the actual length
        encrypted.truncate(count + final_count);

        // Return the resulting ciphertext
        Ok(encrypted)
    }

    // Execute decryption using the AES algorithm in ECB mode.
    fn ssl_ecb_decrypt(
        &self,
        key: &[u8],        // Encryption key
        pad: Option<bool>, // Padding option (optional, default: true)
    ) -> Result<Vec<u8>, JlmCryptoErrors> {
        let cipher = Cipher::aes_128_ecb(); // Use AES algorithm in ECB mode
        let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, None).unwrap();
        crypter.pad(pad.unwrap_or(true)); // Enable padding if specified

        // Create a vector to hold the decrypted plaintext
        let mut decrypted = vec![0; &self.len() + cipher.block_size()];

        // Perform the decryption
        let count = crypter.update(&self, &mut decrypted).unwrap();

        match crypter.finalize(&mut decrypted[count..]) {
            Ok(final_count_value) => {
                // Truncate the decrypted plaintext vector to the actual length
                decrypted.truncate(count + final_count_value);

                // Return the resulting plaintext
                Ok(decrypted)
            }
            Err(_) => Err(JlmCryptoErrors::InvalidPadding),
        }
    }

    // Execute decryption using the AES algorithm in CBC mode.
    fn ssl_cbc_decrypt(
        &self,
        key: &[u8],        // Encryption key
        iv: &[u8],         // Initialization vector (IV)
        pad: Option<bool>, // Padding option (optional, default: true)
    ) -> Result<Vec<u8>, JlmCryptoErrors> {
        let cipher = Cipher::aes_128_cbc(); // Use AES algorithm in CBC mode
        let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv)).unwrap();
        crypter.pad(pad.unwrap_or(true)); // Enable padding if specified

        // Create a vector to hold the decrypted plaintext
        let mut decrypted = vec![0; &self.len() + cipher.block_size()];

        // Perform the decryption
        match crypter.update(&self, &mut decrypted) {
            Ok(count) => {
                match crypter.finalize(&mut decrypted[count..]) {
                    Ok(final_count_value) => {
                        // Truncate the decrypted plaintext vector to the actual length
                        decrypted.truncate(count + final_count_value);

                        // Return the resulting plaintext
                        Ok(decrypted)
                    }
                    Err(_) => Err(JlmCryptoErrors::InvalidPadding),
                }
            }
            Err(_) => Err(JlmCryptoErrors::InvalidPadding),
        }
    }

    fn ssl_ctr_encrypt(&self, key: &[u8], pad: Option<bool>) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Initialize the vector that will hold the ciphertext.
        let mut ciphertext = Vec::new();
        // Initialize the vector that represents the keystream for encryption.
        let mut keystream = vec![0; 16];

        /*
        They keystream is a sequence that is used to generate an
        initial encrypted block. This first block is then used to
        perform an XOR operation between a block of plaintext and
        a block of the keystream.
        For each block, the "counter" value of the first block
        of the keystream is incremented.
         */

        // Iterates over the input data in chunks of 16 bytes.
        // Each chunk represents a block of data to be encrypted.
        for b in self.chunks(16) {
            // Gets the keystream by encrypting the keystream with the key using ECB mode.
            let to_xor = keystream.to_vec().ssl_ecb_encrypt(&key, pad);

            // Performs the XOR operation between the current block and the obtained keystream.
            ciphertext.extend_from_slice(&b.to_vec().xor(to_xor.unwrap()));

            // Updates the keystream by incrementing the counter.
            for b in keystream[16 / 2..].iter_mut() {
                *b += 1;
                if *b != 0 {
                    break;
                }
            }
        }

        // Returns the ciphertext.
        Ok(ciphertext)
    }

    fn ssl_ctr_decrypt(&self, key: &[u8], pad: Option<bool>) -> Result<Vec<u8>, JlmCryptoErrors> {
        self.ssl_ctr_encrypt(key, pad)
    }

    fn nonce_ctr_encrypt(&self, key: &[u8], nonce: Vec<u8>) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Get the block size from the key length
        let block_size = key.len();

        // Initialize an AES encryptor with a 128-bit key
        let encryptor = aessafe::AesSafe128Encryptor::new(&key);

        // Initialize a vector to hold the ciphertext
        let mut result: Vec<u8> = Vec::new();

        // Divide the data into blocks of the AES block size
        let i_blocks = &self.chunks(block_size);

        // Initialize a vector to hold the keystream
        let mut keystream = vec![0; block_size];

        // Iterate over the data blocks and encrypt each block
        for (count, block) in i_blocks.clone().enumerate() {
            // Initialize a vector to hold the nonce and counter
            let mut nonce_count = Vec::new();
            nonce_count.extend_from_slice(&nonce[..]);

            // Check if writing the counter to nonce_count was successful
            if let Ok(_) = nonce_count.write_u64::<LittleEndian>(count as u64) {
                // Encrypt the nonce_count to obtain the keystream
                encryptor.encrypt_block(&nonce_count[..], &mut keystream[..]);

                // Perform the XOR operation between the keystream and the current block
                let b1 = &keystream[0..block.len()];
                let b2 = block;
                let x_result = b1.to_vec().xor(b2.to_vec());

                // Add the ciphertext result to the result vector
                result.extend_from_slice(&x_result[..]);
            } else {
                // If writing the counter fails, return an error
                return Err(JlmCryptoErrors::FailedAesCtrEncrypt);
            }
        }

        // Return the ciphertext result
        Ok(result)
    }
}

pub trait CryptoVecChunks {
    fn contains_duplicates(&mut self) -> bool;
}

impl CryptoVecChunks for Vec<&[u8]> {
    fn contains_duplicates(&mut self) -> bool {
        //Initial length of the vector
        let len = self.len();

        //The dedup function only works with sorted vectors, so I sort the vector before calling the dedup function
        self.sort();

        //Remove duplicates from the vector
        self.dedup();

        //If the initial length of the vector is different from the length without duplicates then the vector contained duplicates
        len != self.len()
    }
}
