use byteorder::{LittleEndian, WriteBytesExt};
use crypto::aessafe;
use crypto::symmetriccipher::BlockEncryptor;
use rand::RngCore;
use std::{fmt, str::FromStr};

use crate::enums::MODE;
use crate::structs::{
    Base64, CustomCrypter11, CustomCrypter12, CustomCrypter13, CustomCrypter14, CustomCrypter16,
    CustomCrypter17, Hex, OracleBase, SingleXorRow,
};
use crate::traits::{CryptoVec, CryptoVecChunks, Oracle, USizeCrypt};
use crate::{consts::LETTER_FREQUENCIES, enums::JlmCryptoErrors};

use openssl::symm::{Cipher, Crypter, Mode};
use rand::{thread_rng, Rng};
use std::str;

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

impl Oracle for OracleBase {
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>, JlmCryptoErrors> {
        let key = &self.key;
        let prefix = &self.prefix;
        let suffix = &self.suffix;
        let mode: MODE = self.mode;
        let iv = &self.iv;

        //Vector for the modified cleartext
        let mut cleartext = Vec::new();

        //Add the prefix
        if let Some(prefix_bytes) = prefix {
            cleartext.extend_from_slice(prefix_bytes);
        }

        //Add the main content
        cleartext.extend_from_slice(u);

        //Add the suffix
        if let Some(suffix_bytes) = suffix {
            cleartext.extend_from_slice(suffix_bytes);
        }

        //Encrypt the value in CBC or EBC
        let encrypted = if mode == MODE::CBC {
            cleartext.ssl_cbc_encrypt(key, &iv.clone().unwrap(), Some(true))
        } else if mode == MODE::ECB {
            cleartext.ssl_ecb_encrypt(key, Some(true))
        } else if mode == MODE::CTR {
            cleartext.ssl_ecb_encrypt(key, Some(true))
        } else {
            Err(JlmCryptoErrors::BadEncryptionMode)
        };

        encrypted
    }
}

impl USizeCrypt for usize {
    //Create a random block of bytes starting from the usize instance value
    fn random_block(self) -> Vec<u8> {
        let mut key = vec![0u8; self];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut key);

        key
    }

    // The first value indicates the number of 'chunks', the second how many bytes need to be added to the usize value to make it a multiple of 16
    fn chunks_count(self) -> (usize, usize) {
        let q = (self + 16 - 1) / 16;
        let r = q * 16 - self;
        (q, r)
    }
}

impl CustomCrypter11 {
    pub fn new() -> Result<Self, JlmCryptoErrors> {
        let mut random_generator = thread_rng();

        //Create a default CIPHER in ECB mode
        let mut cipher: Cipher = Cipher::aes_128_ecb();

        //Randomly choose a mode between ECB or CBC
        let mode: MODE = if random_generator.gen() {
            MODE::ECB
        } else {
            cipher = Cipher::aes_128_cbc();
            MODE::CBC
        };

        //Generate a random key of the block size
        let key = cipher.block_size().random_block();

        //Generate random prefix and suffix of length between 5 and 10
        let prefix: Vec<u8> = random_generator.gen_range(5..=10).random_block();
        let suffix: Vec<u8> = random_generator.gen_range(5..=10).random_block();

        //If the mode is CBC create a random key to use as IV
        let iv: Option<Vec<u8>> = if mode == MODE::CBC {
            Some(cipher.block_size().random_block())
        } else {
            None
        };

        Ok(CustomCrypter11 {
            base: OracleBase {
                key: key,
                prefix: Some(prefix),
                suffix: Some(suffix),
                mode: mode,
                iv: iv,
            },
        })
    }

    //Get the value of the mode used for the cipher, returns true if it is ECB
    pub fn is_ecb(&self) -> bool {
        return self.base.mode == MODE::ECB;
    }

    //Calculate if the key has been encrypted with ECB
    pub fn is_ecb_calculated(&self, vec: Vec<u8>) -> Result<bool, JlmCryptoErrors> {
        // Split the key into 16-byte blocks, skip the first and take the second and third
        let blocks: Vec<&[u8]> = vec.chunks(16).skip(1).take(2).collect();

        //Check if they are equal
        Ok(blocks[0] == blocks[1])
    }

    //Get the value of the mode used for the cipher, returns true if it is CBC
    pub fn is_cbc(&self) -> bool {
        return self.base.mode == MODE::CBC;
    }
}

impl CustomCrypter12 {
    //Block size
    const BLOCK_SIZE: usize = 16;

    pub fn new() -> Result<Self, JlmCryptoErrors> {
        // Create a random key
        let key = Self::BLOCK_SIZE.random_block().to_vec();

        //Create an instance of the Base64 class from a string
        let base64_suffix = Base64::from_string(String::from("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"));
        let suffix: Vec<u8> = base64_suffix
            .to_bytes()
            .unwrap_or_else(|_| panic!("Invalid hex to bytes conversion"));

        // Create a new instance of the CustomCrypter12 class
        Ok(CustomCrypter12 {
            base: OracleBase {
                key: key,
                prefix: None,
                suffix: Some(suffix),
                mode: MODE::ECB,
                iv: None,
            },
        })
    }

    //Check if the current crypter uses padding
    fn uses_padding(&self) -> Result<bool, JlmCryptoErrors> {
        // STEPS
        // Encrypt a string with one byte
        // Encrypt an empty string
        // Calculate the length difference between the first and second
        // If the difference is even and the modulo returns 0 then the crypter uses padding
        Ok(
            (&self.base.encrypt(&[0]).unwrap().len() - &self.base.encrypt(&[]).unwrap().len())
                % Self::BLOCK_SIZE
                == 0,
        )
    }

    pub fn prefix_plus_suffix_length(&self) -> Result<usize, JlmCryptoErrors> {
        // Calculate the length of an empty encrypted string
        let initial = self.base.encrypt(&[]).unwrap().len();

        // If it does not use padding, return the initial encrypted string length as the result
        if !&self.uses_padding().unwrap() {
            return Ok(initial);
        }

        // Create an empty byte array of size 16 filled with zeros
        let input = [0; Self::BLOCK_SIZE];
        if let Some(index) = (1..=Self::BLOCK_SIZE).find(|&i| {
            if let Ok(ciphertext) = self.base.encrypt(&input[..i]) {
                // Check if the length of the encrypted string is different from the initial length
                initial != ciphertext.len()
            } else {
                false
            }
        }) {
            // Return the difference between the initial size and the found index
            Ok(initial - index)
        } else {
            // If no output length variation was found, return a corresponding error
            Err(JlmCryptoErrors::NoOutputLengthChange)
        }
    }

    // Find the suffix
    pub fn get_suffix(&self) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Calculate the length of the prefix.
        let prefix_len = self.prefix_length().unwrap();

        // Calculate the length of the suffix.
        let suffix_len = self.prefix_plus_suffix_length().unwrap() - prefix_len;

        // Get the number of complete blocks in the prefix and the remaining fractional length.
        let (prefix_chunks_count, prefix_fill_len) = prefix_len.chunks_count();

        // Initialize an empty vector to store the suffix.
        let mut suffix = Vec::new();

        // Prepare the input vector with zeros to find the suffix.
        let mut input = vec![0; prefix_fill_len + Self::BLOCK_SIZE - 1];

        // Create a vector of virtual ciphertexts for different left shifts of the input.
        let virtual_ciphertexts = (0..Self::BLOCK_SIZE)
            .map(|left_shift| self.base.encrypt(&input[left_shift..]))
            .collect::<Result<Vec<Vec<u8>>, JlmCryptoErrors>>()
            .unwrap();

        // Find the suffix through forced verification for each byte value.
        for i in 0..suffix_len {
            let block_index = prefix_chunks_count + i / Self::BLOCK_SIZE;
            let left_shift = i % Self::BLOCK_SIZE;

            // Try every byte value (from 0 to 255) to find a matching suffix byte.
            for u in 0u8..=255 {
                input.push(u);

                // Check if the virtual ciphertext matches the real ciphertext for the corresponding block.
                if virtual_ciphertexts[left_shift]
                    [block_index * Self::BLOCK_SIZE..(block_index + 1) * Self::BLOCK_SIZE]
                    == self.base.encrypt(&input[left_shift..]).unwrap()
                        [block_index * Self::BLOCK_SIZE..(block_index + 1) * Self::BLOCK_SIZE]
                {
                    // If a match is found, add the byte value to the suffix and break the loop.
                    suffix.push(u);
                    break;
                }

                // If no match is found, remove the last byte from the input and move to the next byte value.
                input.pop();
            }
        }
        Ok(suffix)
    }

    // Calculate the prefix length
    pub fn prefix_length(&self) -> Result<usize, JlmCryptoErrors> {
        // Get the starting position of the prefix.
        let offset = self.prefix_blocks_count().unwrap() * Self::BLOCK_SIZE;

        // Create a constant block filled with the byte value 0.
        let constant_block = vec![0u8; 16];

        // Extract the initial encrypted block from `offset` to `offset + Self::BLOCK_SIZE`.
        let initial =
            &self.base.encrypt(&constant_block).unwrap()[offset..(offset + Self::BLOCK_SIZE)];

        // Check each subsequent encrypted block starting from different positions of `constant_block`.
        for i in 0..Self::BLOCK_SIZE {
            // Encrypt the portion of `constant_block` starting from index `i+1`.
            let cur = self.base.encrypt(&constant_block[i + 1..]).unwrap();

            // If the current block does not match the initial block, return the prefix length (i).
            if cur.len() < offset + Self::BLOCK_SIZE
                || initial != &cur[offset..(offset + Self::BLOCK_SIZE)]
            {
                return Ok(i);
            }
        }

        // If all subsequent encrypted blocks match the initial block, return the full block size (Self::BLOCK_SIZE).
        Ok(Self::BLOCK_SIZE)
    }

    // Get the number of blocks for the prefix
    pub fn prefix_blocks_count(&self) -> Result<usize, JlmCryptoErrors> {
        // Encrypt the byte `[0]` and the byte `[1]`
        let encrypted_0 = self.base.encrypt(&[0]).unwrap();
        let encrypted_1 = self.base.encrypt(&[1]).unwrap();

        // Divide the encrypted bytes into blocks of size `Self::BLOCK_SIZE`
        let chunks_0 = encrypted_0.chunks(Self::BLOCK_SIZE);
        let chunks_1 = encrypted_1.chunks(Self::BLOCK_SIZE);

        // Find the position of the first block where the contents are different
        if let Some(result) = chunks_0.zip(chunks_1).position(|(x, y)| x != y) {
            Ok(result)
        } else {
            Err(JlmCryptoErrors::NoDifferentBlocks)
        }
    }
}

impl CustomCrypter13 {
    pub fn new() -> Result<Self, JlmCryptoErrors> {
        let block_size: usize = 16;

        // Generate a random 16-byte key
        let key = block_size.random_block();

        Ok({
            CustomCrypter13 {
                base: OracleBase {
                    key: key,
                    prefix: Some(b"email=".to_vec()),
                    suffix: Some(b"&uid=10&role=user".to_vec()),
                    iv: None,
                    mode: MODE::ECB,
                },
            }
        })
    }

    // Create the profile string from the email
    pub fn profile_for(&self, email: String) -> Result<String, JlmCryptoErrors> {
        // Check if the email value contains the '&' character
        if email.contains("&") {
            return Err(JlmCryptoErrors::InvalidSet2Challenge13Chars);
        } else {
            let mut result_string = String::from("email=");

            result_string.push_str(&email);
            result_string.push_str("&uid=10&role=user");

            Ok(result_string)
        }
    }

    // Generate a random email that is 9 characters long
    pub fn generate_test_email(&self) -> String {
        let mut rng = rand::thread_rng();

        // Username is 4 characters long
        let username: String = (0..4).map(|_| rng.gen_range(b'a'..=b'z') as char).collect();

        // Domain is 4 characters long
        let domain: String = (0..4).map(|_| rng.gen_range(b'a'..=b'z') as char).collect();

        format!("{}@{}.com", username, domain)
    }
}

impl Oracle for CustomCrypter13 {
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Encrypt the received array in ECB mode with the key generated during instantiation
        Ok(u.to_vec()
            .ssl_ecb_encrypt(&self.base.key, Some(true))
            .unwrap())
    }
}

impl CustomCrypter14 {
    pub const BLOCK_SIZE: usize = 16;

    // Maximum prefix length
    pub const MAX_PREFIX_SIZE: usize = 10;

    pub fn new() -> Result<Self, JlmCryptoErrors> {
        let mut rng: rand::prelude::ThreadRng = rand::thread_rng();

        // Generate a random 16-byte key
        let key: Vec<u8> = Self::BLOCK_SIZE.random_block().to_vec();

        // Generate a random prefix length
        let prefix_size: usize = rng.gen_range(1..=Self::MAX_PREFIX_SIZE);

        // Generate a random prefix
        let prefix: Vec<u8> = prefix_size.random_block();

        // Initialize the suffix
        let base64_suffix = Base64::from_string(String::from("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"));

        // Convert the Base64 suffix to bytes
        let suffix: Vec<u8> = base64_suffix
            .to_bytes()
            .unwrap_or_else(|_| panic!("Invalid hex to bytes conversion"));

        // Create a new instance of the CustomCrypter14 class
        Ok(CustomCrypter14 {
            base: OracleBase {
                key: key,
                prefix: Some(prefix),
                suffix: Some(suffix),
                mode: MODE::ECB,
                iv: None,
            },
        })
    }

    // Get the number of blocks for the prefix
    pub fn prefix_blocks_count(&self) -> Result<usize, JlmCryptoErrors> {
        // Encrypt the byte `[0]` and the byte `[1]`
        let encrypted_0: Vec<u8> = self.base.encrypt(&[0]).unwrap();
        let encrypted_1: Vec<u8> = self.base.encrypt(&[1]).unwrap();

        // Divide the encrypted bytes into chunks of size `Self::BLOCK_SIZE`
        let chunks_0: std::slice::Chunks<'_, u8> = encrypted_0.chunks(Self::BLOCK_SIZE);
        let chunks_1: std::slice::Chunks<'_, u8> = encrypted_1.chunks(Self::BLOCK_SIZE);

        // Find the position of the first block where the contents differ
        if let Some(result) = chunks_0.zip(chunks_1).position(|(x, y)| x != y) {
            Ok(result)
        } else {
            Err(JlmCryptoErrors::NoDifferentBlocks)
        }
    }

    // Check if the current crypter uses padding
    fn uses_padding(&self) -> Result<bool, JlmCryptoErrors> {
        // STEP
        // Encrypt a string with one byte
        // Encrypt an empty string
        // Calculate the length difference between the first and second
        // If the difference is even and the modulo returns 0 then the crypter uses padding
        Ok(
            (&self.base.encrypt(&[0]).unwrap().len() - &self.base.encrypt(&[]).unwrap().len())
                % Self::BLOCK_SIZE
                == 0,
        )
    }

    pub fn prefix_plus_suffix_length(&self) -> Result<usize, JlmCryptoErrors> {
        // Calculate the length of an empty encrypted string
        let initial = self.base.encrypt(&[]).unwrap().len();

        // If it does not use padding, return the length of the initial encrypted string as the result
        if !&self.uses_padding().unwrap() {
            return Ok(initial);
        }

        // Create an empty byte array of size 16 filled with zeros
        let input = [0; Self::BLOCK_SIZE];
        if let Some(index) = (1..=Self::BLOCK_SIZE).find(|&i| {
            if let Ok(ciphertext) = self.base.encrypt(&input[..i]) {
                // Check if the length of the encrypted string is different from the initial length
                initial != ciphertext.len()
            } else {
                false
            }
        }) {
            // Return the difference between the initial size and the found index
            Ok(initial - index)
        } else {
            // If no output length variation was found, return the corresponding error
            Err(JlmCryptoErrors::NoOutputLengthChange)
        }
    }

    pub fn get_suffix(&self) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Calculate the length of the prefix.
        let prefix_len = self.prefix_length().unwrap();

        // Calculate the length of the suffix.
        let suffix_len = self.prefix_plus_suffix_length().unwrap() - prefix_len;

        // Get the number of complete blocks in the prefix and the remaining fractional length.
        let (prefix_ch_count, prefix_flen) = prefix_len.chunks_count();

        // Initialize an empty vector to store the suffix.
        let mut suffix = Vec::new();

        // Prepare the input vector with zeros to find the suffix.
        let mut input = vec![0; prefix_flen + Self::BLOCK_SIZE - 1];

        // Create a vector of virtual ciphertexts for different left shifts of the input.
        let virtual_ciphertexts = (0..Self::BLOCK_SIZE)
            .map(|left_shift| self.base.encrypt(&input[left_shift..]))
            .collect::<Result<Vec<Vec<u8>>, JlmCryptoErrors>>()
            .unwrap();

        // Find the suffix through forced verification for each byte value.
        for i in 0..suffix_len {
            let block_index = prefix_ch_count + i / Self::BLOCK_SIZE;
            let left_shift = i % Self::BLOCK_SIZE;

            // Try every byte value (from 0 to 255) to find a matching suffix byte.
            for u in 0u8..=255 {
                input.push(u);

                // Check if the virtual ciphertext matches the real ciphertext for the corresponding block.
                if virtual_ciphertexts[left_shift]
                    [block_index * Self::BLOCK_SIZE..(block_index + 1) * Self::BLOCK_SIZE]
                    == self.base.encrypt(&input[left_shift..]).unwrap()
                        [block_index * Self::BLOCK_SIZE..(block_index + 1) * Self::BLOCK_SIZE]
                {
                    // If a match is found, add the byte value to the suffix and break the loop.
                    suffix.push(u);
                    break;
                }

                // If no match is found, remove the last byte from the input and continue to the next byte value.
                input.pop();
            }
        }
        Ok(suffix)
    }

    // Get the length of the prefix
    pub fn prefix_length(&self) -> Result<usize, JlmCryptoErrors> {
        // Get the starting position of the prefix
        let offset = self.prefix_blocks_count().unwrap() * Self::BLOCK_SIZE;

        // Create a constant block filled with the byte value 0.
        let constant_block = vec![0u8; Self::BLOCK_SIZE];

        // Extract the initial encrypted block from `offset` to `offset + Self::BLOCK_SIZE`.
        let initial =
            &self.base.encrypt(&constant_block).unwrap()[offset..(offset + Self::BLOCK_SIZE)];

        // Check each subsequent encrypted block starting from different positions of `constant_block`.
        for i in 0..Self::BLOCK_SIZE {
            // Encrypt the portion of `constant_block` starting from index `i+1`.
            let cur = self.base.encrypt(&constant_block[i + 1..]).unwrap();

            // If the current block does not match the initial block, return the length of the prefix (i).
            if cur.len() < offset + Self::BLOCK_SIZE
                || initial != &cur[offset..(offset + Self::BLOCK_SIZE)]
            {
                return Ok(i);
            }
        }

        // If all subsequent encrypted blocks match the initial block, return the full block size (Self::BLOCK_SIZE).
        Ok(Self::BLOCK_SIZE)
    }
}

impl Oracle for CustomCrypter14 {
    // Encrypt the array obtained in input
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>, JlmCryptoErrors> {
        self.base.encrypt(u)
    }
}

impl CustomCrypter16 {
    // Create and return an instance of this structure `CustomCrypter16`.
    pub fn new() -> CustomCrypter16 {
        return CustomCrypter16 {};
    }

    // Adds quoting to occurrences of the characters ';' and '=' in the input string.
    pub fn quote_str(&self, input: &str) -> String {
        let mut quoted_input = str::replace(input, ";", "\";\"");
        quoted_input = str::replace(&quoted_input[..], "=", "\"=\"");

        quoted_input
    }

    // Removes the quoting added by the `quote_str` function.
    pub fn unquote_str(&self, input: &str) -> String {
        let mut quoted_input = str::replace(input, "\";\"", ";");
        quoted_input = str::replace(&quoted_input[..], "\"=\"", "=");

        quoted_input
    }

    // Prepares a string for encryption by adding specific prefixes and suffixes.
    pub fn prepare_string(&self, input: &str) -> Vec<u8> {
        let input_quoted: String = self.quote_str(input);

        let input_bytes = input_quoted.as_bytes();
        let prepend_bytes = b"comment1=cooking%20MCs;userdata=";
        let append_bytes = b";comment2=%20like%20a%20pound%20of%20bacon";

        let mut plaintext = Vec::new();

        // Adds the prefix bytes, the quoted input bytes, and the suffix bytes to the `plaintext` vector.
        plaintext.extend_from_slice(&prepend_bytes[..]);
        plaintext.extend_from_slice(&input_bytes[..]);
        plaintext.extend_from_slice(&append_bytes[..]);

        plaintext
    }
}

impl CustomCrypter17 {
    pub const BLOCK_SIZE: usize = 16;

    //Lunghezza massima del prefisso
    pub const MAX_PREFIX_SIZE: usize = 20;

    const TOKENS: [&'static str; 10] = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];

    pub fn new() -> Result<Self, JlmCryptoErrors> {
        // Generates a random key
        let key = Self::BLOCK_SIZE.random_block().to_vec();

        // Generates a random IV
        let iv = Self::BLOCK_SIZE.random_block().to_vec();

        let mut rng = rand::thread_rng();
        let i_index = rng.gen_range(0..Self::TOKENS.len());

        let token_extracted = Self::TOKENS[i_index].to_string();

        // Creates a new instance of the CustomCrypter14 class
        Ok(CustomCrypter17 {
            picked_token: token_extracted,
            key: key,
            iv: iv,
        })
    }

    pub fn get_picked_token(&self) -> Base64 {
        Base64::from_string(self.picked_token.clone())
    }

    pub fn get_all_tokens(&self) -> [&str; 10] {
        Self::TOKENS
    }
}

// Define a structure `Hex` to represent hexadecimal values.
impl Hex {
    // Constructor to create a new `Hex` object from a hexadecimal string.
    pub fn new(s: String) -> Result<Hex, JlmCryptoErrors> {
        // Decodes the hexadecimal string into bytes.
        // Validate that the string contains only valid hexadecimal characters
        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(JlmCryptoErrors::InvalidHEXValue);
        }

        // Check if the string has an even number of characters
        if s.len() % 2 != 0 {
            return Err(JlmCryptoErrors::InvalidHEXValue);
        }

        // If validation passes, return a Hex object
        Ok(Hex(s))
    }

    // Constructor to create a `Hex` object from a string.
    pub fn from_string(s: String) -> Result<Hex, JlmCryptoErrors> {
        // Calls the `new` constructor to create a `Hex` object from the provided string.
        Hex::new(s.to_string())
    }

    // Constructor to create a `Hex` object directly from a hexadecimal string.
    pub fn from_hex_string(s: String) -> Result<Hex, JlmCryptoErrors> {
        // Creates a `Hex` object containing the provided hexadecimal string.
        Ok(Hex(s))
    }

    // Constructor to create a `Hex` object from a byte vector.
    pub fn from_bytes(s: Vec<u8>) -> Result<Hex, JlmCryptoErrors> {
        // Encodes the bytes into hexadecimal format without using external libraries
        let hex_string = s
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();
        Ok(Hex(hex_string))
    }

    // Method that returns the length of the hexadecimal sequence.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    // Method that converts the `Hex` object into a byte vector.
    pub fn to_bytes(&self) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Decodes the hexadecimal string into bytes.
        let mut result = Vec::new();

        // Iterate over the hexadecimal string in pairs of characters.
        for i in (0..self.0.len()).step_by(2) {
            // Extract a pair of hexadecimal characters.
            let byte_str = &self.0[i..i + 2];

            // Convert the hexadecimal pair to a byte and add it to the result vector.
            match u8::from_str_radix(byte_str, 16) {
                Ok(byte) => result.push(byte),
                Err(_) => return Err(JlmCryptoErrors::InvalidHEXToBytesConversion),
            }
        }
        Ok(result)
    }

    // Method that converts the `Hex` object into a `Base64` object.
    pub fn to_b64(&self) -> Result<Base64, JlmCryptoErrors> {
        // Converts the `Hex` object into a byte vector and then into a `Base64` object.
        match &self.to_bytes() {
            Ok(v) => Ok(Base64::from_string(base64::encode(v))),
            // If there is an error during conversion, return a `JlmCryptoErrors` error.
            Err(_) => Err(JlmCryptoErrors::InvalidHEXToBase64Conversion),
        }
    }
}

// Implementation of the `FromStr` trait for the `Hex` structure.
impl FromStr for Hex {
    type Err = JlmCryptoErrors;

    // Method that converts a string into a `Hex` object.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Calls the `from_hex_string` method of the `Hex` structure to create a `Hex` object from the string.
        Hex::from_hex_string(s.to_string())
    }
}

// Definition of the `Base64` structure.
impl Base64 {
    // Constructor to create a new `Base64` object from a string.
    pub fn new(s: String) -> Base64 {
        Base64(s)
    }

    // Method that creates a `Base64` object from a string.
    pub fn from_string(s: String) -> Base64 {
        Base64(s)
    }

    // Method that creates a `Base64` object from a byte vector.
    pub fn from_bytes(s: &[u8]) -> Base64 {
        Base64(base64::encode(s))
    }

    // Method that converts the `Base64` object into a byte vector.
    pub fn to_bytes(&self) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Decodes the Base64 string into bytes.
        match base64::decode(&self.0) {
            // If decoding is successful, return the obtained bytes.
            Ok(r) => Ok(r),
            // If there is an error during decoding, return a `JlmCryptoErrors` error.
            Err(_) => Err(JlmCryptoErrors::InvalidBase64ToBytes),
        }
    }
}

// Implementation of the `PartialEq` trait for the `Base64` structure.
impl PartialEq for Base64 {
    // Method that compares two `Base64` objects for equality.
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

// Implementation of the `PartialEq` trait for the `Hex` structure.
impl PartialEq for Hex {
    // Method that compares two `Hex` objects for equality.
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

// Implementation of the `Display` trait for the `Hex` structure.
impl<'a> fmt::Display for Hex {
    // Method that formats the `Hex` object for display.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Implementation of the `Debug` trait for the `Hex` structure.
impl<'a> fmt::Debug for Hex {
    // Method that formats the `Hex` object for display in debug mode.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Formats the hexadecimal string into a readable format, separating pairs of digits with a space.
        let hex_string = self.0.to_lowercase();
        let spaced_hex_string = hex_string
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                if i > 0 && i % 2 == 0 {
                    Some(' ') // Insert a space after every pair of digits
                } else {
                    None
                }
                .into_iter()
                .chain(std::iter::once(c))
            })
            .collect::<String>();

        write!(f, "Hex({})", spaced_hex_string)
    }
}

// Implementation of the `Display` trait for the `Base64` structure.
impl<'a> fmt::Display for Base64 {
    // Method that formats the `Base64` object for display.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Implementation of the `Debug` trait for the `Base64` structure.
impl<'a> fmt::Debug for Base64 {
    // Method that formats the `Base64` object for display in debug mode.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Base64({})", self.0)
    }
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
