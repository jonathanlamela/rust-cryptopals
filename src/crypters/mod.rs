use openssl::symm::Cipher;
use rand::{thread_rng, Rng};

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum MODE {
    ECB,
    CBC,
    CTR,
}

use crate::{
    base64::Base64, cryptovec::CryptoVec, errors::JlmCryptoErrors, oracle::Oracle,
    oraclebase::OracleBase, usizecrypt::USizeCrypt,
};

pub struct CustomCrypter11 {
    pub base: OracleBase,
}

pub struct CustomCrypter12 {
    pub base: OracleBase,
}

pub struct CustomCrypter13 {
    pub base: OracleBase,
}

pub struct CustomCrypter14 {
    pub base: OracleBase,
}

pub struct CustomCrypter16 {}

pub struct CustomCrypter17 {
    pub picked_token: String,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
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
