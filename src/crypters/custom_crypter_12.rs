use crate::{
    base64::Base64,
    errors::JlmCryptoErrors,
    oracle::{base::OracleBase, Oracle},
    usizecrypt::USizeCrypt,
};

use super::MODE;

pub struct CustomCrypter12 {
    pub base: OracleBase,
}

impl CustomCrypter12 {
    //Block size
    const BLOCK_SIZE: usize = 16;

    pub fn new() -> Result<Self, JlmCryptoErrors> {
        // Create a random key
        let key = Self::BLOCK_SIZE.random_block().to_vec();

        //Create an instance of the Base64 class from a string
        let base64_suffix = Base64::new(String::from("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"));
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
