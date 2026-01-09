use rand::Rng;

use crate::{base64::Base64, errors::JlmCryptoErrors, usizecrypt::USizeCrypt};

#[derive(Clone)]
pub struct CustomCrypter17 {
    pub picked_token: String,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
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

        // Creates a new instance of the CustomCrypter17 class
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
