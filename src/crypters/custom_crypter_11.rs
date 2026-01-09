use openssl::symm::Cipher;
use rand::{thread_rng, Rng};

use crate::{errors::JlmCryptoErrors, oracle::base::OracleBase, usizecrypt::USizeCrypt};

use super::MODE;

pub struct CustomCrypter11 {
    pub base: OracleBase,
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
