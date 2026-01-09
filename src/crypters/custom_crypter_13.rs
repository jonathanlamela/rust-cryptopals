use rand::Rng;

use crate::{
    cryptovec::CryptoVec,
    errors::JlmCryptoErrors,
    oracle::{base::OracleBase, Oracle},
    usizecrypt::USizeCrypt,
};

use super::MODE;

pub struct CustomCrypter13 {
    pub base: OracleBase,
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
