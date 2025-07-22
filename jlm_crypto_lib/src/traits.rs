use crate::enums::JlmCryptoErrors;

pub trait USizeCrypt {
    fn random_block(self) -> Vec<u8>;
    fn chunks_count(self) -> (usize, usize);
}
pub trait Oracle {
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>, JlmCryptoErrors>;
}
pub trait CryptoVecChunks {
    fn contains_duplicates(&mut self) -> bool;
}

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
