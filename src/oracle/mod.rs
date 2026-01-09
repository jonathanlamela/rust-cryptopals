pub mod base;

use crate::errors::JlmCryptoErrors;

pub trait Oracle {
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>, JlmCryptoErrors>;
}
