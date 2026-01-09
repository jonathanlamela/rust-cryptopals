use crate::{crypters::MODE, cryptovec::CryptoVec, errors::JlmCryptoErrors, oracle::Oracle};

pub struct OracleBase {
    pub key: Vec<u8>,
    pub prefix: Option<Vec<u8>>,
    pub suffix: Option<Vec<u8>>,
    pub iv: Option<Vec<u8>>,
    pub mode: MODE,
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
