use std::fmt;

use crate::errors::JlmCryptoErrors;

pub struct Base64(pub String);

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
        const BASE64_CHARS: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();

        for chunk in s.chunks(3) {
            let b1 = chunk[0];
            let b2 = if chunk.len() > 1 { chunk[1] } else { 0 };
            let b3 = if chunk.len() > 2 { chunk[2] } else { 0 };

            let n = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);

            result.push(BASE64_CHARS[((n >> 18) & 63) as usize] as char);
            result.push(BASE64_CHARS[((n >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                result.push(BASE64_CHARS[((n >> 6) & 63) as usize] as char);
            } else {
                result.push('=');
            }
            if chunk.len() > 2 {
                result.push(BASE64_CHARS[(n & 63) as usize] as char);
            } else {
                result.push('=');
            }
        }

        Base64(result)
    }

    // Method that converts the `Base64` object into a byte vector.
    pub fn to_bytes(&self) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Decodes the Base64 string into bytes.
        const BASE64_CHARS: &str =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = Vec::new();
        let mut buffer = 0u32;
        let mut bits = 0;

        for c in self.0.chars() {
            if c == '=' {
                break;
            }

            if let Some(index) = BASE64_CHARS.find(c) {
                buffer = (buffer << 6) | (index as u32);
                bits += 6;

                if bits >= 8 {
                    bits -= 8;
                    result.push((buffer >> bits) as u8);
                    buffer &= (1 << bits) - 1;
                }
            } else if !c.is_whitespace() {
                return Err(JlmCryptoErrors::InvalidBase64ToBytes);
            }
        }

        Ok(result)
    }
}

// Implementation of the `PartialEq` trait for the `Base64` structure.
impl PartialEq for Base64 {
    // Method that compares two `Base64` objects for equality.
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
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
