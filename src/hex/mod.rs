use std::{fmt, str::FromStr};

use crate::{base64::Base64, errors::JlmCryptoErrors};

pub struct Hex(pub String);

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
            Ok(v) => {
                const BASE64_CHARS: &[u8] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                let mut result = String::new();

                for chunk in v.chunks(3) {
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

                Ok(Base64::from_string(result))
            }
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
