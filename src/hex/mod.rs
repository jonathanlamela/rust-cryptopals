use std::{fmt, str::FromStr};

use crate::{base64::Base64, errors::JlmCryptoErrors};

/// Structure representing a hexadecimal sequence.
pub struct Hex(pub String);

/// Implementation of methods for the `Hex` structure.
impl Hex {
    /// Constructor to create a `Hex` object from a hexadecimal string with validation.
    /// Returns an error if the string is not a valid hexadecimal representation.
    pub fn from_string(s: String) -> Result<Hex, JlmCryptoErrors> {
        // First validation: check that the string contains only valid hexadecimal characters (0-9, a-f, A-F)
        // This uses the is_ascii_hexdigit() method which returns true for valid hex digits
        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(JlmCryptoErrors::InvalidHEXValue);
        }

        // Second validation: check if the string has an even number of characters
        // This is required because each byte is represented by exactly 2 hex characters
        if s.len() % 2 != 0 {
            return Err(JlmCryptoErrors::InvalidHEXValue);
        }

        // If both validations pass, return a Hex object wrapping the string
        Ok(Hex(s))
    }

    /// Constructor to create a `Hex` object from a hexadecimal string without validation.
    /// This method assumes the input is already valid hex and does not perform validation.
    /// Use this when you're certain the input is valid to avoid redundant validation checks.
    pub fn from_hex_string(s: String) -> Result<Hex, JlmCryptoErrors> {
        // Simply wraps the string in a Hex object without any validation
        Ok(Hex(s))
    }

    /// Constructor to create a `Hex` object from a byte vector.
    /// Each byte is converted to a two-character hexadecimal representation.
    pub fn from_bytes(s: Vec<u8>) -> Result<Hex, JlmCryptoErrors> {
        // Encodes the bytes into hexadecimal format without using external libraries
        // For each byte, format it as a 2-digit lowercase hexadecimal string
        // Example: byte 255 becomes "ff", byte 10 becomes "0a"
        let hex_string = s
            .iter()
            .map(|byte| format!("{:02x}", byte)) // {:02x} formats as 2 hex digits with leading zero if needed
            .collect::<String>(); // Concatenate all hex pairs into a single string
        Ok(Hex(hex_string))
    }

    /// Returns the length of the hexadecimal string in characters.
    /// Note: The actual number of bytes represented is half of this value,
    /// since each byte is represented by 2 hex characters.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Converts the `Hex` object into a byte vector.
    /// Each pair of hexadecimal characters is converted into a single byte.
    /// Returns an error if the conversion fails (e.g., invalid hex characters).
    pub fn to_bytes(&self) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Initialize an empty vector to store the resulting bytes
        let mut result = Vec::new();

        // Iterate over the hexadecimal string in steps of 2 (since each byte = 2 hex chars)
        // Example: "48656c6c6f" -> iterate at positions 0, 2, 4, 6, 8
        for i in (0..self.0.len()).step_by(2) {
            // Extract a pair of hexadecimal characters (e.g., "48", "65", "6c")
            let byte_str = &self.0[i..i + 2];

            // Convert the hexadecimal pair to a byte using base-16 parsing
            // from_str_radix parses the string as a base-16 (hexadecimal) number
            match u8::from_str_radix(byte_str, 16) {
                Ok(byte) => result.push(byte), // Add the byte to the result vector
                Err(_) => return Err(JlmCryptoErrors::InvalidHEXToBytesConversion), // Return error if parsing fails
            }
        }
        Ok(result)
    }

    /// Converts the `Hex` object into a `Base64` object.
    /// This implements the Base64 encoding algorithm manually.
    pub fn to_base64(&self) -> Result<Base64, JlmCryptoErrors> {
        // First, convert the hexadecimal string to bytes
        match &self.to_bytes() {
            Ok(v) => {
                // Base64 character set: A-Z (0-25), a-z (26-51), 0-9 (52-61), + (62), / (63)
                const BASE64_CHARS: &[u8] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

                let mut result = String::new();

                // Process the bytes in chunks of 3 bytes (24 bits)
                // Each chunk of 3 bytes is converted into 4 Base64 characters (6 bits each)
                for chunk in v.chunks(3) {
                    // Get the three bytes, padding with 0 if we have fewer than 3 bytes
                    let b1 = chunk[0];
                    let b2 = if chunk.len() > 1 { chunk[1] } else { 0 };
                    let b3 = if chunk.len() > 2 { chunk[2] } else { 0 };

                    // Combine the three bytes into a single 24-bit number
                    // b1 goes in the high 8 bits, b2 in the middle 8 bits, b3 in the low 8 bits
                    let n = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);

                    // Extract four 6-bit values from the 24-bit number and convert to Base64 chars
                    // First char: bits 18-23 (top 6 bits)
                    result.push(BASE64_CHARS[((n >> 18) & 63) as usize] as char);
                    // Second char: bits 12-17
                    result.push(BASE64_CHARS[((n >> 12) & 63) as usize] as char);
                    // Third char: bits 6-11 (or '=' padding if we only had 1 byte)
                    if chunk.len() > 1 {
                        result.push(BASE64_CHARS[((n >> 6) & 63) as usize] as char);
                    } else {
                        result.push('='); // Padding character
                    }
                    // Fourth char: bits 0-5 (or '=' padding if we only had 1 or 2 bytes)
                    if chunk.len() > 2 {
                        result.push(BASE64_CHARS[(n & 63) as usize] as char);
                    } else {
                        result.push('='); // Padding character
                    }
                }

                Ok(Base64::from_string(result))
            }
            Err(_) => Err(JlmCryptoErrors::InvalidHEXToBase64Conversion),
        }
    }
}

/// Implementation of the `FromStr` trait for the `Hex` structure.
/// This allows creating a Hex object from a string slice using the parse() method.
impl FromStr for Hex {
    type Err = JlmCryptoErrors;

    /// Converts a string slice into a `Hex` object.
    /// This is called when using str.parse::<Hex>() or Hex::from_str().
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Convert the string slice to an owned String and create a Hex object
        // Note: This uses from_hex_string which does NOT validate the input
        Hex::from_hex_string(s.to_string())
    }
}

/// Implementation of the `PartialEq` trait for the `Hex` structure.
/// This allows comparing two Hex objects for equality using == and !=.
impl PartialEq for Hex {
    /// Compares two `Hex` objects for equality.
    /// Two Hex objects are equal if their underlying hex strings are identical.
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// Implementation of the `Display` trait for the `Hex` structure.
/// This defines how a Hex object is displayed when using println!() or format!().
impl<'a> fmt::Display for Hex {
    /// Formats the `Hex` object for display.
    /// Simply outputs the raw hexadecimal string without any formatting.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Implementation of the `Debug` trait for the `Hex` structure.
/// This defines how a Hex object is displayed when using println!("{:?}") or dbg!().
impl<'a> fmt::Debug for Hex {
    /// Formats the `Hex` object for debugging with enhanced readability.
    /// Converts to lowercase and adds spaces between byte pairs for easier reading.
    /// Example: "48656c6c6f" becomes "Hex(48 65 6c 6c 6f)"
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Convert the hexadecimal string to lowercase for consistency
        let hex_string = self.0.to_lowercase();

        // Format the hex string with spaces between each byte (pair of hex digits)
        let spaced_hex_string = hex_string
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                // Insert a space before every character at an even index (except at position 0)
                // This creates pairs: "48656c" becomes "48 65 6c"
                if i > 0 && i % 2 == 0 {
                    Some(' ') // Add a space before this character
                } else {
                    None // Don't add a space
                }
                .into_iter() // Convert Option to iterator
                .chain(std::iter::once(c)) // Chain with the character itself
            })
            .collect::<String>(); // Collect all characters into a final string

        write!(f, "Hex({})", spaced_hex_string)
    }
}
