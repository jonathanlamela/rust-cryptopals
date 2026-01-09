use std::str;

#[derive(Clone)]
pub struct CustomCrypter16 {}

impl CustomCrypter16 {
    // Create and return an instance of this structure `CustomCrypter16`.
    pub fn new() -> CustomCrypter16 {
        return CustomCrypter16 {};
    }

    // Adds quoting to occurrences of the characters ';' and '=' in the input string.
    pub fn quote_str(&self, input: &str) -> String {
        let mut quoted_input = str::replace(input, ";", "\";\"");
        quoted_input = str::replace(&quoted_input[..], "=", "\"=\"");

        quoted_input
    }

    // Removes the quoting added by the `quote_str` function.
    pub fn unquote_str(&self, input: &str) -> String {
        let mut quoted_input = str::replace(input, "\";\"", ";");
        quoted_input = str::replace(&quoted_input[..], "\"=\"", "=");

        quoted_input
    }

    // Prepares a string for encryption by adding specific prefixes and suffixes.
    pub fn prepare_string(&self, input: &str) -> Vec<u8> {
        let input_quoted: String = self.quote_str(input);

        let input_bytes = input_quoted.as_bytes();
        let prepend_bytes = b"comment1=cooking%20MCs;userdata=";
        let append_bytes = b";comment2=%20like%20a%20pound%20of%20bacon";

        let mut plaintext = Vec::new();

        // Adds the prefix bytes, the quoted input bytes, and the suffix bytes to the `plaintext` vector.
        plaintext.extend_from_slice(&prepend_bytes[..]);
        plaintext.extend_from_slice(&input_bytes[..]);
        plaintext.extend_from_slice(&append_bytes[..]);

        plaintext
    }
}
