#[cfg(test)]
mod tests {
    use crate::base64::Base64;

    #[test]
    fn test_from_string() {
        let input = String::from("SGVsbG8gd29ybGQ=");
        let base64 = Base64::from_string(input.clone());
        assert_eq!(base64.0, input);
    }

    #[test]
    fn test_from_bytes() {
        let input = b"Hello world";
        let base64 = Base64::from_bytes(input);
        assert_eq!(base64.0, "SGVsbG8gd29ybGQ=");
    }
}
