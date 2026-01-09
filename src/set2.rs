#[cfg(test)]
mod tests {

    use crate::base64::Base64;
    use crate::crypters::{
        CustomCrypter11, CustomCrypter12, CustomCrypter13, CustomCrypter14, CustomCrypter16,
    };
    use crate::cryptovec::CryptoVec;
    use crate::oracle::Oracle;
    use crate::usizecrypt::USizeCrypt;

    use core::panic;
    use std::fs::File;
    use std::io::prelude::*;
    use std::str;

    const YELLOW_SUBMARINE_STRING : &str = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";

    #[test]
    fn challenge_9() {
        let size = 20;

        // String to pad with extra bytes
        let mut string_to_pad = b"YELLOW SUBMARINE".to_vec();

        // Pad the string to the specified size
        string_to_pad.pad(size).unwrap();

        // Verify that the padded string is equal to the provided array
        assert_eq!(
            &string_to_pad,
            [89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4,].as_ref()
        )
    }

    #[test]
    fn challenge_10() {
        let file_path = "./data/data_10.txt";

        // Open the specified file
        let mut file = File::open(file_path).expect("Unable to read file");
        let mut buffer = Vec::new();

        // Read the content of the file into a buffer
        file.read_to_end(&mut buffer).expect("Error reading file.");

        // Convert the buffer into a string and remove new line characters
        let buffer_to_string = str::from_utf8(&buffer).unwrap().replace("\n", "");

        // Convert the string from Base64 to bytes
        let input = Base64::from_string(buffer_to_string);
        let input_bytes = input
            .to_bytes()
            .unwrap_or_else(|_| panic!("Invalid Base64 to bytes"));

        // Initialization vector (IV)
        let iv = &[0; 16];

        // Try to decrypt the data using CBC mode
        if let Ok(v) = input_bytes.legacy_cbc_decrypt(b"YELLOW SUBMARINE", &mut iv.to_owned()) {
            let result = String::from_utf8(v).unwrap();

            // Verify that the result is equal to the provided string
            assert_eq!(YELLOW_SUBMARINE_STRING, result)
        }
    }

    // Test the detection of the encryption mode (ECB or CBC) used.
    #[test]
    pub fn challenge_11() {
        // Create an instance of the oracle with random encryption.
        let oracle = CustomCrypter11::new();

        match oracle {
            Ok(r) => {
                // Create an empty input and encrypt the bytes with the oracle.
                let input: Vec<u8> = vec![0; 48];
                let encrypted_value = r.base.encrypt(&input).unwrap();

                // Verify that the oracle detected the correct mode.
                if r.is_cbc() {
                    assert_eq!(r.is_ecb_calculated(encrypted_value).unwrap(), false);
                } else if r.is_ecb() {
                    assert_eq!(r.is_ecb_calculated(encrypted_value).unwrap(), true);
                }
            }
            Err(_) => {
                panic!();
            }
        }
    }

    #[test]
    pub fn challenge_12() {
        // Create an instance of the custom cryptographic oracle for challenge 12
        let oracle = CustomCrypter12::new();

        // Base64-encoded suffix to decode
        let base64_suffix = Base64::from_string(String::from(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",
    ));

        match oracle {
            Ok(r) => {
                // Input to encrypt
                let input: Vec<u8> = b"A".to_vec();

                // Get the encrypted value of the input
                let encrypted_value = r.base.encrypt(&input).unwrap();

                // Verify that the size of the encrypted value is a multiple of 16
                assert_eq!(encrypted_value.len() % 16, 0);

                // Verify that the Base64-encoded suffix is equal to the suffix obtained from the oracle
                assert_eq!(
                    base64_suffix,
                    Base64::from_bytes(r.get_suffix().unwrap().as_slice())
                )
            }
            Err(_) => {
                panic!();
            }
        }
    }

    #[test]
    pub fn challenge_13() {
        // Create an instance of the oracle CustomCrypter13
        let oracle13 = CustomCrypter13::new().unwrap();

        // Generate a malicious address
        let email = &String::from(oracle13.generate_test_email());

        // Create padding data
        let junk1: Vec<u8> = vec![65u8; 10];
        let mut admin_with_padding = b"admin".to_vec();
        let padding = vec![11; 11];

        // Add padding to the "admin" username
        admin_with_padding.extend_from_slice(&padding[..]);

        // Create a vector for the test data
        let mut test_bytes = Vec::new();

        // Add padding data and the padded username to the test data vector
        test_bytes.extend_from_slice(&junk1[..]);
        test_bytes.extend_from_slice(&admin_with_padding[..]);

        // Generate a cookie with a fake string to obtain the encrypted value of "admin"
        let ciphertext1 = &oracle13
            .encrypt(
                &oracle13
                    .profile_for(String::from_utf8(test_bytes[..].to_vec()).unwrap())
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();

        // Divide the encrypted value into 16-byte chunks
        let mut ciphertext1_chunks = ciphertext1.chunks(16);

        // Generate a cookie with a fake email address, which contains the user's role
        let ciphertext2 = &mut oracle13
            .encrypt(&oracle13.profile_for(email.to_string()).unwrap().as_bytes())
            .unwrap();

        // Get the last block of the encrypted value 1, which contains the encrypted value of "admin"
        let last_block = ciphertext1_chunks.nth(1).unwrap();

        // Remove all bytes after position 32 from ciphertext2
        ciphertext2.truncate(32);

        // Add the bytes of the last block to ciphertext2
        ciphertext2.extend_from_slice(&last_block);

        // Decrypt the new cookie that should contain the role "admin"
        let new_cookie_decrypted = ciphertext2
            .to_vec()
            .ssl_ecb_decrypt(&oracle13.base.key, Some(true))
            .unwrap();

        // Verify that the decrypted cookie contains the role "admin"
        assert!(String::from_utf8(new_cookie_decrypted)
            .unwrap()
            .ends_with("role=admin"));
    }

    #[test]
    pub fn challenge_14() {
        // Create an instance of the oracle CustomCrypter14
        let oracle = CustomCrypter14::new();

        // Base64-encoded suffix to decode
        let base64_suffix = Base64::from_string(String::from(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",
        ));

        match oracle {
            Ok(r) => {
                // Verify that the Base64-encoded suffix is equal to the suffix obtained from the oracle
                assert_eq!(
                    base64_suffix,
                    Base64::from_bytes(r.get_suffix().unwrap().as_slice())
                )
            }
            Err(_) => {
                panic!();
            }
        }
    }

    #[test]
    pub fn challenge_15() {
        // Strings with different padding schemes
        let str1 = String::from("ICE ICE BABY\x04\x04\x04\x04");
        let str2 = String::from("ICE ICE BABY\x05\x05\x05\x05");
        let str3 = String::from("ICE ICE BABY\x05\x05\x05\x05");

        // Convert the strings into mutable byte vectors
        let mut str1_vec = str1.as_bytes().to_vec();
        let str2_vec = str2.as_bytes().to_vec();
        let str3_vec = str3.as_bytes().to_vec();

        // Verify that the padding of str1 is valid (returns true)
        assert_eq!(str1_vec.check_padding_valid(16).unwrap(), true);

        // Verify that the padding of str2 is invalid (returns an error)
        assert_eq!(str2_vec.check_padding_valid(16).is_err(), true);

        // Verify that the padding of str3 is invalid (returns an error)
        assert_eq!(str3_vec.check_padding_valid(16).is_err(), true);

        // Remove padding from str1's data
        let _ = str1_vec.unpad(16);

        // Verify that the conversion to string of str1's bytes is "ICE ICE BABY"
        assert_eq!(String::from_utf8(str1_vec).unwrap(), "ICE ICE BABY");
    }

    #[test]
    pub fn challenge_16() {
        // Size of the key
        let key_size: usize = 16;

        // Generate a random IV of size key_size
        let iv: Vec<u8> = key_size.random_block();

        // Generate a random key of size key_size
        let key = key_size.random_block();

        // Create an instance of the oracle CustomCrypter16
        let oracle = CustomCrypter16::new();

        // Prepare a string to encrypt
        let plaintext1 = oracle.prepare_string("testing 123;admin=true;blah");

        // Encrypt the string with CBC using the key and IV, including padding
        let encrypted1 = plaintext1.ssl_cbc_encrypt(&key, &iv, Some(true)).unwrap();

        // Decrypt the encrypted string with CBC using the key and IV
        let decrypted1 = encrypted1.ssl_cbc_decrypt(&key, &iv, Some(true)).unwrap();

        // Get a string from the decrypted byte sequence
        let decrypted_string1 = String::from_utf8_lossy(&decrypted1);

        // Remove any escapes from the decrypted value
        let unquoted_decrypted_value1 = oracle.unquote_str(&decrypted_string1);

        // Verify if the decrypted value contains ";admin=true;"
        let check_contains_admin = unquoted_decrypted_value1.find(";admin=true;").is_some();
        assert_eq!(check_contains_admin, true);

        // Prepare a second string with the input "\x00admin\x00true"
        let plaintext2 = oracle.prepare_string("\x00admin\x00true");

        // Encrypt the second string with CBC using the key and IV, including padding
        let mut encrypted2 = plaintext2.ssl_cbc_encrypt(&key, &iv, Some(true)).unwrap();

        // Modify some bytes of the ciphertext to try to obtain ";admin=true;"
        encrypted2[16] ^= 59; // ASCII of character ";"
        encrypted2[22] ^= 61; // ASCII of character "="

        // Decrypt the modified ciphertext with CBC using the key and IV
        let decrypted2 = encrypted2.ssl_cbc_decrypt(&key, &iv, Some(true)).unwrap();

        // Get a string from the decrypted byte sequence
        let decrypted_string2 = String::from_utf8_lossy(&decrypted2);

        // Remove any escapes from the decrypted value
        let unquoted_decrypted_value2 = oracle.unquote_str(&decrypted_string2);

        // Verify if the decrypted value contains ";admin=true;"
        let check_contains_admin = unquoted_decrypted_value2.find(";admin=true;").is_some();
        assert_eq!(check_contains_admin, true);
    }
}
