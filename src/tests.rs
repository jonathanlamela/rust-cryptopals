use crate::base64::Base64;

use crate::crypters::{
    CustomCrypter11, CustomCrypter12, CustomCrypter13, CustomCrypter14, CustomCrypter16,
    CustomCrypter17,
};
use crate::cryptovec::{CryptoVec, CryptoVecChunks};
use crate::hex::Hex;
use crate::oracle::Oracle;
use crate::usizecrypt::USizeCrypt;

use core::panic;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::str;

const YELLOW_SUBMARINE_STRING : &str = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";

// Test the conversion from Hex to Base64.
#[test]
fn set_1_challenge_1() {
    // Compare the result of the operation with an expected value.
    assert_eq!(
            Hex::from_string(String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
                .unwrap()
                .to_b64()
                .unwrap(),
            Base64::from_string(String::from(
                "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
            ))
        );
}

// Test the XOR operation between two Hex values.
#[test]
fn set_1_challenge_2() {
    // Create Hex instances from the provided values.
    let hex1 = Hex::from_string(String::from("1c0111001f010100061a024b53535009181c")).unwrap();
    let hex2 = Hex::from_string(String::from("686974207468652062756c6c277320657965")).unwrap();

    // Convert Hex to byte array.
    let bytes1 = hex1.to_bytes().unwrap_or_else(|err| {
        panic!("Error converting from Hex to byte: {:?}", err);
    });
    let bytes2 = hex2.to_bytes().unwrap_or_else(|err| {
        panic!("Error converting from Hex to byte: {:?}", err);
    });

    // Perform XOR between the byte arrays.
    let xor_result = bytes1.xor(bytes2);

    // Create an expected Hex value from the XOR result.
    let expected_result =
        Hex::from_string(String::from("746865206b696420646f6e277420706c6179")).unwrap();

    // Convert the XOR result to Hex and compare it with the expected value.
    let result = Hex::from_bytes(xor_result).unwrap();
    assert_eq!(result, expected_result);
}

// Test the decryption of an XOR encrypted text with a single key.
#[test]
fn set_1_challenge_3() {
    // Decrypt an XOR encrypted text and verify the result.
    let result = Hex::from_string(String::from(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
    ))
    .unwrap()
    .to_bytes()
    .unwrap()
    .evaluate_frequency()
    .unwrap();

    // Compare the result with an expected value.
    let stringa = String::from_utf8(result.2).unwrap();
    assert_eq!(stringa, "Cooking MC's like a pound of bacon");
}

// Test the decryption of XOR encrypted texts to find the correct plaintext.
#[test]
fn set_1_challenge_4() {
    // Read the file containing the XOR encrypted texts.
    let file_path = "./data/data_4.txt";
    let file = File::open(file_path).expect("Unable to read file");
    let buf_reader = BufReader::new(file);
    let mut readed_lines: Vec<(f64, String, Vec<u8>)> = Vec::new();

    // Iterate over the lines of the file.
    for line in buf_reader.lines() {
        if line.is_ok() {
            let unwrapped_line = line.unwrap();

            // Create a Hex instance from the read line and convert it to a byte array.
            let hex_value = Hex::from_string(unwrapped_line.clone())
                .unwrap_or_else(|_| panic!("Conversion from Hex to byte failed"));

            let bytes = hex_value.to_bytes().unwrap_or_else(|_| {
                panic!("Conversion from Hex to byte failed");
            });

            // Calculate the character frequency and store the result.
            match bytes.evaluate_frequency() {
                Some(result) => {
                    readed_lines.push((result.0, unwrapped_line, result.2));
                }
                None => {}
            };
        }
    }

    // Check if there are valid results.
    if readed_lines.len() > 0 {
        // Find the result with the highest frequency among those stored.
        let value = readed_lines
            .iter()
            .min_by(|(a, _, _), (b, _, _)| b.partial_cmp(a).unwrap());

        let value_unwrapped = value.unwrap();

        // Convert the decrypted bytes into a string and compare with the expected value.
        let stringa = str::from_utf8(&value_unwrapped.2).unwrap();
        assert_eq!(stringa, "Now that the party is jumping\n")
    } else {
        panic!("Test failed: No valid results found");
    }
}

// Test the repeated XOR encryption of a plaintext.
#[test]
fn set_1_challenge_5() {
    // Convert the plaintext and key into byte arrays.
    let expected_result = Hex::from_string(String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")).unwrap();
    let clear_text_as_bytes =
        b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_vec();
    let clear_key_as_bytes = b"ICE";

    // Execute the repeated XOR encryption and compare with the expected result.
    let result = clear_text_as_bytes.repeating_key_xor(clear_key_as_bytes);
    let hex_result = Hex::from_bytes(result).unwrap_or_else(|_| panic!("Hex from bytes failed"));
    assert_eq!(expected_result, hex_result);
}

#[test]
fn set_1_challenge_6() {
    let file_path = "./data/data_6.txt";

    // Read the file from path supplied
    let mut file = File::open(file_path).expect("Unable to read file");
    let mut buffer = Vec::new();

    file.read_to_end(&mut buffer).expect("Error reading file.");

    let buffer_to_string = &str::from_utf8(&buffer).unwrap().replace("\n", "");

    let input: Base64 = Base64::from_string(buffer_to_string.to_string());

    match input.to_bytes() {
        Ok(bytes) => match bytes.repeating_xor_attack() {
            Ok(result) => {
                assert_eq!(result, YELLOW_SUBMARINE_STRING)
            }
            Err(_) => panic!("Test failed"),
        },
        Err(_) => {
            panic!("Invalid base64 to bytes")
        }
    }
}

// Test the encryption and decryption of a text using AES in ECB mode.
#[test]
fn set_1_challenge_7() {
    let expected_result = String::from("testo di prova");

    // Convert the encrypted content from Base64 to Base64.
    let encrypted_content = Base64::from_string(String::from("ZlBz+2/3RVo7TTsubWlesA=="));

    // Convert the encrypted content into a byte array.
    let encrypted_bytes = encrypted_content
        .to_bytes()
        .unwrap_or_else(|_| panic!("Base64 to bytes failed"));

    // Decrypt the content using AES in ECB mode and verify the result.
    let decrypted_bytes = encrypted_bytes
        .ssl_ecb_decrypt(b"YELLOW SUBMARINE", Some(true))
        .unwrap();

    // Convert the decrypted bytes into a string and compare with the expected value.
    let decrypted_string = str::from_utf8(&decrypted_bytes).unwrap().to_string();
    assert_eq!(decrypted_string, expected_result)
}

#[test]
fn set_1_challenge_8() {
    // Open the specified file
    let file_path = "./data/data_8.txt";
    let file = File::open(file_path).expect("Unable to read file");
    let buf_reader = BufReader::new(file);

    // Read the file line by line
    for line in buf_reader.lines() {
        // If reading the line was successful
        if line.is_ok() {
            // Get the content of the line
            let unwrapped_line = line.unwrap();
            let line_bytes = unwrapped_line.as_bytes();

            // Divide the line's bytes into chunks of 32 bytes each
            let mut v_slices: Vec<&[u8]> = line_bytes.chunks(32).collect();

            // Check for duplicate chunks
            if v_slices.contains_duplicates() {
                // Verify that the line is equal to the provided string
                assert_eq!(unwrapped_line,"d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")
            }
        }
    }
}

#[test]
fn set_2_challenge_9() {
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
fn set_2_challenge_10() {
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
pub fn set_2_challenge_11() {
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
pub fn set_2_challenge_12() {
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
pub fn set_2_challenge_13() {
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
pub fn set_2_challenge_14() {
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
pub fn set_2_challenge_15() {
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
pub fn set_2_challenge_16() {
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

#[test]
pub fn set_3_challenge_17() {
    // Create an instance of CustomCrypter17
    let crypter = CustomCrypter17::new().unwrap();

    // Block size
    const BLOCK_SIZE: usize = 16;

    // Initialize the key and IV with random 16-byte values
    let key = BLOCK_SIZE.random_block();
    let iv = BLOCK_SIZE.random_block();

    // Get the value to decrypt from position 8 of the tokens obtained from CustomCrypter17
    let clear_value = Base64::from_string(crypter.get_all_tokens().get(8).unwrap().to_string());
    let clear_bytes = clear_value.to_bytes().unwrap();

    // Perform CBC encryption of the bytes with the provided key and IV
    let encrypted_value = clear_bytes.to_vec().ssl_cbc_encrypt(&key, &iv, Some(false));

    match encrypted_value {
        Ok(ciphertext) => {
            // Initialize the cleartext_encrypted vector to hold the encrypted plaintext
            let mut cleartext_encrypted = vec![0; ciphertext.len()];
            let mut prev = iv.clone();

            // Divide the ciphertext into blocks
            let chunks = ciphertext.chunks(BLOCK_SIZE);

            // Iterate over each encrypted block
            for (block_index, block) in chunks.enumerate() {
                let block_offset = block_index * BLOCK_SIZE;

                // Iterate backwards within the block
                for i in (0..BLOCK_SIZE).rev() {
                    let padding = (BLOCK_SIZE - i) as u8;
                    let t = [(padding - 1) ^ padding];
                    let xor_res = prev[i + 1..].to_vec().xor_single(t[0]);
                    prev[i + 1..].copy_from_slice(&xor_res);

                    // Try all possible values for the last byte of the previous block
                    for u in 0u8..=255 {
                        prev[i] ^= u;
                        let value_decrypted =
                            block.to_vec().ssl_cbc_decrypt(&key, &prev, Some(true));

                        // Verify if the value has been decrypted correctly
                        if value_decrypted.is_ok()
                            && (i < BLOCK_SIZE - 1 || {
                                prev[i - 1] ^= 1;
                                let result =
                                    block.to_vec().ssl_cbc_decrypt(&key, &prev, Some(true));
                                prev[i - 1] ^= 1;
                                result.is_ok()
                            })
                        {
                            // Calculate the new plaintext byte
                            let new_content = padding ^ u;
                            cleartext_encrypted[block_offset + i] = new_content;

                            break;
                        }
                        prev[i] ^= u;
                    }
                }
                prev = block.to_vec();
            }

            // Remove padding from decrypted bytes
            let _ = cleartext_encrypted.unpad(16);

            // Decrypt the original bytes and those obtained after the process
            let decrypted_first = clear_bytes.ssl_cbc_decrypt(&key, &iv, Some(false));
            let decrypted_second = cleartext_encrypted.ssl_cbc_decrypt(&key, &iv, Some(false));

            // Verify that the two decrypted texts are equal
            assert_eq!(decrypted_first.unwrap(), decrypted_second.unwrap());
        }
        Err(_) => {}
    }
}

#[test]
pub fn set_3_challenge_18() {
    // Base64-encoded ciphertext to decrypt (AES-CTR mode, key: "YELLOW SUBMARINE")
    let ciphertext = Base64::from_string(String::from(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
    ));

    // Decode the Base64 ciphertext to bytes, then decrypt using AES-CTR with the given key
    let cleartext = ciphertext
        .to_bytes()
        .unwrap()
        .ssl_ctr_decrypt(b"YELLOW SUBMARINE", Some(true))
        .unwrap();

    // Convert the decrypted bytes to a UTF-8 string
    let result = String::from_utf8_lossy(&cleartext);

    // Assert that the decrypted string matches the expected plaintext
    assert_eq!(
        result,
        "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
    )
}

#[test]
pub fn set_3_challenge_19() {
    // Block size
    const BLOCK_SIZE: usize = 16;

    // Generate a random key
    let key = BLOCK_SIZE.random_block();

    // Read the file data_19
    let file_path = "./data/data_19.txt";
    let file = File::open(file_path).expect("Unable to read the file");
    let buf_reader = BufReader::new(file);

    let mut results: Vec<Vec<u8>> = Vec::new();

    // Read the file line by line
    for line in buf_reader.lines() {
        // If reading the line was successful
        if line.is_ok() {
            // Get the content of the line
            let unwrapped_line = line.unwrap();
            let line_bytes = Base64::from_string(unwrapped_line);

            if let Ok(bytes) = line_bytes.to_bytes() {
                if let Ok(encrypt_result) = bytes.nonce_ctr_encrypt(&key, vec![0; 8]) {
                    results.push(encrypt_result);
                }
            }
        }
    }

    assert!(results.len() != 0);
}

#[test]
pub fn set_3_challenge_20() {
    // Block size
    const BLOCK_SIZE: usize = 16;

    // Generate a random key
    let key = BLOCK_SIZE.random_block();

    // Read the file data_19
    let file_path = "./data/data_20.txt";
    let file = File::open(file_path).expect("Unable to read the file");
    let buf_reader = BufReader::new(file);

    let mut results: Vec<Vec<u8>> = Vec::new();

    // Read the file line by line
    for line in buf_reader.lines() {
        // If reading the line was successful
        if line.is_ok() {
            // Get the content of the line
            let unwrapped_line = line.unwrap();

            // Convert the Base64 string to bytes
            let line_bytes = Base64::from_string(unwrapped_line);

            if let Ok(bytes) = line_bytes.to_bytes() {
                // Encrypt the bytes using AES-CTR with zero nonce
                if let Ok(encrypt_result) = bytes.nonce_ctr_encrypt(&key, vec![0; 8]) {
                    results.push(encrypt_result);
                }
            }
        }
    }

    // Get the minimum length of the ciphertext results
    let min = results.iter().map(|c| c.len()).min().unwrap();

    // Truncate all results to the minimum length
    for ciphertext in &mut results {
        ciphertext.truncate(min);
    }

    // Transpose the ciphertext results for a repeated XOR attack
    let mut transposed: Vec<Vec<u8>> = vec![vec![]; min];
    for string in &results {
        for i in 0..string.len() {
            let item = string[i];
            transposed[i].push(item);
        }
    }

    // Initialize a vector for the decryption key.
    let mut k_vec: Vec<u8> = Vec::new();

    // Perform the repeated XOR attack on the data blocks.
    for bl in transposed {
        match bl.evaluate_frequency() {
            // If frequency analysis returns a possible key
            Some((_, key, _)) => k_vec.push(key),
            // Otherwise, continue with the next block
            None => {}
        }
    }

    // Combine all ciphertext results into a single vector
    let flat_result: Vec<u8> = results.into_iter().flat_map(|f| f).collect();

    // Apply the XOR operation with the found decryption key
    let res = flat_result.repeating_key_xor(&k_vec);

    // Convert the decrypted results into a UTF-8 string
    let res_plain = String::from_utf8(res).unwrap();

    // Verify that the decrypted string contains the desired substring
    assert!(res_plain.contains("I'm rated"));
}
