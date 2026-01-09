#[cfg(test)]
mod tests {
    use crate::base64::Base64;

    use crate::cryptovec::{CryptoVec, CryptoVecChunks};
    use crate::hex::Hex;

    use core::panic;
    use std::fs::File;
    use std::io::prelude::*;
    use std::io::BufReader;
    use std::str;

    const YELLOW_SUBMARINE_STRING : &str = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";

    // Test the conversion from Hex to Base64.
    #[test]
    fn challenge_1() {
        // Compare the result of the operation with an expected value.
        assert_eq!(
            Hex::from_string(String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
                .unwrap()
                .to_base64()
                .unwrap(),
            Base64::from_string(String::from(
                "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
            ))
        );
    }

    // Test the XOR operation between two Hex values.
    #[test]
    fn challenge_2() {
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
    fn challenge_3() {
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
    fn challenge_4() {
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
    fn challenge_5() {
        // Convert the plaintext and key into byte arrays.
        let expected_result = Hex::from_string(String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")).unwrap();
        let clear_text_as_bytes =
            b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_vec();
        let clear_key_as_bytes = b"ICE";

        // Execute the repeated XOR encryption and compare with the expected result.
        let result = clear_text_as_bytes.repeating_key_xor(clear_key_as_bytes);
        let hex_result =
            Hex::from_bytes(result).unwrap_or_else(|_| panic!("Hex from bytes failed"));
        assert_eq!(expected_result, hex_result);
    }

    #[test]
    fn challenge_6() {
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
    fn challenge_7() {
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
    fn challenge_8() {
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
}
