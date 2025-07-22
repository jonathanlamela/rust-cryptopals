#[cfg(test)]
mod tests {
    use crate::consts::YELLOW_SUBMARINE_STRING;
    use crate::structs::{
        Base64, CustomCrypter11, CustomCrypter12, CustomCrypter13, CustomCrypter14,
        CustomCrypter16, CustomCrypter17, Hex,
    };
    use crate::traits::{CryptoVec, CryptoVecChunks, Oracle, USizeCrypt};

    use core::panic;
    use std::fs::File;
    use std::io::prelude::*;
    use std::io::BufReader;
    use std::str;

    // Testa la funzione di conversione da Hex a Base64.
    #[test]
    fn set_1_challenge_1() {
        // Confronta il risultato dell'operazione con un valore atteso.
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

    // Testa l'operazione di XOR tra due valori Hex.
    #[test]
    fn set_1_challenge_2() {
        // Crea istanze Hex dai valori forniti.
        let hex1 = Hex::from_string(String::from("1c0111001f010100061a024b53535009181c")).unwrap();
        let hex2 = Hex::from_string(String::from("686974207468652062756c6c277320657965")).unwrap();

        // Converti Hex in byte array.
        let bytes1 = hex1.to_bytes().unwrap_or_else(|err| {
            panic!("Errore nella conversione da Hex a byte: {:?}", err);
        });
        let bytes2 = hex2.to_bytes().unwrap_or_else(|err| {
            panic!("Errore nella conversione da Hex a byte: {:?}", err);
        });

        // Esegui XOR tra i byte array.
        let xor_result = bytes1.xor(bytes2);

        // Crea un valore Hex atteso dal risultato dell'XOR.
        let expected_result =
            Hex::from_string(String::from("746865206b696420646f6e277420706c6179")).unwrap();

        // Converti il risultato dell'XOR in Hex e confrontalo con il valore atteso.
        let result = Hex::from_bytes(xor_result).unwrap();
        assert_eq!(result, expected_result);
    }

    // Testa la decrittografia di un testo cifrato XOR con una chiave singola.
    #[test]
    fn set_1_challenge_3() {
        // Decifra un testo cifrato XOR e verifica il risultato.
        let result = Hex::from_string(String::from(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
        ))
        .unwrap()
        .to_bytes()
        .unwrap()
        .evaluate_frequency()
        .unwrap();

        // Confronta il risultato con un valore atteso.
        let stringa = String::from_utf8(result.2).unwrap();
        assert_eq!(stringa, "Cooking MC's like a pound of bacon");
    }

    // Testa la decifrazione di testi cifrati XOR per trovare il testo in chiaro corretto.
    #[test]
    fn set_1_challenge_4() {
        // Legge il file contenente i testi cifrati XOR.
        let file_path = "./data/data_4.txt";
        let file = File::open(file_path).expect("Impossibile leggere il file");
        let buf_reader = BufReader::new(file);
        let mut readed_lines: Vec<(f64, String, Vec<u8>)> = Vec::new();

        // Itera sulle linee del file.
        for line in buf_reader.lines() {
            if line.is_ok() {
                let unwrapped_line = line.unwrap();

                // Crea un'istanza Hex dalla linea letta e converte in byte array.
                let hex_value = Hex::from_string(unwrapped_line.clone())
                    .unwrap_or_else(|_| panic!("Conversione da Hex a byte fallita"));

                let bytes = hex_value.to_bytes().unwrap_or_else(|_| {
                    panic!("Conversione da Hex a byte fallita");
                });

                // Calcola la frequenza dei caratteri e memorizza il risultato.
                match bytes.evaluate_frequency() {
                    Some(result) => {
                        readed_lines.push((result.0, unwrapped_line, result.2));
                    }
                    None => {}
                };
            }
        }

        // Verifica se ci sono risultati validi.
        if readed_lines.len() > 0 {
            // Trova il risultato con la frequenza massima tra quelli memorizzati.
            let value = readed_lines
                .iter()
                .min_by(|(a, _, _), (b, _, _)| b.partial_cmp(a).unwrap());

            let value_unwrapped = value.unwrap();

            // Converte i byte decifrati in una stringa e confronta con il valore atteso.
            let stringa = str::from_utf8(&value_unwrapped.2).unwrap();
            assert_eq!(stringa, "Now that the party is jumping\n")
        } else {
            panic!("Test fallito")
        }
    }

    // Testa la crittografia XOR ripetuta di un testo in chiaro.
    #[test]
    fn set_1_challenge_5() {
        // Converte i valori in chiaro e la chiave in byte array.
        let expected_result = Hex::from_string(String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")).unwrap();
        let clear_text_as_bytes =
            b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_vec();
        let clear_key_as_bytes = b"ICE";

        // Esegui la crittografia XOR ripetuta e confronta con il risultato atteso.
        let result = clear_text_as_bytes.repeating_key_xor(clear_key_as_bytes);
        let hex_result =
            Hex::from_bytes(result).unwrap_or_else(|_| panic!("Hex da byte non valido"));
        assert_eq!(expected_result, hex_result);
    }

    #[test]
    fn set_1_challenge_6() {
        let file_path = "./data/data_6.txt";

        //Read the file from path supplied
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

    // Testa la crittografia e decrittografia di un testo utilizzando AES in modalità ECB.
    #[test]
    fn set_1_challenge_7() {
        let expected_result = String::from("testo di prova");

        // Converti il contenuto cifrato da Base64 a Base64.
        let encrypted_content = Base64::from_string(String::from("ZlBz+2/3RVo7TTsubWlesA=="));

        // Converti il contenuto cifrato in byte array.
        let encrypted_bytes = encrypted_content
            .to_bytes()
            .unwrap_or_else(|_| panic!("Base64 da byte non valido"));

        // Decifra il contenuto utilizzando AES in modalità ECB e verifica il risultato.
        let decrypted_bytes = encrypted_bytes
            .ssl_ecb_decrypt(b"YELLOW SUBMARINE", Some(true))
            .unwrap();

        // Converte i byte decifrati in una stringa e confronta con il valore atteso.
        let decrypted_string = str::from_utf8(&decrypted_bytes).unwrap().to_string();
        assert_eq!(decrypted_string, expected_result)
    }

    #[test]
    fn set_1_challenge_8() {
        // Apre il file specificato
        let file_path = "./data/data_8.txt";
        let file = File::open(file_path).expect("Impossibile leggere il file");
        let buf_reader = BufReader::new(file);

        // Legge il file linea per linea
        for line in buf_reader.lines() {
            // Se la lettura della linea è avvenuta senza errori
            if line.is_ok() {
                // Ottiene il contenuto della linea
                let unwrapped_line = line.unwrap();
                let line_bytes = unwrapped_line.as_bytes();

                // Divide i byte della linea in pezzi di 32 byte ciascuno
                let mut v_slices: Vec<&[u8]> = line_bytes.chunks(32).collect();

                // Controlla se ci sono pezzi duplicati
                if v_slices.contains_duplicates() {
                    // Verifica che la linea sia uguale alla stringa fornita
                    assert_eq!(unwrapped_line,"d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")
                }
            }
        }
    }

    #[test]
    fn set_2_challenge_9() {
        let size = 20;

        // Stringa da riempire con byte extra
        let mut string_to_pad = b"YELLOW SUBMARINE".to_vec();

        // Riempie la stringa fino alla dimensione specificata
        string_to_pad.pad(size).unwrap();

        // Verifica che la stringa riempita sia uguale all'array fornito
        assert_eq!(
            &string_to_pad,
            [89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4,].as_ref()
        )
    }

    #[test]
    fn set_2_challenge_10() {
        let file_path = "./data/data_10.txt";

        // Apre il file specificato
        let mut file = File::open(file_path).expect("Impossibile leggere il file");
        let mut buffer = Vec::new();

        // Legge il contenuto del file in un buffer
        file.read_to_end(&mut buffer)
            .expect("Errore durante la lettura del file.");

        // Converti il buffer in una stringa e rimuovi i caratteri di nuova linea
        let buffer_to_string = str::from_utf8(&buffer).unwrap().replace("\n", "");

        // Converte la stringa da Base64 a bytes
        let input = Base64::from_string(buffer_to_string);
        let input_bytes = input
            .to_bytes()
            .unwrap_or_else(|_| panic!("Base64 non valido"));

        // Inizializzazione del vettore di inizializzazione (IV)
        let iv = &[0; 16];

        // Prova a decifrare i dati usando CBC mode
        if let Ok(v) = input_bytes.legacy_cbc_decrypt(b"YELLOW SUBMARINE", &mut iv.to_owned()) {
            let result = String::from_utf8(v).unwrap();

            // Verifica che il risultato sia uguale alla stringa fornita
            assert_eq!(YELLOW_SUBMARINE_STRING, result)
        }
    }

    // Testa il rilevamento della modalità di crittografia (ECB o CBC) utilizzata.
    #[test]
    pub fn set_2_challenge_11() {
        // Crea un'istanza dell'oracolo con crittografia casuale.
        let oracle = CustomCrypter11::new();

        match oracle {
            Ok(r) => {
                // Crea un input vuoto e cifra i byte con l'oracolo.
                let input: Vec<u8> = vec![0; 48];
                let encrypted_value = r.base.encrypt(&input).unwrap();

                // Verifica se l'oracolo ha rilevato la modalità corretta.
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
        // Crea un'istanza dell'oracle crittografico personalizzato per la sfida 12
        let oracle = CustomCrypter12::new();

        // Suffix in formato Base64 da decodificare
        let base64_suffix = Base64::from_string(String::from(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",
    ));

        match oracle {
            Ok(r) => {
                // Input da crittografare
                let input: Vec<u8> = b"A".to_vec();

                // Ottieni il valore crittografato dell'input
                let encrypted_value = r.base.encrypt(&input).unwrap();

                // Verifica che la dimensione del valore crittografato sia un multiplo di 16
                assert_eq!(encrypted_value.len() % 16, 0);

                // Verifica che il suffisso in formato Base64 sia uguale al suffisso ottenuto dall'oracle
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
        // Crea un'istanza dell'oracolo CustomCrypter13
        let oracle13 = CustomCrypter13::new().unwrap();

        // Genera un indirizzo malevolo
        let email = &String::from(oracle13.generate_test_email());

        // Crea dati di riempimento
        let junk1: Vec<u8> = vec![65u8; 10];
        let mut admin_with_padding = b"admin".to_vec();
        let padding = vec![11; 11];

        // Aggiungi il padding all'username "admin"
        admin_with_padding.extend_from_slice(&padding[..]);

        // Crea un vettore per i dati di test
        let mut test_bytes = Vec::new();

        // Aggiungi dati di riempimento e l'username con padding al vettore dei dati di test
        test_bytes.extend_from_slice(&junk1[..]);
        test_bytes.extend_from_slice(&admin_with_padding[..]);

        // Genera un cookie con una stringa fasulla per ottenere il valore criptato di "admin"
        let ciphertext1 = &oracle13
            .encrypt(
                &oracle13
                    .profile_for(String::from_utf8(test_bytes[..].to_vec()).unwrap())
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();

        // Dividi il valore crittografato in blocchi da 16 byte
        let mut ciphertext1_chunks = ciphertext1.chunks(16);

        // Genera un cookie con un falso indirizzo email, che contiene il ruolo dell'utente
        let ciphertext2 = &mut oracle13
            .encrypt(&oracle13.profile_for(email.to_string()).unwrap().as_bytes())
            .unwrap();

        // Ottieni l'ultimo blocco del valore crittografato 1, che contiene il valore criptato di "admin"
        let last_block = ciphertext1_chunks.nth(1).unwrap();

        // Rimuovi tutti i byte dopo la posizione 32 da ciphertext2
        ciphertext2.truncate(32);

        // Aggiungi al ciphertext2 i byte dell'ultimo blocco
        ciphertext2.extend_from_slice(&last_block);

        // Decifra il nuovo cookie che dovrebbe contenere il ruolo "admin"
        let new_cookie_decrypted = ciphertext2
            .to_vec()
            .ssl_ecb_decrypt(&oracle13.base.key, Some(true))
            .unwrap();

        // Verifica che il cookie decifrato contenga il ruolo "admin"
        assert!(String::from_utf8(new_cookie_decrypted)
            .unwrap()
            .ends_with("role=admin"));
    }

    #[test]
    pub fn set_2_challenge_14() {
        // Crea un'istanza dell'oracolo CustomCrypter14
        let oracle = CustomCrypter14::new();

        // Suffix in formato Base64 da decodificare
        let base64_suffix = Base64::from_string(String::from(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",
        ));

        match oracle {
            Ok(r) => {
                // Verifica che il suffisso in formato Base64 sia uguale al suffisso ottenuto dall'oracolo
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
        // Stringhe con diversi schemi di padding
        let str1 = String::from("ICE ICE BABY\x04\x04\x04\x04");
        let str2 = String::from("ICE ICE BABY\x05\x05\x05\x05");
        let str3 = String::from("ICE ICE BABY\x05\x05\x05\x05");

        // Converti le stringhe in vettori di byte mutabili
        let mut str1_vec = str1.as_bytes().to_vec();
        let str2_vec = str2.as_bytes().to_vec();
        let str3_vec = str3.as_bytes().to_vec();

        // Verifica se il padding di str1 è valido (ritorna true)
        assert_eq!(str1_vec.check_padding_valid(16).unwrap(), true);

        // Verifica se il padding di str2 è invalido (ritorna un errore)
        assert_eq!(str2_vec.check_padding_valid(16).is_err(), true);

        // Verifica se il padding di str3 è invalido (ritorna un errore)
        assert_eq!(str3_vec.check_padding_valid(16).is_err(), true);

        // Rimuovi il padding dai dati di str1
        let _ = str1_vec.unpad(16);

        // Verifica che la conversione in stringa dei byte di str1 sia "ICE ICE BABY"
        assert_eq!(String::from_utf8(str1_vec).unwrap(), "ICE ICE BABY");
    }

    #[test]
    pub fn set_2_challenge_16() {
        // Dimensione della chiave e del vettore di inizializzazione (IV)
        let key_size: usize = 16;

        // Genera un IV casuale di dimensione key_size
        let iv: Vec<u8> = key_size.random_block();

        // Genera una chiave casuale di dimensione key_size
        let key = key_size.random_block();

        // Crea un'istanza dell'oracolo CustomCrypter16
        let oracle = CustomCrypter16::new();

        // Prepara una stringa da crittografare
        let plaintext1 = oracle.prepare_string("testing 123;admin=true;blah");

        // Cifra la stringa con CBC usando la chiave e l'IV, includendo il padding
        let encrypted1 = plaintext1.ssl_cbc_encrypt(&key, &iv, Some(true)).unwrap();

        // Decifra la stringa cifrata con CBC usando la chiave e l'IV
        let decrypted1 = encrypted1.ssl_cbc_decrypt(&key, &iv, Some(true)).unwrap();

        // Ottieni una stringa dalla sequenza di byte decifrata
        let decrypted_string1 = String::from_utf8_lossy(&decrypted1);

        // Rimuovi eventuali escape dal valore decifrato
        let unquoted_decrypted_value1 = oracle.unquote_str(&decrypted_string1);

        // Verifica se il valore decifrato contiene ";admin=true;"
        let check_contains_admin = unquoted_decrypted_value1.find(";admin=true;").is_some();
        assert_eq!(check_contains_admin, true);

        // Prepara una seconda stringa con l'input "\x00admin\x00true"
        let plaintext2 = oracle.prepare_string("\x00admin\x00true");

        // Cifra la seconda stringa con CBC usando la chiave e l'IV, includendo il padding
        let mut encrypted2 = plaintext2.ssl_cbc_encrypt(&key, &iv, Some(true)).unwrap();

        // Modifica manualmente alcuni byte del ciphertext per cercare di ottenere ";admin=true;"
        encrypted2[16] ^= 59; // ASCII del carattere ";"
        encrypted2[22] ^= 61; // ASCII del carattere "="

        // Decifra il ciphertext modificato con CBC usando la chiave e l'IV
        let decrypted2 = encrypted2.ssl_cbc_decrypt(&key, &iv, Some(true)).unwrap();

        // Ottieni una stringa dalla sequenza di byte decifrata
        let decrypted_string2 = String::from_utf8_lossy(&decrypted2);

        // Rimuovi eventuali escape dal valore decifrato
        let unquoted_decrypted_value2 = oracle.unquote_str(&decrypted_string2);

        // Verifica se il valore decifrato contiene ";admin=true;"
        let check_contains_admin = unquoted_decrypted_value2.find(";admin=true;").is_some();
        assert_eq!(check_contains_admin, true);
    }

    #[test]
    pub fn set_3_challenge_17() {
        // Crea un oggetto CustomCrypter17
        let crypter = CustomCrypter17::new().unwrap();

        // Dimensione di un blocco
        const BLOCK_SIZE: usize = 16;

        // Inizializza la chiave e l'IV con valori random di 16 bytes
        let key = BLOCK_SIZE.random_block();
        let iv = BLOCK_SIZE.random_block();

        // Ottiene il valore da decifrare dalla posizione 8 dei token ottenuti da CustomCrypter17
        let clear_value = Base64::from_string(crypter.get_all_tokens().get(8).unwrap().to_string());
        let clear_bytes = clear_value.to_bytes().unwrap();

        // Esegue la cifratura CBC dei byte con la chiave e l'IV forniti
        let encrypted_value = clear_bytes.to_vec().ssl_cbc_encrypt(&key, &iv, Some(false));

        match encrypted_value {
            Ok(ciphertext) => {
                // Inizializza il vettore cleartext_encrypted per contenere il testo in chiaro cryptato
                let mut cleartext_encrypted = vec![0; ciphertext.len()];
                let mut prev = iv.clone();

                // Divide il testo cifrato in blocchi
                let chunks = ciphertext.chunks(BLOCK_SIZE);

                // Itera su ogni blocco cifrato
                for (block_index, block) in chunks.enumerate() {
                    let block_offset = block_index * BLOCK_SIZE;

                    // Itera all'indietro all'interno del blocco
                    for i in (0..BLOCK_SIZE).rev() {
                        let padding = (BLOCK_SIZE - i) as u8;
                        let t = [(padding - 1) ^ padding];
                        let xor_res = prev[i + 1..].to_vec().xor_single(t[0]);
                        prev[i + 1..].copy_from_slice(&xor_res);

                        // Prova tutti i possibili valori per l'ultimo byte del blocco precedente
                        for u in 0u8..=255 {
                            prev[i] ^= u;
                            let value_decrypted =
                                block.to_vec().ssl_cbc_decrypt(&key, &prev, Some(true));

                            // Verifica se il valore è stato decifrato correttamente
                            if value_decrypted.is_ok()
                                && (i < BLOCK_SIZE - 1 || {
                                    prev[i - 1] ^= 1;
                                    let result =
                                        block.to_vec().ssl_cbc_decrypt(&key, &prev, Some(true));
                                    prev[i - 1] ^= 1;
                                    result.is_ok()
                                })
                            {
                                // Calcola il nuovo byte del testo in chiaro
                                let new_content = padding ^ u;
                                cleartext_encrypted[block_offset + i] = new_content;

                                break;
                            }
                            prev[i] ^= u;
                        }
                    }
                    prev = block.to_vec();
                }

                // Rimuove il padding dai byte decifrati
                let _ = cleartext_encrypted.unpad(16);

                // Decifra i byte originali e quelli ottenuti dopo il processo
                let decrypted_first = clear_bytes.ssl_cbc_decrypt(&key, &iv, Some(false));
                let decrypted_second = cleartext_encrypted.ssl_cbc_decrypt(&key, &iv, Some(false));

                // Verifica che i due testi decifrati siano uguali
                assert_eq!(decrypted_first.unwrap(), decrypted_second.unwrap());
            }
            Err(_) => {}
        }
    }

    #[test]
    pub fn set_3_challenge_18() {
        let ciphertext = Base64::from_string(String::from(
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
        ));

        let cleartext = ciphertext
            .to_bytes()
            .unwrap()
            .ssl_ctr_decrypt(b"YELLOW SUBMARINE", Some(true))
            .unwrap();

        let result = String::from_utf8_lossy(&cleartext);

        assert_eq!(
            result,
            "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
        )
    }

    #[test]
    pub fn set_3_challenge_19() {
        // Dimensione di un blocco
        const BLOCK_SIZE: usize = 16;

        // Genera una chiave random
        let key = BLOCK_SIZE.random_block();

        //Legge il file data_19
        let file_path = "./data/data_19.txt";
        let file = File::open(file_path).expect("Impossibile leggere il file");
        let buf_reader = BufReader::new(file);

        let mut results: Vec<Vec<u8>> = Vec::new();

        // Legge il file linea per linea
        for line in buf_reader.lines() {
            // Se la lettura della linea è avvenuta senza errori
            if line.is_ok() {
                // Ottiene il contenuto della linea
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
        // Dimensione di un blocco
        const BLOCK_SIZE: usize = 16;

        // Genera una chiave random
        let key = BLOCK_SIZE.random_block();

        // Legge il file data_19
        let file_path = "./data/data_20.txt";
        let file = File::open(file_path).expect("Impossibile leggere il file");
        let buf_reader = BufReader::new(file);

        let mut results: Vec<Vec<u8>> = Vec::new();

        // Legge il file linea per linea
        for line in buf_reader.lines() {
            // Se la lettura della linea è avvenuta senza errori
            if line.is_ok() {
                // Ottiene il contenuto della linea
                let unwrapped_line = line.unwrap();

                // Converte la stringa Base64 in bytes
                let line_bytes = Base64::from_string(unwrapped_line);

                if let Ok(bytes) = line_bytes.to_bytes() {
                    // Cripta i bytes usando AES-CTR con nonce zero
                    if let Ok(encrypt_result) = bytes.nonce_ctr_encrypt(&key, vec![0; 8]) {
                        results.push(encrypt_result);
                    }
                }
            }
        }

        // Ottiene la lunghezza minima dei risultati crittografici
        let min = results.iter().map(|c| c.len()).min().unwrap();

        // Tronca tutti i risultati alla lunghezza minima
        for ciphertext in &mut results {
            ciphertext.truncate(min);
        }

        // Transpone i risultati crittografici per eseguire un attacco XOR ripetuto
        let mut transposed: Vec<Vec<u8>> = vec![vec![]; min];
        for string in &results {
            for i in 0..string.len() {
                let item = string[i];
                transposed[i].push(item);
            }
        }

        // Inizializza un vettore per la chiave di decifrazione.
        let mut k_vec: Vec<u8> = Vec::new();

        // Esegui l'attacco XOR ripetuto sui blocchi di dati.
        for bl in transposed {
            match bl.evaluate_frequency() {
                // Se la valutazione della frequenza restituisce una chiave possibile
                Some((_, key, _)) => k_vec.push(key),
                // Altrimenti, continua con il prossimo blocco
                None => {}
            }
        }

        // Combina tutti i risultati crittografici in un singolo vettore
        let flat_result: Vec<u8> = results.into_iter().flat_map(|f| f).collect();

        // Applica l'operazione XOR con la chiave di decifrazione trovata
        let res = flat_result.repeating_key_xor(&k_vec);

        // Converte i risultati decifrati in una stringa UTF-8
        let res_plain = String::from_utf8(res).unwrap();

        // Verifica che la stringa decifrata contenga la sottostringa desiderata
        assert!(res_plain.contains("I'm rated"));
    }
}
