use byteorder::{LittleEndian, WriteBytesExt};
use crypto::aessafe;
use crypto::symmetriccipher::BlockEncryptor;
use rand::RngCore;
use std::{fmt, str::FromStr};

use crate::enums::MODE;
use crate::structs::{
    Base64, CustomCrypter11, CustomCrypter12, CustomCrypter13, CustomCrypter14, CustomCrypter16,
    CustomCrypter17, Hex, OracleBase, SingleXorRow,
};
use crate::traits::{CryptoVec, CryptoVecChunks, Oracle, USizeCrypt};
use crate::{consts::LETTER_FREQUENCIES, enums::JlmCryptoErrors};

use openssl::symm::{Cipher, Crypter, Mode};
use rand::{thread_rng, Rng};
use std::str;

impl CryptoVecChunks for Vec<&[u8]> {
    fn contains_duplicates(&mut self) -> bool {
        //Lunghezza iniziale del vettore
        let len = self.len();

        //La funzione dedup funziona solo con vettori ordinati, quindi prima di chiamare la funzione dedup ordino il vettore
        self.sort();

        //Rimuovo i duplicati
        self.dedup();

        //Se la lunghezza iniziale del vettore è diversa dalla lunghezza senza duplicati allora il vettore conteneva duplicai
        len != self.len()
    }
}

impl Oracle for OracleBase {
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>, JlmCryptoErrors> {
        let key = &self.key;
        let prefix = &self.prefix;
        let suffix = &self.suffix;
        let mode: MODE = self.mode;
        let iv = &self.iv;

        //Vettore per il clear text modificato
        let mut cleartext = Vec::new();

        //Aggiungo il prefisso
        if let Some(prefix_bytes) = prefix {
            cleartext.extend_from_slice(prefix_bytes);
        }

        //Aggiungo il contenuto principale
        cleartext.extend_from_slice(u);

        //Aggiungo il suffisso
        if let Some(suffix_bytes) = suffix {
            cleartext.extend_from_slice(suffix_bytes);
        }

        //Crittografia del valore in CBC o EBC
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

impl USizeCrypt for usize {
    //Crea un blocco di bytes random partendo dal valore dell'istanza usize
    fn random_block(self) -> Vec<u8> {
        let mut key = vec![0u8; self];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut key);

        key
    }

    // Il primo valore indica il numero di blocchi 'chunks', il secondo quanti byte bisogna aggiungere al valore usize affinché sia multiplo di 16
    fn chunks_count(self) -> (usize, usize) {
        let q = (self + 16 - 1) / 16;
        let r = q * 16 - self;
        (q, r)
    }
}

impl CustomCrypter11 {
    pub fn new() -> Result<Self, JlmCryptoErrors> {
        let mut random_generator = thread_rng();

        //Crea di default un CIPHER in modalità ECB
        let mut cipher: Cipher = Cipher::aes_128_ecb();

        //Scegli casualmente una modalità tra ECB o CBC
        let mode: MODE = if random_generator.gen() {
            MODE::ECB
        } else {
            cipher = Cipher::aes_128_cbc();
            MODE::CBC
        };

        //Genera una chiave casuale della dimensione del blocco
        let key = cipher.block_size().random_block();

        //Genera prefisso e suffisso casuale di dimensione compresa tra 5 e 10
        let prefix: Vec<u8> = random_generator.gen_range(5..=10).random_block();
        let suffix: Vec<u8> = random_generator.gen_range(5..=10).random_block();

        //Se la modalità è CBC crea una chiave casuale da usare come IV
        let iv: Option<Vec<u8>> = if mode == MODE::CBC {
            Some(cipher.block_size().random_block())
        } else {
            None
        };

        Ok(CustomCrypter11 {
            base: OracleBase {
                key: key,
                prefix: Some(prefix),
                suffix: Some(suffix),
                mode: mode,
                iv: iv,
            },
        })
    }

    //Ottieni il valore della modalità usata per il cipher, restituisce true se è ECB
    pub fn is_ecb(&self) -> bool {
        return self.base.mode == MODE::ECB;
    }

    //Calcola se la chiave è stata criptata con ECB
    pub fn is_ecb_calculated(&self, vec: Vec<u8>) -> Result<bool, JlmCryptoErrors> {
        // Dividi la chiave in blocchi da 16, salta il primo e prendi il second e il terzo
        let blocks: Vec<&[u8]> = vec.chunks(16).skip(1).take(2).collect();

        //Verifica se sono uguali
        Ok(blocks[0] == blocks[1])
    }

    //Ottieni il valore della modalità usata per il cipher, restituisce true se è CBC
    pub fn is_cbc(&self) -> bool {
        return self.base.mode == MODE::CBC;
    }
}

impl CustomCrypter12 {
    //Dimensione del blocco
    const BLOCK_SIZE: usize = 16;

    pub fn new() -> Result<Self, JlmCryptoErrors> {
        // Crea una chiave casuale
        let key = Self::BLOCK_SIZE.random_block().to_vec();

        //Crea istanza della classe Base64 partendo da una stringa
        let base64_suffix = Base64::from_string(String::from("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"));
        let suffix: Vec<u8> = base64_suffix
            .to_bytes()
            .unwrap_or_else(|_| panic!("Invalid hex to bytes conversion"));

        // Crea una nuova istanza della classe CustomCrypter12
        Ok(CustomCrypter12 {
            base: OracleBase {
                key: key,
                prefix: None,
                suffix: Some(suffix),
                mode: MODE::ECB,
                iv: None,
            },
        })
    }

    //Controlla se il cypter attuale usa il padding
    fn uses_padding(&self) -> Result<bool, JlmCryptoErrors> {
        // STEP
        // Cifra una stringa con un byte
        // Cifra una stringa vuota
        // Calcola la differenza di lunghezza tra la prima e la seconda
        // Se la differenza è pari e il modulo restituisce 0 allora il crypter usa il padding
        Ok(
            (&self.base.encrypt(&[0]).unwrap().len() - &self.base.encrypt(&[]).unwrap().len())
                % Self::BLOCK_SIZE
                == 0,
        )
    }

    pub fn prefix_plus_suffix_length(&self) -> Result<usize, JlmCryptoErrors> {
        // Calcola la dimensione di una stringa cifrata vuota
        let initial = self.base.encrypt(&[]).unwrap().len();

        // Se non utilizza il padding, restituisci la dimensione della stringa cifrata iniziale come risultato
        if !&self.uses_padding().unwrap() {
            return Ok(initial);
        }

        // Crea un array di byte vuoto di dimensione 16 riempito con zeri
        let input = [0; Self::BLOCK_SIZE];
        if let Some(index) = (1..=Self::BLOCK_SIZE).find(|&i| {
            if let Ok(ciphertext) = self.base.encrypt(&input[..i]) {
                // Verifica se la lunghezza della stringa cifrata è diversa dalla lunghezza iniziale
                initial != ciphertext.len()
            } else {
                false
            }
        }) {
            // Restituisci la differenza tra la dimensione iniziale e l'indice trovato
            Ok(initial - index)
        } else {
            // Se non è stata trovata alcuna variazione di lunghezza dell'output, restituisci un errore corrispondente
            Err(JlmCryptoErrors::NoOutputLengthChange)
        }
    }

    // Trova il suffisso
    pub fn get_suffix(&self) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Calcola la lunghezza del prefisso.
        let prefix_len = self.prefix_length().unwrap();

        // Calcola la lunghezza del suffisso.
        let suffix_len = self.prefix_plus_suffix_length().unwrap() - prefix_len;

        // Ottieni il numero di blocchi completi nel prefisso e la lunghezza frazionaria rimanente.
        let (prefix_chunks_count, prefix_fill_len) = prefix_len.chunks_count();

        // Inizializza un vettore vuoto per memorizzare il suffisso.
        let mut suffix = Vec::new();

        // Prepara il vettore di input con zeri per trovare il suffisso.
        let mut input = vec![0; prefix_fill_len + Self::BLOCK_SIZE - 1];

        // Crea un vettore di cifre virtuali per diversi spostamenti a sinistra dell'input.
        let virtual_ciphertexts = (0..Self::BLOCK_SIZE)
            .map(|left_shift| self.base.encrypt(&input[left_shift..]))
            .collect::<Result<Vec<Vec<u8>>, JlmCryptoErrors>>()
            .unwrap();

        // Trova il suffisso tramite verifica forzata per ogni valore di byte.
        for i in 0..suffix_len {
            let block_index = prefix_chunks_count + i / Self::BLOCK_SIZE;
            let left_shift = i % Self::BLOCK_SIZE;

            // Prova ogni valore di byte (da 0 a 255) per trovare un byte di suffisso corrispondente.
            for u in 0u8..=255 {
                input.push(u);

                // Verifica se la cifra virtuale corrisponde alla cifra reale per il blocco corrispondente.
                if virtual_ciphertexts[left_shift]
                    [block_index * Self::BLOCK_SIZE..(block_index + 1) * Self::BLOCK_SIZE]
                    == self.base.encrypt(&input[left_shift..]).unwrap()
                        [block_index * Self::BLOCK_SIZE..(block_index + 1) * Self::BLOCK_SIZE]
                {
                    // Se viene trovata una corrispondenza, aggiungi il valore di byte al suffisso e interrompi il ciclo.
                    suffix.push(u);
                    break;
                }

                // Se non viene trovata alcuna corrispondenza, rimuovi l'ultimo byte dall'input e passa al valore di byte successivo.
                input.pop();
            }
        }
        Ok(suffix)
    }

    //Calcola la lunghezza del prefisso
    pub fn prefix_length(&self) -> Result<usize, JlmCryptoErrors> {
        // Ottieni la posizione di inizio del prefisso.
        let offset = self.prefix_blocks_count().unwrap() * Self::BLOCK_SIZE;

        // Crea un blocco costante riempito con il valore di byte 0.
        let constant_block = vec![0u8; 16];

        // Estrai il blocco crittografato iniziale da `offset` a `offset + Self::BLOCK_SIZE`.
        let initial =
            &self.base.encrypt(&constant_block).unwrap()[offset..(offset + Self::BLOCK_SIZE)];

        // Verifica ogni blocco crittografato successivo a partire da diverse posizioni di `constant_block`.
        for i in 0..Self::BLOCK_SIZE {
            // Cifra la porzione di `constant_block` che inizia dall'indice `i+1`.
            let cur = self.base.encrypt(&constant_block[i + 1..]).unwrap();

            // Se il blocco corrente non corrisponde al blocco iniziale, restituisci la lunghezza del prefisso (i).
            if cur.len() < offset + Self::BLOCK_SIZE
                || initial != &cur[offset..(offset + Self::BLOCK_SIZE)]
            {
                return Ok(i);
            }
        }

        // Se tutti i blocchi crittografati successivi corrispondono al blocco iniziale, restituisci la dimensione del blocco completo (Self::BLOCK_SIZE).
        Ok(Self::BLOCK_SIZE)
    }

    // Ottieni il numero di blocchi per il prefisso
    pub fn prefix_blocks_count(&self) -> Result<usize, JlmCryptoErrors> {
        // Cifra il byte `[0]` e il byte `[1]`
        let encrypted_0 = self.base.encrypt(&[0]).unwrap();
        let encrypted_1 = self.base.encrypt(&[1]).unwrap();

        // Dividi i byte cifrati in blocchi di dimensione `Self::BLOCK_SIZE`
        let chunks_0 = encrypted_0.chunks(Self::BLOCK_SIZE);
        let chunks_1 = encrypted_1.chunks(Self::BLOCK_SIZE);

        // Trova la posizione del primo blocco in cui i contenuti sono diversi
        if let Some(result) = chunks_0.zip(chunks_1).position(|(x, y)| x != y) {
            Ok(result)
        } else {
            Err(JlmCryptoErrors::NoDifferentBlocks)
        }
    }
}

impl CustomCrypter13 {
    pub fn new() -> Result<Self, JlmCryptoErrors> {
        let block_size: usize = 16;

        //Genera una chiave casuale di 16 byte
        let key = block_size.random_block();

        Ok({
            CustomCrypter13 {
                base: OracleBase {
                    key: key,
                    prefix: Some(b"email=".to_vec()),
                    suffix: Some(b"&uid=10&role=user".to_vec()),
                    iv: None,
                    mode: MODE::ECB,
                },
            }
        })
    }

    //Crea la stringa per il profilo partendo dall'email
    pub fn profile_for(&self, email: String) -> Result<String, JlmCryptoErrors> {
        //Controlla se il valore email contiene  il carattere '&'
        if email.contains("&") {
            return Err(JlmCryptoErrors::InvalidSet2Challenge13Chars);
        } else {
            let mut result_string = String::from("email=");

            result_string.push_str(&email);
            result_string.push_str("&uid=10&role=user");

            Ok(result_string)
        }
    }

    //Genera un email casuale che sia lunga 9 caratteri
    pub fn generate_test_email(&self) -> String {
        let mut rng = rand::thread_rng();

        //Username lungo 4 caratteri
        let username: String = (0..4).map(|_| rng.gen_range(b'a'..=b'z') as char).collect();

        //Dominio lungo 4 caratteri
        let domain: String = (0..4).map(|_| rng.gen_range(b'a'..=b'z') as char).collect();

        format!("{}@{}.com", username, domain)
    }
}

impl Oracle for CustomCrypter13 {
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Cifra l'array ricevuto in modalità ECB con la chiave generata in fase di istanza
        Ok(u.to_vec()
            .ssl_ecb_encrypt(&self.base.key, Some(true))
            .unwrap())
    }
}

impl CustomCrypter14 {
    pub const BLOCK_SIZE: usize = 16;

    //Lunghezza massima del prefisso
    pub const MAX_PREFIX_SIZE: usize = 10;

    pub fn new() -> Result<Self, JlmCryptoErrors> {
        let mut rng: rand::prelude::ThreadRng = rand::thread_rng();

        // Genera una chiave casuale
        let key: Vec<u8> = Self::BLOCK_SIZE.random_block().to_vec();

        // Genera una lunghezza casuale del prefisso
        let prefix_size: usize = rng.gen_range(1..=Self::MAX_PREFIX_SIZE);

        //Genera un prefisso casuale
        let prefix: Vec<u8> = prefix_size.random_block();

        //Inizializza il suffisso
        let base64_suffix = Base64::from_string(String::from("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"));

        // Trasforma il valore Base64 in bytes
        let suffix: Vec<u8> = base64_suffix
            .to_bytes()
            .unwrap_or_else(|_| panic!("Invalid hex to bytes conversion"));

        // Crea una nuova istanza della casse CustomCrypter14
        Ok(CustomCrypter14 {
            base: OracleBase {
                key: key,
                prefix: Some(prefix),
                suffix: Some(suffix),
                mode: MODE::ECB,
                iv: None,
            },
        })
    }

    // Ottieni il numero di blocchi per il prefisso
    pub fn prefix_blocks_count(&self) -> Result<usize, JlmCryptoErrors> {
        // Cifra il byte `[0]` e il byte `[1]`
        let encrypted_0: Vec<u8> = self.base.encrypt(&[0]).unwrap();
        let encrypted_1: Vec<u8> = self.base.encrypt(&[1]).unwrap();

        // Dividi i byte cifrati in blocchi della dimensione `Self::BLOCK_SIZE`
        let chunks_0: std::slice::Chunks<'_, u8> = encrypted_0.chunks(Self::BLOCK_SIZE);
        let chunks_1: std::slice::Chunks<'_, u8> = encrypted_1.chunks(Self::BLOCK_SIZE);

        // Trova la posizione del primo blocco in cui i contenuti sono diversi
        if let Some(result) = chunks_0.zip(chunks_1).position(|(x, y)| x != y) {
            Ok(result)
        } else {
            Err(JlmCryptoErrors::NoDifferentBlocks)
        }
    }

    //Controlla se il cypter attuale usa il padding
    fn uses_padding(&self) -> Result<bool, JlmCryptoErrors> {
        // STEP
        // Cifra una stringa con un byte
        // Cifra una stringa vuota
        // Calcola la differenza di lunghezza tra la prima e la seconda
        // Se la differenza è pari e il modulo restituisce 0 allora il crypter usa il padding
        Ok(
            (&self.base.encrypt(&[0]).unwrap().len() - &self.base.encrypt(&[]).unwrap().len())
                % Self::BLOCK_SIZE
                == 0,
        )
    }

    pub fn prefix_plus_suffix_length(&self) -> Result<usize, JlmCryptoErrors> {
        // Calcola la dimensione di una stringa cifrata vuota
        let initial = self.base.encrypt(&[]).unwrap().len();

        // Se non utilizza il padding, restituisci la dimensione della stringa cifrata iniziale come risultato
        if !&self.uses_padding().unwrap() {
            return Ok(initial);
        }

        // Crea un array di byte vuoto di dimensione 16 riempito con zeri
        let input = [0; Self::BLOCK_SIZE];
        if let Some(index) = (1..=Self::BLOCK_SIZE).find(|&i| {
            if let Ok(ciphertext) = self.base.encrypt(&input[..i]) {
                // Verifica se la lunghezza della stringa cifrata è diversa dalla lunghezza iniziale
                initial != ciphertext.len()
            } else {
                false
            }
        }) {
            // Restituisci la differenza tra la dimensione iniziale e l'indice trovato
            Ok(initial - index)
        } else {
            // Se non è stata trovata alcuna variazione di lunghezza dell'output, restituisci un errore corrispondente
            Err(JlmCryptoErrors::NoOutputLengthChange)
        }
    }

    pub fn get_suffix(&self) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Calcola la lunghezza del prefisso.
        let prefix_len = self.prefix_length().unwrap();

        // Calcola la lunghezza del suffisso.
        let suffix_len = self.prefix_plus_suffix_length().unwrap() - prefix_len;

        // Ottieni il numero di blocchi completi nel prefisso e la lunghezza frazionaria rimanente.
        let (prefix_ch_count, prefix_flen) = prefix_len.chunks_count();

        // Inizializza un vettore vuoto per memorizzare il suffisso.
        let mut suffix = Vec::new();

        // Prepara il vettore di input con zeri per trovare il suffisso.
        let mut input = vec![0; prefix_flen + Self::BLOCK_SIZE - 1];

        // Crea un vettore di cifre virtuali per diversi spostamenti a sinistra dell'input.
        let virtual_ciphertexts = (0..Self::BLOCK_SIZE)
            .map(|left_shift| self.base.encrypt(&input[left_shift..]))
            .collect::<Result<Vec<Vec<u8>>, JlmCryptoErrors>>()
            .unwrap();

        // Trova il suffisso verificando forzatamente ogni valore di byte.
        for i in 0..suffix_len {
            let block_index = prefix_ch_count + i / Self::BLOCK_SIZE;
            let left_shift = i % Self::BLOCK_SIZE;

            // Prova ogni valore di byte (da 0 a 255) per trovare un byte di suffisso corrispondente.
            for u in 0u8..=255 {
                input.push(u);

                // Verifica se la cifra virtuale corrisponde alla cifra reale per il blocco corrispondente.
                if virtual_ciphertexts[left_shift]
                    [block_index * Self::BLOCK_SIZE..(block_index + 1) * Self::BLOCK_SIZE]
                    == self.base.encrypt(&input[left_shift..]).unwrap()
                        [block_index * Self::BLOCK_SIZE..(block_index + 1) * Self::BLOCK_SIZE]
                {
                    // Se viene trovata una corrispondenza, aggiungi il valore di byte al suffisso e interrompi il ciclo.
                    suffix.push(u);
                    break;
                }

                // Se non viene trovata alcuna corrispondenza, rimuovi l'ultimo byte dall'input e continua al prossimo valore di byte.
                input.pop();
            }
        }
        Ok(suffix)
    }

    // Ottieni la lunghezza del prefisso
    pub fn prefix_length(&self) -> Result<usize, JlmCryptoErrors> {
        // Ottieni la posizione di inizio del prefisso
        let offset = self.prefix_blocks_count().unwrap() * Self::BLOCK_SIZE;

        // Crea un blocco costante riempito con il valore di byte 0.
        let constant_block = vec![0u8; Self::BLOCK_SIZE];

        // Estrai il blocco crittografato iniziale da `offset` a `offset + Self::BLOCK_SIZE`.
        let initial =
            &self.base.encrypt(&constant_block).unwrap()[offset..(offset + Self::BLOCK_SIZE)];

        // Verifica ogni blocco crittografato successivo a partire da diverse posizioni di `constant_block`.
        for i in 0..Self::BLOCK_SIZE {
            // Cifra la porzione di `constant_block` che inizia dall'indice `i+1`.
            let cur = self.base.encrypt(&constant_block[i + 1..]).unwrap();

            // Se il blocco corrente non corrisponde al blocco iniziale, restituisci la lunghezza del prefisso (i).
            if cur.len() < offset + Self::BLOCK_SIZE
                || initial != &cur[offset..(offset + Self::BLOCK_SIZE)]
            {
                return Ok(i);
            }
        }

        // Se tutti i blocchi crittografati successivi corrispondono al blocco iniziale, restituisci la dimensione del blocco completo (Self::BLOCK_SIZE).
        Ok(Self::BLOCK_SIZE)
    }
}

impl Oracle for CustomCrypter14 {
    //Cifra l'array ottenuto in input
    fn encrypt(&self, u: &[u8]) -> Result<Vec<u8>, JlmCryptoErrors> {
        self.base.encrypt(u)
    }
}

impl CustomCrypter16 {
    // Crea e restituisci un'istanza di questa struttura `CustomCrypter16`.
    pub fn new() -> CustomCrypter16 {
        return CustomCrypter16 {};
    }

    // Aggiunge quotatura alle occorrenze dei caratteri ';' e '=' nella stringa di input.
    pub fn quote_str(&self, input: &str) -> String {
        let mut quoted_input = str::replace(input, ";", "\";\"");
        quoted_input = str::replace(&quoted_input[..], "=", "\"=\"");

        quoted_input
    }

    // Rimuove la quotatura aggiunta dalla funzione `quote_str`.
    pub fn unquote_str(&self, input: &str) -> String {
        let mut quoted_input = str::replace(input, "\";\"", ";");
        quoted_input = str::replace(&quoted_input[..], "\"=\"", "=");

        quoted_input
    }

    // Prepara una stringa per la cifratura, aggiungendo prefissi e suffissi specifici.
    pub fn prepare_string(&self, input: &str) -> Vec<u8> {
        let input_quoted: String = self.quote_str(input);

        let input_bytes = input_quoted.as_bytes();
        let prepend_bytes = b"comment1=cooking%20MCs;userdata=";
        let append_bytes = b";comment2=%20like%20a%20pound%20of%20bacon";

        let mut plaintext = Vec::new();

        // Aggiungi i byte di prefisso, i byte di input quotato e i byte di suffisso al vettore `plaintext`.
        plaintext.extend_from_slice(&prepend_bytes[..]);
        plaintext.extend_from_slice(&input_bytes[..]);
        plaintext.extend_from_slice(&append_bytes[..]);

        plaintext
    }
}

impl CustomCrypter17 {
    pub const BLOCK_SIZE: usize = 16;

    //Lunghezza massima del prefisso
    pub const MAX_PREFIX_SIZE: usize = 20;

    const TOKENS: [&'static str; 10] = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];

    pub fn new() -> Result<Self, JlmCryptoErrors> {
        // Genera una chiave casuale
        let key = Self::BLOCK_SIZE.random_block().to_vec();

        // Genere un IV casuale
        let iv = Self::BLOCK_SIZE.random_block().to_vec();

        let mut rng = rand::thread_rng();
        let i_index = rng.gen_range(0..Self::TOKENS.len());

        let token_extracted = Self::TOKENS[i_index].to_string();

        // Crea una nuova istanza della casse CustomCrypter14
        Ok(CustomCrypter17 {
            picked_token: token_extracted,
            key: key,
            iv: iv,
        })
    }

    pub fn get_picked_token(&self) -> Base64 {
        Base64::from_string(self.picked_token.clone())
    }

    pub fn get_all_tokens(&self) -> [&str; 10] {
        Self::TOKENS
    }
}

// Definizione di una struttura `Hex` che rappresenta una sequenza di byte in formato esadecimale.
impl Hex {
    // Costruttore per creare un nuovo oggetto `Hex` da una stringa esadecimale.
    pub fn new(s: String) -> Result<Hex, JlmCryptoErrors> {
        // Decodifica la stringa esadecimale in bytes.
        match hex::decode(s.clone()) {
            // Se la decodifica va a buon fine, restituisci un oggetto `Hex` contenente la stringa.
            Ok(_) => Ok(Hex(s)),
            // Se c'è un errore durante la decodifica, restituisci un errore di tipo `JlmCryptoErrors`.
            Err(_) => Err(JlmCryptoErrors::InvalidHEXValue),
        }
    }

    // Costruttore che crea un oggetto `Hex` da una stringa.
    pub fn from_string(s: String) -> Result<Hex, JlmCryptoErrors> {
        // Chiama il costruttore `new` per creare un oggetto `Hex` dalla stringa fornita.
        Hex::new(s.to_string())
    }

    // Costruttore che crea un oggetto `Hex` direttamente da una stringa esadecimale.
    pub fn from_hex_string(s: String) -> Result<Hex, JlmCryptoErrors> {
        // Crea un oggetto `Hex` contenente la stringa esadecimale fornita.
        Ok(Hex(s))
    }

    // Costruttore che crea un oggetto `Hex` da un vettore di bytes.
    pub fn from_bytes(s: Vec<u8>) -> Result<Hex, JlmCryptoErrors> {
        // Codifica i bytes in formato esadecimale e tenta di parsare il risultato come un oggetto `Hex`.
        match hex::encode(s).parse::<Hex>() {
            // Se il parsing va a buon fine, restituisci l'oggetto `Hex` creato.
            Ok(hex_value) => Ok(hex_value),
            // Se c'è un errore durante il parsing, restituisci un errore di tipo `JlmCryptoErrors`.
            Err(_) => Err(JlmCryptoErrors::InvalidBytesToHEX),
        }
    }

    // Metodo che restituisce la lunghezza della sequenza esadecimale.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    // Metodo che converte l'oggetto `Hex` in un vettore di bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Decodifica la stringa esadecimale in bytes.
        match hex::decode(&self.0) {
            // Se la decodifica va a buon fine, restituisci i bytes ottenuti.
            Ok(v) => Ok(v),
            // Se c'è un errore durante la decodifica, restituisci un errore di tipo `JlmCryptoErrors`.
            Err(_) => Err(JlmCryptoErrors::InvalidHEXToBytesConversion),
        }
    }

    // Metodo che converte l'oggetto `Hex` in un oggetto `Base64`.
    pub fn to_b64(&self) -> Result<Base64, JlmCryptoErrors> {
        // Converte l'oggetto `Hex` in un vettore di bytes e quindi in un oggetto `Base64`.
        match &self.to_bytes() {
            Ok(v) => Ok(Base64::from_string(base64::encode(v))),
            // Se c'è un errore nella conversione, restituisci un errore di tipo `JlmCryptoErrors`.
            Err(_) => Err(JlmCryptoErrors::InvalidHEXToBase64Conversion),
        }
    }
}

// Implementazione del trait `FromStr` per la struttura `Hex`.
impl FromStr for Hex {
    type Err = JlmCryptoErrors;

    // Metodo che converte una stringa in un oggetto `Hex`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Chiama il metodo `from_hex_string` della struttura `Hex` per creare un oggetto `Hex` dalla stringa.
        Hex::from_hex_string(s.to_string())
    }
}

// Definizione della struttura `Base64`.
impl Base64 {
    // Costruttore per creare un nuovo oggetto `Base64` da una stringa.
    pub fn new(s: String) -> Base64 {
        Base64(s)
    }

    // Metodo che crea un oggetto `Base64` da una stringa.
    pub fn from_string(s: String) -> Base64 {
        Base64(s)
    }

    // Metodo che crea un oggetto `Base64` da un vettore di bytes.
    pub fn from_bytes(s: &[u8]) -> Base64 {
        Base64(base64::encode(s))
    }

    // Metodo che converte l'oggetto `Base64` in un vettore di bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Decodifica la stringa Base64 in bytes.
        match base64::decode(&self.0) {
            // Se la decodifica va a buon fine, restituisci i bytes ottenuti.
            Ok(r) => Ok(r),
            // Se c'è un errore durante la decodifica, restituisci un errore di tipo `JlmCryptoErrors`.
            Err(_) => Err(JlmCryptoErrors::InvalidBase64ToBytes),
        }
    }
}

// Implementazione del trait `PartialEq` per la struttura `Base64`.
impl PartialEq for Base64 {
    // Metodo che confronta due oggetti `Base64` per uguaglianza.
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

// Implementazione del trait `PartialEq` per la struttura `Hex`.
impl PartialEq for Hex {
    // Metodo che confronta due oggetti `Hex` per uguaglianza.
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

// Implementazione del trait `Display` per la struttura `Hex`.
impl<'a> fmt::Display for Hex {
    // Metodo che formatta l'oggetto `Hex` per la visualizzazione.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Implementazione del trait `Debug` per la struttura `Hex`.
impl<'a> fmt::Debug for Hex {
    // Metodo che formatta l'oggetto `Hex` per la visualizzazione in modalità di debug.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Formatta la stringa esadecimale in un formato leggibile, separando le coppie di cifre con uno spazio.
        let hex_string = self.0.to_lowercase();
        let spaced_hex_string = hex_string
            .chars()
            .enumerate()
            .flat_map(|(i, c)| {
                if i > 0 && i % 2 == 0 {
                    Some(' ') // Inserisci uno spazio dopo ogni coppia di cifre
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

// Implementazione del trait `Display` per la struttura `Base64`.
impl<'a> fmt::Display for Base64 {
    // Metodo che formatta l'oggetto `Base64` per la visualizzazione.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Implementazione del trait `Debug` per la struttura `Base64`.
impl<'a> fmt::Debug for Base64 {
    // Metodo che formatta l'oggetto `Base64` per la visualizzazione in modalità di debug.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Base64({})", self.0)
    }
}

impl CryptoVec for Vec<u8> {
    // Funzione per aggiungere il padding PKCS7 ad un vettore di byte.
    fn pad(&mut self, k: u8) -> Result<bool, JlmCryptoErrors> {
        // Verifica se il valore di padding k è minore di 2
        if k < 2 {
            // Se k è minore di 2, restituisci un errore che indica un fallimento del padding PKCS7
            return Err(JlmCryptoErrors::PKCS7PaddingFailed);
        }

        // Calcola il valore di padding p necessario per raggiungere un multiplo di k
        let p = k - (self.len() % k as usize) as u8;

        // Aggiungi il valore di padding p al vettore p volte
        for _ in 0..p {
            self.push(p);
        }

        Ok(true)
    }

    // Funzione per rimuovere il padding PKCS7 da un vettore di byte.
    fn unpad(&mut self, k: u8) -> Result<bool, JlmCryptoErrors> {
        // Verifica se il padding è valido utilizzando la funzione check_padding_valid
        if !self.check_padding_valid(k)? {
            // Se il padding non è valido, restituisci un errore che indica un padding non valido
            return Err(JlmCryptoErrors::InvalidPadding);
        }

        // Calcola la nuova lunghezza del vettore dopo aver rimosso il padding
        let len_new = self.len() - self[self.len() - 1] as usize;

        // Tronca il vettore alla nuova lunghezza per rimuovere il padding
        self.truncate(len_new);

        // Restituisci Ok(true) per indicare la rimozione del padding avvenuta con successo
        Ok(true)
    }

    // Funzione per verificare se il padding PKCS7 in un vettore di byte è valido.
    fn check_padding_valid(&self, k: u8) -> Result<bool, JlmCryptoErrors> {
        // Verifica se il valore di padding k è minore di 2
        if k < 2 {
            // Se k è minore di 2, restituisci un errore che indica un padding non valido
            return Err(JlmCryptoErrors::InvalidPadding);
        }

        // Verifica se il vettore è vuoto o non è un multiplo di k
        if self.is_empty() || self.len() % k as usize != 0 {
            // Se il vettore è vuoto o non è un multiplo di k, restituisci false (padding non valido)
            return Err(JlmCryptoErrors::InvalidPadding);
        }

        // Ottieni l'ultimo byte del vettore, che indica la quantità di padding
        let padding = self[self.len() - 1];

        // Verifica se il valore di padding è all'interno dell'intervallo previsto [1, k]
        if !(1 <= padding && padding <= k) {
            // Se il valore di padding non è all'interno dell'intervallo previsto, restituisci false (padding non valido)
            return Err(JlmCryptoErrors::InvalidPadding);
        }

        // Verifica se i byte di padding sono consistenti con il valore atteso
        // Confronta gli ultimi `padding` byte con il valore di padding
        let is_valid = self[self.len() - padding as usize..]
            .iter()
            .all(|&b| b == padding);

        // Restituisci se il padding è valido
        if is_valid {
            return Ok(true);
        } else {
            return Err(JlmCryptoErrors::InvalidPadding);
        }
    }

    // Funzione per trovare la dimensione della chiave (ks) più probabile.
    fn find_ks(&self) -> Result<usize, JlmCryptoErrors> {
        // Inizializza una variabile per la dimensione della chiave (ks) e una per la distanza minima.
        let mut out_keysize: Option<usize> = None;
        let mut out_dist = f64::INFINITY;

        // Itera attraverso possibili dimensioni della chiave da 2 a 39 (incluso).
        for ks in 2..40 {
            // Dividi i dati in blocchi di dimensione ks.
            let chunks: Vec<&[u8]> = self.chunks(ks).collect();

            // Estrai i primi quattro blocchi per calcolare le distanze tra di essi.
            let block1 = chunks.get(0).unwrap().to_vec();
            let block2 = chunks.get(1).unwrap().to_vec();
            let block3 = chunks.get(2).unwrap().to_vec();
            let block4 = chunks.get(3).unwrap().to_vec();

            // Calcola la distanza normalizzata tra tutti i possibili coppie di blocchi.
            let ds = (&block1.compute_distance_bytes(&block2)
                + &block1.compute_distance_bytes(&block3)
                + &block1.compute_distance_bytes(&block4)
                + &block2.compute_distance_bytes(&block3)
                + &block2.compute_distance_bytes(&block4)
                + &block3.compute_distance_bytes(&block4)) as f64
                / (6.0 * ks as f64);

            // Aggiorna la dimensione della chiave (ks) e la distanza minima se necessario.
            if out_keysize.is_some() {
                if ds < out_dist {
                    out_dist = ds;
                    out_keysize = Some(ks);
                }
            } else {
                out_dist = ds;
                out_keysize = Some(ks);
            }
        }

        // Restituisci la dimensione della chiave (ks) più probabile.
        if let Some(ks) = out_keysize {
            Ok(ks)
        } else {
            // Se non è possibile trovare una dimensione della chiave valida, restituisci un errore.
            Err(JlmCryptoErrors::UnableFindKs)
        }
    }

    // Funzione per eseguire un'operazione XOR tra due vettori di byte.
    fn xor(&self, v2: Vec<u8>) -> Vec<u8> {
        self.iter().zip(v2.iter()).map(|(&x, &y)| x ^ y).collect()
    }

    fn mutable_xor(&mut self, v2: Vec<u8>) {
        for chunk in self.chunks_mut(v2.len()) {
            let len = chunk.len();
            for (c, &d) in chunk.iter_mut().zip(v2[..len].iter()) {
                *c ^= d;
            }
        }
    }

    // Funzione per calcolare la distanza di Hamming tra due vettori di byte.
    fn compute_distance_bytes(&self, bytes_b: &Vec<u8>) -> u32 {
        self.iter()
            .zip(bytes_b.iter())
            .fold(0, |acc, (&byte_a, &byte_b)| {
                acc + (byte_a ^ byte_b).count_ones()
            })
    }

    // Funzione per valutare il punteggio di un vettore di byte in base alle frequenze delle lettere.
    fn evaluate_score(&self) -> Option<f64> {
        // Verifica se tutti i caratteri della stringa sono caratteri ASCII stampabili o spazi bianchi.
        if !self
            .iter()
            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        {
            return None;
        }

        // Calcola il punteggio valutando le frequenze delle lettere nei caratteri alfabeticamente ASCII.
        Some(self.iter().fold(0.0, |score, b| {
            if b.is_ascii_alphabetic() {
                let i = b.to_ascii_lowercase() - (b'a');
                score + LETTER_FREQUENCIES[usize::from(i)].log10()
            } else {
                score
            }
        }))
    }

    // Funzione per eseguire un'operazione XOR tra un vettore di byte e una singola chiave.
    fn xor_single(&self, k: u8) -> Vec<u8> {
        self.iter().map(|x| x ^ k).collect()
    }

    // Funzione per eseguire un attacco XOR ripetuto per rompere la chiave di cifratura.
    fn repeating_xor_attack(&self) -> Result<String, JlmCryptoErrors> {
        // Trova la dimensione della chiave (ks) più probabile.
        let ks = self.find_ks().unwrap();

        // Inizializza una matrice transposta per i blocchi di dati.
        let mut transposed: Vec<Vec<u8>> = vec![vec![]; ks];

        // Estrai i blocchi di dati dalla dimensione della chiave (ks).
        for slice in self.chunks(ks) {
            let s_len = slice.len();
            if s_len == ks {
                for i in 0..s_len {
                    transposed[i].push(slice[i]);
                }
            }
        }

        // Inizializza un vettore per la chiave di decifrazione.
        let mut k_vec: Vec<u8> = Vec::new();

        // Esegui l'attacco XOR ripetuto sui blocchi di dati.
        for bl in transposed {
            match bl.evaluate_frequency() {
                Some((_, key, _)) => k_vec.push(key),
                None => {}
            }
        }

        // Se la chiave è stata determinata, decifra il testo cifrato e restituisci il risultato.
        if k_vec.len() > 0 {
            let repeating_key_xor_result = self.repeating_key_xor(&k_vec);

            match &str::from_utf8(&repeating_key_xor_result) {
                Ok(v) => Ok(v.to_string()),
                Err(_) => Err(JlmCryptoErrors::BreakRepeatingKeyAttackFailed),
            }
        } else {
            return Err(JlmCryptoErrors::BreakRepeatingKeyAttackFailed);
        }
    }

    fn repeating_key_xor(&self, key: &[u8]) -> Vec<u8> {
        // Creo un vettore vuoto per immagazzinare il risultato
        let mut result: Vec<u8> = Vec::new();

        // Creo un iteratore ciclico per la chiave fornita
        let mut key_iterator = key.into_iter().cycle();

        // Itero attraverso gli elementi del dato di input
        for i in self.into_iter() {
            // Eseguo un'operazione di XOR tra l'elemento del dato e il prossimo elemento della chiave
            // e aggiungo il risultato al vettore di risultati
            result.push(key_iterator.next().unwrap() ^ i);
        }

        // Restituisco il vettore risultante
        result
    }

    fn evaluate_frequency(&self) -> Option<(f64, u8, Vec<u8>)> {
        // Creo un vettore per memorizzare i risultati di XOR singoli
        let mut xors_vector: Vec<SingleXorRow> = Vec::new();

        // Itero attraverso tutti i possibili valori di chiave (da 0 a 255)
        for key in 0..=255 {
            // Calcolo il risultato XOR singolo per la chiave corrente
            let item = SingleXorRow {
                key,
                xor_value: self.xor_single(key),
            };
            // Aggiungo il risultato XOR singolo al vettore
            xors_vector.push(item);
        }

        // Filtraggio dei risultati con punteggio positivo
        let filtered_map = xors_vector.iter().filter_map(|row| {
            row.xor_value
                .evaluate_score()
                .map(|score| (score, row.key, row.xor_value.clone()))
        });

        // Estraggo il valore XOR con il punteggio più alto
        let max_value = filtered_map.max_by(|(a, _, _), (b, _, _)| a.partial_cmp(b).unwrap());

        // Restituisco il risultato con il punteggio più alto (se presente)
        max_value
    }

    fn legacy_cbc_decrypt(&self, key: &[u8], iv: &mut [u8]) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Definisco la dimensione di un blocco (tipicamente 16 byte)
        let block_size = 16;

        // Creo un vettore per contenere il testo in chiaro decrittografato
        let mut plaintext = Vec::new();

        // Creo un vettore per mantenere il blocco cifrato precedente (inizializzato con l'IV)
        let mut prev_ciphertext_block = iv.to_vec();

        // Itero attraverso i dati cifrati in blocchi della dimensione del blocco
        for chunk in self.chunks(block_size) {
            // Decifro il blocco corrente utilizzando l'algoritmo di cifratura a blocchi (presumibilmente AES-ECB)
            let decrypted_block = chunk.to_vec().ssl_ecb_decrypt(key, Some(false)).unwrap();

            // Effettuo un'operazione di XOR tra il blocco decifrato corrente e il blocco cifrato precedente
            let mut decrypted_block_xor = Vec::with_capacity(block_size);
            for j in 0..block_size {
                // Eseguo XOR tra i byte del blocco corrente e quelli del blocco cifrato precedente
                decrypted_block_xor.push(decrypted_block[j] ^ prev_ciphertext_block[j]);
            }

            // Aggiorno il blocco cifrato precedente con il blocco corrente
            prev_ciphertext_block = chunk.to_vec();

            // Aggiungo il risultato dell'operazione XOR al vettore del testo in chiaro
            plaintext.extend_from_slice(&decrypted_block_xor);
        }

        // Rimuovo il padding dall'output del decrittografia
        let _ = plaintext.unpad(16);

        // Restituisco il testo in chiaro decrittografato
        Ok(plaintext)
    }

    // Esegue la cifratura utilizzando la modalità di crittografia CBC (Cipher Block Chaining).
    fn ssl_cbc_encrypt(
        &self,
        key: &[u8],        // Chiave di crittografia
        iv: &[u8],         // Vettore di inizializzazione (IV)
        pad: Option<bool>, // Opzione per il padding (opzionale, default: true)
    ) -> Result<Vec<u8>, JlmCryptoErrors> {
        let cipher = Cipher::aes_128_cbc(); // Utilizza l'algoritmo AES con modalità CBC

        let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv)).unwrap();
        crypter.pad(pad.unwrap_or(true)); // Abilita il padding, se specificato

        // Crea un vettore per immagazzinare il testo cifrato
        let mut encrypted = vec![0; &self.len() + cipher.block_size()];

        // Esegue la cifratura
        let count = crypter.update(&self, &mut encrypted).unwrap();

        match crypter.finalize(&mut encrypted[count..]) {
            Ok(final_count_value) => {
                // Tronca il vettore del testo cifrato alla lunghezza effettiva
                encrypted.truncate(count + final_count_value);

                // Restituisce il testo cifrato risultante
                Ok(encrypted)
            }
            Err(_) => Err(JlmCryptoErrors::InvalidPadding),
        }
    }

    // Esegue la cifratura utilizzando la modalità di crittografia ECB (Electronic Codebook).
    fn ssl_ecb_encrypt(
        &self,
        key: &[u8],        // Chiave di crittografia
        pad: Option<bool>, // Opzione per il padding (opzionale, default: true)
    ) -> Result<Vec<u8>, JlmCryptoErrors> {
        let cipher = Cipher::aes_128_ecb(); // Utilizza l'algoritmo AES con modalità ECB
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, None).unwrap();
        crypter.pad(pad.unwrap_or(true)); // Abilita il padding, se specificato

        // Crea un vettore per immagazzinare il testo cifrato
        let mut encrypted = vec![0; &self.len() + cipher.block_size()];

        // Esegue la cifratura
        let count = crypter.update(&self, &mut encrypted).unwrap();
        let final_count = crypter.finalize(&mut encrypted[count..]).unwrap();

        // Tronca il vettore del testo cifrato alla lunghezza effettiva
        encrypted.truncate(count + final_count);

        // Restituisce il testo cifrato risultante
        Ok(encrypted)
    }

    // Esegue la decifratura utilizzando la modalità di crittografia ECB (Electronic Codebook).
    fn ssl_ecb_decrypt(
        &self,
        key: &[u8],        // Chiave di crittografia
        pad: Option<bool>, // Opzione per il padding (opzionale, default: true)
    ) -> Result<Vec<u8>, JlmCryptoErrors> {
        let cipher = Cipher::aes_128_ecb(); // Utilizza l'algoritmo AES con modalità ECB
        let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, None).unwrap();
        crypter.pad(pad.unwrap_or(true)); // Abilita il padding, se specificato

        // Crea un vettore per immagazzinare il testo decifrato
        let mut decrypted = vec![0; &self.len() + cipher.block_size()];

        // Esegue la decifratura
        let count = crypter.update(&self, &mut decrypted).unwrap();

        match crypter.finalize(&mut decrypted[count..]) {
            Ok(final_count_value) => {
                // Tronca il vettore del testo decifrato alla lunghezza effettiva
                decrypted.truncate(count + final_count_value);

                // Restituisce il testo decifrato risultante
                Ok(decrypted)
            }
            Err(_) => Err(JlmCryptoErrors::InvalidPadding),
        }
    }

    // Esegue la decifratura utilizzando la modalità di crittografia CBC (Cipher Block Chaining).
    fn ssl_cbc_decrypt(
        &self,
        key: &[u8],        // Chiave di crittografia
        iv: &[u8],         // Vettore di inizializzazione (IV)
        pad: Option<bool>, // Opzione per il padding (opzionale, default: true)
    ) -> Result<Vec<u8>, JlmCryptoErrors> {
        let cipher = Cipher::aes_128_cbc(); // Utilizza l'algoritmo AES con modalità CBC
        let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv)).unwrap();
        crypter.pad(pad.unwrap_or(true)); // Abilita il padding, se specificato

        // Crea un vettore per immagazzinare il testo decifrato
        let mut decrypted = vec![0; &self.len() + cipher.block_size()];

        // Esegue la decifratura
        match crypter.update(&self, &mut decrypted) {
            Ok(count) => {
                match crypter.finalize(&mut decrypted[count..]) {
                    Ok(final_count_value) => {
                        // Tronca il vettore del testo decifrato alla lunghezza effettiva
                        decrypted.truncate(count + final_count_value);

                        // Restituisce il testo decifrato risultante
                        Ok(decrypted)
                    }
                    Err(_) => Err(JlmCryptoErrors::InvalidPadding),
                }
            }
            Err(_) => Err(JlmCryptoErrors::InvalidPadding),
        }
    }

    fn ssl_ctr_encrypt(&self, key: &[u8], pad: Option<bool>) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Inizializza il vettore che conterrà il testo cifrato.
        let mut ciphertext = Vec::new();
        // Inizializza il vettore che rappresenta lo stream di chiavi per la cifratura.
        let mut keystream = vec![0; 16];

        /*
         * Il keystream è una sequenza che viene utilizzata per generare un
         * primo blocco cifrato. Questo primo blocco viene poi usato per
         * effettuare uno xor tra un blocco del testo in chiaro e
         * un blocco del keystream.
         * Per ogni blocco il valore "contatore" del primo blocco
         * del keystream viene incrementato.
         */

        // Itera sui blocchi di 16 byte del messaggio in input.
        for b in self.chunks(16) {
            // Ottiene lo stream di chiavi cifrando il keystream con la chiave usando la modalità ECB.
            let to_xor = keystream.to_vec().ssl_ecb_encrypt(&key, pad);

            // Esegue l'operazione XOR tra il blocco corrente e lo stream di chiavi ottenuto.
            ciphertext.extend_from_slice(&b.to_vec().xor(to_xor.unwrap()));

            // Aggiorna il keystream incrementando il contatore.
            for b in keystream[16 / 2..].iter_mut() {
                *b += 1;
                if *b != 0 {
                    break;
                }
            }
        }

        // Restituisce il testo cifrato.
        Ok(ciphertext)
    }

    fn ssl_ctr_decrypt(&self, key: &[u8], pad: Option<bool>) -> Result<Vec<u8>, JlmCryptoErrors> {
        self.ssl_ctr_encrypt(key, pad)
    }

    fn nonce_ctr_encrypt(&self, key: &[u8], nonce: Vec<u8>) -> Result<Vec<u8>, JlmCryptoErrors> {
        // Ottieni la lunghezza del blocco dalla lunghezza della chiave
        let block_size = key.len();

        // Inizializza un encryptor AES con chiave 128-bit
        let encryptor = aessafe::AesSafe128Encryptor::new(&key);

        // Inizializza un vettore per contenere il risultato crittografico
        let mut result: Vec<u8> = Vec::new();

        // Divide i dati in blocchi della dimensione del blocco AES
        let i_blocks = &self.chunks(block_size);

        // Inizializza un vettore per contenere lo stream di chiavi
        let mut keystream = vec![0; block_size];

        // Itera attraverso i blocchi di dati e crittografa ciascun blocco
        for (count, block) in i_blocks.clone().enumerate() {
            // Inizializza un vettore per contenere il nonce e il contatore
            let mut nonce_count = Vec::new();
            nonce_count.extend_from_slice(&nonce[..]);

            // Controlla se la scrittura del contatore nel nonce_count è riuscita
            if let Ok(_) = nonce_count.write_u64::<LittleEndian>(count as u64) {
                // Cripta il nonce_count per ottenere lo stream di chiavi
                encryptor.encrypt_block(&nonce_count[..], &mut keystream[..]);

                // Esegue l'operazione XOR tra lo stream di chiavi e il blocco corrente
                let b1 = &keystream[0..block.len()];
                let b2 = block;
                let x_result = b1.to_vec().xor(b2.to_vec());

                // Aggiungi il risultato crittografico al vettore di risultato
                result.extend_from_slice(&x_result[..]);
            } else {
                // Se la scrittura del contatore fallisce, restituisci un errore
                return Err(JlmCryptoErrors::FailedAesCtrEncrypt);
            }
        }

        // Restituisci il risultato crittografico
        Ok(result)
    }
}
