---
layout: default
title: "Sfida 2 — XOR a larghezza fissa"
parent: "Set 1 IT"
grand_parent: IT
nav_order: 2
permalink: /it/set1/challenge_02/
lang: it
---

# Sfida 2 — XOR a larghezza fissa

[← Sfida precedente](../challenge_01/) · [Sfida successiva →](../challenge_03/) · [🇬🇧 English](../../../en/set1/challenge_02/) · [Set 1](../) · [Home](../../)

---

## Teoria

L'operazione XOR (OR esclusivo) è il mattone fondamentale di quasi ogni primitiva crittografica moderna. XOR opera bit per bit su due valori: restituisce 1 se i due bit sono diversi, 0 se sono uguali. Le sue proprietà algebriche lo rendono ideale per la crittografia: è la propria operazione inversa (`A XOR B XOR B = A`), è commutativo (`A XOR B = B XOR A`) e associativo.

L'XOR a larghezza fissa consiste nell'applicare XOR byte per byte tra due array di uguale lunghezza. Questo è il caso più semplice: nessun riutilizzo della chiave, nessun padding. Si usa in CBC mode (XOR tra blocco cifrato precedente e blocco in chiaro), in One-Time Pad (quando la chiave è lunga quanto il messaggio e usata una volta sola) e come primitiva nei cifrari a flusso.

Il One-Time Pad, basato su XOR a larghezza fissa con chiave casuale e mai riutilizzata, è l'unico cifrario con sicurezza perfetta dimostrabile. Nella pratica, la difficoltà di distribuire chiavi della stessa lunghezza del messaggio lo rende impraticabile; tuttavia le proprietà matematiche di XOR permeano ogni sistema crittografico reale.

Capire XOR è anche essenziale per l'analisi crittografica: se si conosce il testo in chiaro e il corrispondente cifrato XOR, si può ricavare immediatamente la chiave (`chiave = cifrato XOR testo_in_chiaro`). Questo principio si chiama "known-plaintext attack" ed è la base della sfida 3 e delle successive.

## Concetti chiave

- **XOR bitwise**: operazione logica che produce 1 solo quando i bit di ingresso sono diversi.
- **Proprietà di autoinduzione XOR**: `A XOR A = 0` e `A XOR 0 = A`, fondamentali per la cifratura e decifratura.
- **Fixed-width XOR**: XOR applicato tra due vettori di uguale lunghezza, byte per byte.
- **One-Time Pad**: cifrario con sicurezza perfetta basato su XOR con chiave casuale usa-e-getta.
- **Known-plaintext attack**: attacco in cui conoscere la coppia (chiave, cifrato) permette di ricavare il testo o viceversa.
- **Trait `CryptoVec`**: trait Rust definito su `Vec<u8>` che raccoglie tutte le operazioni crittografiche sul vettore.

## Spiegazione del codice

### Struttura generale

La sfida utilizza `src/hex/mod.rs` per parsare le stringhe hex e `src/cryptovec/mod.rs` per eseguire lo XOR. Il metodo `xor` è definito nel trait `CryptoVec` implementato su `Vec<u8>`.

### Implementazione

Dopo aver creato i due oggetti `Hex` tramite `from_string`, il test chiama `to_bytes()` su entrambi per ottenere i vettori di byte grezzi:

```rust
let bytes1 = hex1.to_bytes().unwrap_or_else(|err| {
    panic!("Error converting from Hex to byte: {:?}", err);
});
let bytes2 = hex2.to_bytes().unwrap_or_else(|err| {
    panic!("Error converting from Hex to byte: {:?}", err);
});
```

Il metodo `to_bytes` è già stato analizzato nella sfida 1: itera sulla stringa hex a passi di 2 e converte ogni coppia con `u8::from_str_radix(..., 16)`.

L'operazione XOR è implementata nel metodo `xor` del trait `CryptoVec`:

```rust
fn xor(&self, v2: Vec<u8>) -> Vec<u8> {
    self.iter().zip(v2.iter()).map(|(&x, &y)| x ^ y).collect()
}
```

Il metodo usa `.zip()` per accoppiare elementi corrispondenti dei due iteratori e `.map()` per applicare l'operatore XOR `^` su ogni coppia. Il risultato viene raccolto in un nuovo `Vec<u8>`. Poiché `.zip()` si ferma al vettore più corto, i due input devono avere la stessa lunghezza per un XOR corretto.

Infine, il risultato viene reimpacchettato in un oggetto `Hex` usando `Hex::from_bytes`:

```rust
pub fn from_bytes(s: Vec<u8>) -> Result<Hex, JlmCryptoErrors> {
    let hex_string = s
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();
    Ok(Hex(hex_string))
}
```

Il formato `{:02x}` produce esattamente due caratteri hex minuscoli per byte, con zero iniziale se necessario.

### Il test

```rust
#[test]
fn challenge_2() {
    let hex1 = Hex::from_string(String::from("1c0111001f010100061a024b53535009181c")).unwrap();
    let hex2 = Hex::from_string(String::from("686974207468652062756c6c277320657965")).unwrap();
    let bytes1 = hex1.to_bytes().unwrap_or_else(|err| panic!("Error converting from Hex to byte: {:?}", err));
    let bytes2 = hex2.to_bytes().unwrap_or_else(|err| panic!("Error converting from Hex to byte: {:?}", err));
    let xor_result = bytes1.xor(bytes2);
    let expected_result = Hex::from_string(String::from("746865206b696420646f6e277420706c6179")).unwrap();
    let result = Hex::from_bytes(xor_result).unwrap();
    assert_eq!(result, expected_result);
}
```

Il test applica XOR a due array di byte di uguale lunghezza e verifica che il risultato corrisponda al valore hex atteso. I valori originali sono testi ASCII mascherati: "hit the bull's eye" XOR con l'altro produce "the kid don't play".
