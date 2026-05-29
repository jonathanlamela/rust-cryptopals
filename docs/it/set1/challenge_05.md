---
layout: default
title: "Sfida 5 — XOR a chiave ripetuta"
parent: "Set 1 IT"
grand_parent: IT
nav_order: 5
permalink: /it/set1/challenge_05/
lang: it
---

# Sfida 5 — XOR a chiave ripetuta

[← Sfida precedente](../challenge_04/) · [Sfida successiva →](../challenge_06/) · [🇬🇧 English](../../../en/set1/challenge_05/) · [Set 1](../) · [Home](../../)

---

## Teoria

Il cifrario di Vigenère, inventato nel XVI secolo, è il capostipite dei cifrari XOR a chiave ripetuta. L'idea è semplice: si usa una chiave di lunghezza fissa, molto più corta del messaggio, e la si ripete ciclicamente per coprire l'intero testo. Ogni byte del messaggio viene combinato in XOR con il byte corrispondente della chiave ripetuta.

Rispetto al cifrario XOR a byte singolo, questo approccio offre una sicurezza apparentemente maggiore: invece di 256 chiavi possibili, si deve affrontare uno spazio di chiavi esponenzialmente più grande. Tuttavia, il cifrario è ancora vulnerabile perché ogni posizione nella chiave viene usata per cifrare un sottoinsieme regolare dei caratteri del messaggio. Se la chiave è lunga K byte, allora i byte alle posizioni 0, K, 2K, ... sono tutti cifrati con lo stesso byte di chiave, i byte alle posizioni 1, K+1, 2K+1, ... con un secondo byte, e così via. Ogni sottoserie è quindi un semplice cifrario XOR a byte singolo, attaccabile con l'analisi della frequenza.

Questo cifrario è storicamente importante perché fu usato durante la Guerra Civile americana (con l'alfabeto Vigenère tradizionale invece di XOR) e durante la Prima e Seconda Guerra Mondiale in versioni più elaborate. La sua debolezza strutturale — la periodicità della chiave — fu formalizzata dal metodo di Kasiski nel 1863 e dall'indice di coincidenza di Friedman nel 1920.

La sfida 5 implementa la parte di cifratura; la sfida 6 implementa la decifrazione (l'attacco). Insieme, dimostrano il ciclo completo di attacco: costruire la primitiva vulnerabile e poi romperla.

## Concetti chiave

- **Cifrario di Vigenère**: cifrario polialfabetico che usa una chiave ripetuta per cifrare il messaggio.
- **Chiave ciclica**: chiave che viene ripetuta per coprire l'intera lunghezza del messaggio.
- **Periodicità**: proprietà della chiave ripetuta che rende il cifrario vulnerabile all'analisi della frequenza per colonne.
- **`repeating_key_xor`**: metodo del trait `CryptoVec` che implementa la cifratura XOR a chiave ripetuta.
- **Iteratore ciclico**: in Rust, il metodo `.cycle()` su un iteratore crea una sequenza infinita che ripete la sequenza originale.
- **Sicurezza computazionale**: la forza di un cifrario dipende non solo dalla lunghezza della chiave ma anche dalla struttura dell'algoritmo.

## Spiegazione del codice

### Struttura generale

La sfida usa `src/cryptovec/mod.rs`, specificamente il metodo `repeating_key_xor` del trait `CryptoVec`. Il test verifica che il cifrato prodotto corrisponda al valore atteso.

### Implementazione

Il metodo `repeating_key_xor` è elegante nella sua semplicità:

```rust
fn repeating_key_xor(&self, key: &[u8]) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    let mut key_iterator = key.into_iter().cycle();
    for i in self.into_iter() {
        result.push(key_iterator.next().unwrap() ^ i);
    }
    result
}
```

Il punto chiave è l'uso di `.cycle()` sull'iteratore della chiave. `cycle()` trasforma un iteratore finito in uno infinito che ripete la sequenza dall'inizio ogni volta che arriva alla fine. In questo modo, `key_iterator.next()` restituirà sempre un valore, anche se il messaggio è molto più lungo della chiave. Per ogni byte del messaggio (`i` nell'iterazione), si esegue XOR con il prossimo byte della chiave ciclica. Il risultato viene accumulato in un vettore.

Notare che il metodo prende `key: &[u8]` — un slice di byte — anziché un tipo generico. Questo permette di passare sia literal di byte (`b"ICE"`) che vettori (`&key_vec[..]`) senza allocazioni aggiuntive.

### Il test

```rust
#[test]
fn challenge_5() {
    let expected_result = Hex::from_string(String::from(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    )).unwrap();
    let clear_text_as_bytes =
        b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_vec();
    let clear_key_as_bytes = b"ICE";
    let result = clear_text_as_bytes.repeating_key_xor(clear_key_as_bytes);
    let hex_result = Hex::from_bytes(result).unwrap_or_else(|_| panic!("Hex from bytes failed"));
    assert_eq!(expected_result, hex_result);
}
```

Il test cifra un testo ASCII con la chiave "ICE" e confronta il risultato (convertito in hex) con il valore atteso. Il testo è un frammento di testo di "Play That Funky Music" di Vanilla Ice.
