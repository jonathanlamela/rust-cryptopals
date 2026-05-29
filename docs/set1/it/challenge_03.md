---
layout: default
title: "Sfida 3 — Cifrario XOR a carattere singolo"
parent: "Set 1 — IT"
nav_order: 3
permalink: /set1/it/challenge_03/
lang: it
---

# Sfida 3 — Cifrario XOR a carattere singolo

[← Sfida precedente](../challenge_02/) · [Sfida successiva →](../challenge_04/) · [🇬🇧 English](../../en/challenge_03/) · [Indice Set 1](../../)

---

## Teoria

Il cifrario XOR a carattere singolo è uno dei cifrari più deboli esistenti: un messaggio viene cifrato facendo XOR di ogni byte del plaintext con lo stesso byte di chiave. Pur avendo solo 256 possibili chiavi (valori da 0 a 255), questo schema è istruttivo perché la sua rottura introduce la tecnica dell'analisi delle frequenze, un approccio statistico usato per attaccare molti cifrari classici.

L'analisi delle frequenze si basa sull'osservazione che in qualsiasi lingua naturale alcune lettere compaiono con una frequenza molto più alta di altre. In inglese, la lettera `e` è la più frequente (circa 12,7%), seguita da `t`, `a`, `o`, `i`, `n`. Se un testo inglese viene cifrato con XOR a singolo byte, la distribuzione di frequenza delle lettere viene spostata ma non alterata nella forma: la lettera più comune nel ciphertext corrisponde probabilmente alla cifra di `e`, e così via.

Nel codice, invece di usare un'analisi statistica complessa, si adotta un approccio più robusto: per ogni chiave possibile (0–255), si calcola uno score che misura quanto il testo decifrato assomiglia all'inglese. Lo score è la somma dei logaritmi delle frequenze di ciascuna lettera alfabetica nel testo candidato. Si sceglie poi la chiave che massimizza questo score.

Questo approccio di forza bruta su uno spazio di chiavi piccolo (256 valori) è pratico e molto efficace. Rappresenta un caso speciale di frequency scoring applicato a cifrari monoalfabetici. La comprensione di questo attacco è fondamentale: il cifrario XOR a chiave ripetuta (sfida 5–6) può essere ricondotto a una serie di istanze di questo problema.

## Concetti chiave

- **Cifrario XOR a singolo byte:** ogni byte del plaintext viene XORato con lo stesso valore di chiave.
- **Analisi delle frequenze:** sfrutta la distribuzione non uniforme delle lettere nelle lingue naturali.
- **Score di frequenza:** misura la verosimiglianza di un testo in base alle frequenze attese delle lettere.
- **Brute force su 256 chiavi:** approccio pratico dato il piccolo spazio delle chiavi.
- **`LETTER_FREQUENCIES`:** array delle frequenze attese delle lettere inglesi usato per il scoring.
- **`evaluate_score`:** metodo che assegna uno score a un vettore di byte candidato.

## Spiegazione del codice

### Struttura generale

Il metodo principale è `evaluate_frequency` definito nel trait `CryptoVec` in `src/cryptovec/mod.rs`. Questo metodo prova tutte le 256 chiavi possibili, usa `xor_single` per decifrare e `evaluate_score` per valutare il risultato.

### Implementazione

Le frequenze delle lettere inglesi sono definite come costante:

```rust
pub const LETTER_FREQUENCIES: [f64; 26] = [
    8.34, 1.54, 2.73, 4.14, 12.60, 2.03, 1.92, 6.11, 6.71, 0.23, 0.87, 4.24, 2.53, 6.80, 7.70,
    1.66, 0.09, 5.68, 6.11, 9.37, 2.85, 1.06, 2.34, 0.20, 2.04, 0.06,
];
```

Le 26 voci corrispondono a `a–z` con le rispettive frequenze percentuali.

Il metodo `xor_single` applica XOR con un singolo byte:

```rust
fn xor_single(&self, k: u8) -> Vec<u8> {
    self.iter().map(|x| x ^ k).collect()
}
```

Semplice map: ogni byte `x` viene XORato con la chiave `k`.

Il metodo `evaluate_score` calcola la plausibilità del testo:

```rust
fn evaluate_score(&self) -> Option<f64> {
    if !self.iter().all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace()) {
        return None;
    }
    Some(self.iter().fold(0.0, |score, b| {
        if b.is_ascii_alphabetic() {
            let i = b.to_ascii_lowercase() - (b'a');
            score + LETTER_FREQUENCIES[usize::from(i)].log10()
        } else {
            score
        }
    }))
}
```

Prima filtra: se uno qualsiasi dei byte non è un carattere ASCII stampabile o whitespace, il testo non è plausibile e restituisce `None`. Poi calcola la somma dei `log10` delle frequenze di ogni lettera alfabetica. Il logaritmo trasforma le moltiplicazioni in somme (dato che le probabilità vengono moltiplicate, i log vengono sommati), rendendo il calcolo numericamente stabile.

Il metodo `evaluate_frequency` orchestra il tutto:

```rust
fn evaluate_frequency(&self) -> Option<(f64, u8, Vec<u8>)> {
    let mut xors_vector: Vec<(u8, Vec<u8>)> = Vec::new();
    for key in 0..=255 {
        xors_vector.push((key, self.xor_single(key)));
    }
    let filtered_map = xors_vector.iter().filter_map(|row| {
        row.1.evaluate_score().map(|score| (score, row.0, row.1.clone()))
    });
    let max_value = filtered_map.max_by(|(a, _, _), (b, _, _)| a.partial_cmp(b).unwrap());
    max_value
}
```

Costruisce un vettore di coppie `(chiave, plaintext_candidato)` per ogni chiave da 0 a 255. Poi usa `filter_map` per tenere solo i candidati che passano `evaluate_score` (testi ASCII plausibili) e ne calcola lo score. Infine `max_by` sceglie il candidato con lo score più alto. Il tipo di ritorno `Option<(f64, u8, Vec<u8>)>` è `(score, chiave, plaintext)`.

### Il test

```rust
#[test]
fn challenge_3() {
    let result = Hex::from_string(String::from(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
    ))
    .unwrap()
    .to_bytes()
    .unwrap()
    .evaluate_frequency()
    .unwrap();

    let stringa = String::from_utf8(result.2).unwrap();
    assert_eq!(stringa, "Cooking MC's like a pound of bacon");
}
```

Il test costruisce una catena: hex → byte → `evaluate_frequency()`. Il risultato è una tupla `(score, key, plaintext)`. `result.2` è il plaintext come `Vec<u8>`, convertito in `String` con `from_utf8`. Il valore atteso "Cooking MC's like a pound of bacon" è la canzone rap di riferimento delle Cryptopals.
