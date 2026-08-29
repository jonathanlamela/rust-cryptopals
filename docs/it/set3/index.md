---
layout: default
title: "Set 3 IT"
parent: IT
nav_order: 3
has_children: true
permalink: /it/set3/
---

# Set 3 — CTR, padding oracle e attacchi statistici

Il terzo set introduce la modalità CTR (Counter) di AES, un cifrario a flusso costruito sopra AES-ECB, e il celebre attacco "CBC padding oracle". Le prime sfide mostrano come cifrature CTR con nonce fisso siano vulnerabili agli stessi attacchi statistici usati contro XOR a chiave ripetuta. La seconda metà implementa il RNG MT19937 Mersenne Twister e ne dimostra l'insicurezza: recupero del seed basato sul tempo, clonazione dello stato dall'output e rottura di uno stream cipher basato su MT19937.

| # | Titolo | IT | EN |
|---|--------|----|-----|
| 17 | CBC padding oracle | [it](challenge_17/) | [en](../../en/set3/challenge_17/) |
| 18 | Implementa AES CTR | [it](challenge_18/) | [en](../../en/set3/challenge_18/) |
| 19 | Rompi CTR a nonce fisso (sostituzione) | [it](challenge_19/) | [en](../../en/set3/challenge_19/) |
| 20 | Rompi CTR a nonce fisso (statisticamente) | [it](challenge_20/) | [en](../../en/set3/challenge_20/) |
| 21 | Implementa il RNG MT19937 Mersenne Twister | [it](challenge_21/) | [en](../../en/set3/challenge_21/) |
| 22 | Cracca il seed di MT19937 | [it](challenge_22/) | [en](../../en/set3/challenge_22/) |
| 23 | Clona MT19937 dall'output | [it](challenge_23/) | [en](../../en/set3/challenge_23/) |
| 24 | Crea lo stream cipher MT19937 e rompilo | [it](challenge_24/) | [en](../../en/set3/challenge_24/) |
