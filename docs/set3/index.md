---
layout: default
title: "Set 3 — IT"
nav_order: 7
has_children: true
permalink: /set3/it/
---

# Set 3 — Attacchi avanzati: padding oracle e CTR

Il terzo set porta gli attacchi a un livello superiore. La sfida 17 mostra come il padding oracle CBC permetta di decifrare qualsiasi ciphertext senza conoscere la chiave. Le sfide 18–20 introducono la modalità CTR (counter mode), che trasforma AES in un cifrario a flusso, e dimostrano come il riutilizzo del nonce crei vulnerabilità sfruttabili statisticamente.

| # | Titolo | Descrizione | IT | EN |
|---|--------|-------------|----|----|
| 17 | The CBC padding oracle | Decifratura completa via oracle di padding | [IT](it/challenge_17/) | [EN](en/challenge_17/) |
| 18 | Implementa CTR mode | AES come cifrario a flusso con contatore | [IT](it/challenge_18/) | [EN](en/challenge_18/) |
| 19 | Rompi CTR con nonce fisso (statistico) | Attacco frequenziale su keystream riutilizzato | [IT](it/challenge_19/) | [EN](en/challenge_19/) |
| 20 | Rompi CTR con nonce fisso (sostituzione) | Attacco scalato su molti ciphertext a keystream comune | [IT](it/challenge_20/) | [EN](en/challenge_20/) |
