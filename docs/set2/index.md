---
layout: default
title: "Set 2 — IT"
nav_order: 5
has_children: true
permalink: /set2/it/
---

# Set 2 — Cifrari a blocchi e attacchi oracle

Il secondo set esplora le modalità operative dei cifrari a blocchi — in particolare CBC ed ECB — e introduce la famiglia di attacchi "oracle", dove l'avversario può porre domande a un sistema di cifratura ignaro per ricavare informazioni segrete. Le sfide mostrano come difetti di progettazione, come l'assenza di integrità o il riutilizzo di IV, possano essere sfruttati in modo devastante.

| # | Titolo | Descrizione | IT | EN |
|---|--------|-------------|----|----|
| 9 | Padding PKCS#7 | Aggiunge padding a blocchi di lunghezza arbitraria | [IT](/set2/it/challenge_09/) | [EN](/set2/en/challenge_09/) |
| 10 | Implementa CBC mode | Implementazione manuale di AES-CBC | [IT](/set2/it/challenge_10/) | [EN](/set2/en/challenge_10/) |
| 11 | Oracle ECB/CBC | Rileva la modalità di cifratura sconosciuta | [IT](/set2/it/challenge_11/) | [EN](/set2/en/challenge_11/) |
| 12 | Byte-at-a-time ECB (semplice) | Estrazione del suffisso segreto dall'oracle | [IT](/set2/it/challenge_12/) | [EN](/set2/en/challenge_12/) |
| 13 | ECB cut-and-paste | Forgiatura di token cifrati per privilege escalation | [IT](/set2/it/challenge_13/) | [EN](/set2/en/challenge_13/) |
| 14 | Byte-at-a-time ECB (difficile) | Come nella 12 ma con prefisso casuale | [IT](/set2/it/challenge_14/) | [EN](/set2/en/challenge_14/) |
| 15 | Validazione padding PKCS#7 | Controllo della correttezza del padding | [IT](/set2/it/challenge_15/) | [EN](/set2/en/challenge_15/) |
| 16 | CBC bitflipping | Modifica del plaintext manipolando il ciphertext CBC | [IT](/set2/it/challenge_16/) | [EN](/set2/en/challenge_16/) |
