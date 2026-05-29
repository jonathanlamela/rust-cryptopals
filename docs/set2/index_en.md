---
layout: default
title: "Set 2 — EN"
nav_order: 6
has_children: true
permalink: /set2/en/
---

# Set 2 — Block Ciphers and Oracle Attacks

The second set explores block cipher operating modes — particularly CBC and ECB — and introduces the "oracle attack" family, where an adversary can query an unwitting encryption system to extract secret information. The challenges demonstrate how design flaws such as missing integrity checks or IV reuse can be exploited devastatingly.

| # | Title | Description | IT | EN |
|---|-------|-------------|----|----|
| 9 | PKCS#7 padding | Add padding to arbitrarily-length blocks | [IT](/set2/it/challenge_09/) | [EN](/set2/en/challenge_09/) |
| 10 | Implement CBC mode | Manual AES-CBC implementation | [IT](/set2/it/challenge_10/) | [EN](/set2/en/challenge_10/) |
| 11 | ECB/CBC oracle | Detect unknown encryption mode | [IT](/set2/it/challenge_11/) | [EN](/set2/en/challenge_11/) |
| 12 | Byte-at-a-time ECB (simple) | Extract secret suffix from oracle | [IT](/set2/it/challenge_12/) | [EN](/set2/en/challenge_12/) |
| 13 | ECB cut-and-paste | Forge encrypted tokens for privilege escalation | [IT](/set2/it/challenge_13/) | [EN](/set2/en/challenge_13/) |
| 14 | Byte-at-a-time ECB (harder) | Like challenge 12 but with random prefix | [IT](/set2/it/challenge_14/) | [EN](/set2/en/challenge_14/) |
| 15 | PKCS#7 padding validation | Verify padding correctness | [IT](/set2/it/challenge_15/) | [EN](/set2/en/challenge_15/) |
| 16 | CBC bitflipping | Modify plaintext by manipulating CBC ciphertext | [IT](/set2/it/challenge_16/) | [EN](/set2/en/challenge_16/) |
