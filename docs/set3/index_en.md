---
layout: default
title: "Set 3 — EN"
nav_order: 8
has_children: true
permalink: /set3/en/
---

# Set 3 — Advanced Attacks: Padding Oracle and CTR

The third set raises the stakes. Challenge 17 demonstrates how the CBC padding oracle allows complete decryption of any ciphertext without knowing the key. Challenges 18–20 introduce CTR (counter) mode, which turns AES into a stream cipher, and show how nonce reuse creates statistically exploitable vulnerabilities.

| # | Title | Description | IT | EN |
|---|-------|-------------|----|----|
| 17 | The CBC padding oracle | Full decryption via padding oracle | [IT](it/challenge_17/) | [EN](en/challenge_17/) |
| 18 | Implement CTR mode | AES as stream cipher with counter | [IT](it/challenge_18/) | [EN](en/challenge_18/) |
| 19 | Break fixed-nonce CTR statistically | Frequency attack on reused keystream | [IT](it/challenge_19/) | [EN](en/challenge_19/) |
| 20 | Break fixed-nonce CTR using substitutions | Scaled attack on many ciphertexts sharing keystream | [IT](it/challenge_20/) | [EN](en/challenge_20/) |
