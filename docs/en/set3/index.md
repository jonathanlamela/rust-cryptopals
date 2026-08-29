---
layout: default
title: "Set 3 EN"
parent: EN
nav_order: 3
has_children: true
permalink: /en/set3/
---

# Set 3 — CTR, padding oracle and statistical attacks

The third set introduces AES CTR (Counter) mode, a stream cipher built on top of AES-ECB, and the celebrated CBC padding oracle attack. The final challenges show how CTR encryption with a fixed nonce is vulnerable to the same statistical attacks used against repeating-key XOR. The second half of the set implements the MT19937 Mersenne Twister RNG and demonstrates its insecurity: time-based seed recovery, state cloning from outputs, and breaking an MT19937-based stream cipher.

| # | Title | EN | IT |
|---|-------|----|-----|
| 17 | The CBC padding oracle | [en](challenge_17/) | [it](../../it/set3/challenge_17/) |
| 18 | Implement CTR, the stream cipher mode | [en](challenge_18/) | [it](../../it/set3/challenge_18/) |
| 19 | Break fixed-nonce CTR mode using substitutions | [en](challenge_19/) | [it](../../it/set3/challenge_19/) |
| 20 | Break fixed-nonce CTR statistically | [en](challenge_20/) | [it](../../it/set3/challenge_20/) |
| 21 | Implement the MT19937 Mersenne Twister RNG | [en](challenge_21/) | [it](../../it/set3/challenge_21/) |
| 22 | Crack an MT19937 seed | [en](challenge_22/) | [it](../../it/set3/challenge_22/) |
| 23 | Clone an MT19937 from its output | [en](challenge_23/) | [it](../../it/set3/challenge_23/) |
| 24 | Create the MT19937 stream cipher and break it | [en](challenge_24/) | [it](../../it/set3/challenge_24/) |
