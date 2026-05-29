---
name: italian-doc-conventions
description: Established conventions for Italian Cryptopals documentation in this repo
metadata:
  type: feedback
---

Use "asserisce" (not "afferma") to translate `assert_eq!` and `assert!` macro calls — it matches the technical term and is used consistently across all challenge files.

**Why:** "asserisce" is the direct calque of `assert` and is standard in Italian technical documentation for testing frameworks.

**How to apply:** Whenever describing what a test macro does, use "asserisce" consistently.

---

Challenge titles in `# Sfida N — ...` headings must match exactly the titles used in `README_it.md` index tables. Do not add or remove articles (e.g., "Rompi XOR" not "Rompi lo XOR"; "Attacchi di bitflipping CBC" not "Attacchi di bitflipping su CBC").

**Why:** Inconsistency between file headings and index tables creates navigational confusion.

**How to apply:** When editing a challenge file title, check `set*/README_it.md` and `docs/README_it.md` to confirm the exact wording.

---

Code identifiers cited in prose (variable names, method names) should match the actual identifier in the source code, not be translated into Italian. Example: use `readed_lines` not `righe_lette`.

**Why:** Readers cross-reference the documentation against the code; translated identifiers break that link.

---

Parenthetical expansions of acronyms use lowercase: "nonce (numero usato una volta)" not "nonce (Numero usato Una volta)".

**Why:** Italian convention for parenthetical glosses is sentence-case only, not title-case.
