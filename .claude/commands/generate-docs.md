# Generate Cryptopals Challenge Documentation

Generate bilingual (Italian + English) Markdown documentation for every Cryptopals challenge implemented in this repository, structured for **GitHub Pages with the [Just the Docs](https://just-the-docs.com/) Jekyll theme**.

## GitHub Pages structure

The output must be a fully working Jekyll site under `docs/`. GitHub Pages will serve it when the repository is configured to use `docs/` as the Pages source.

### Files to create at the root of `docs/`

**`docs/_config.yml`**
```yaml
title: Rust Cryptopals
description: Soluzioni alle Cryptopals Crypto Challenges in Rust — documentazione bilingue IT/EN
remote_theme: just-the-docs/just-the-docs@v0.10.0

plugins:
  - jekyll-remote-theme
url: ""
baseurl: ""
lang: it

# Just the Docs settings
search_enabled: true
heading_anchors: true
color_scheme: light
nav_sort: case_sensitive

aux_links:
  "GitHub":
    - "//github.com/yourusername/rust-cryptopals"

footer_content: "Rust Cryptopals Docs · Just the Docs theme"
```

**`docs/index.md`** — home page (Italian), frontmatter:
```yaml
---
layout: home
title: Home
nav_order: 1
---
```

**`docs/index_en.md`** — home page (English), frontmatter:
```yaml
---
layout: home
title: Home (EN)
nav_order: 2
---
```

### Directory layout

```
docs/
├── _config.yml
├── index.md                    ← home IT (nav_order: 1)
├── index_en.md                 ← home EN (nav_order: 2)
├── set1/
│   ├── index.md                ← set1 landing IT  (has_children: true, nav_order: 3)
│   ├── index_en.md             ← set1 landing EN  (has_children: true, nav_order: 4)
│   ├── it/
│   │   ├── challenge_01.md     ← (parent: "Set 1 — IT", nav_order: 1)
│   │   └── … challenge_08.md
│   └── en/
│       ├── challenge_01.md     ← (parent: "Set 1 — EN", nav_order: 1)
│       └── … challenge_08.md
├── set2/
│   ├── index.md                (nav_order: 5)
│   ├── index_en.md             (nav_order: 6)
│   ├── it/ challenge_09…16
│   └── en/ challenge_09…16
└── set3/
    ├── index.md                (nav_order: 7)
    ├── index_en.md             (nav_order: 8)
    ├── it/ challenge_17…20
    └── en/ challenge_17…20
```

## Frontmatter rules for every file

Every Markdown file **must** start with a YAML frontmatter block. No file may be missing it.

**Set index files** (`set*/index.md`, `set*/index_en.md`):
```yaml
---
layout: default
title: "<Set N — IT|EN>"
nav_order: <N>
has_children: true
permalink: /setN/it/    # or /setN/en/
---
```

**Challenge files** (`set*/it/challenge_NN.md`, `set*/en/challenge_NN.md`):
```yaml
---
layout: default
title: "<Sfida NN — Titolo | Challenge NN — Title>"
parent: "<Set N — IT | Set N — EN>"
nav_order: <NN>
permalink: /setN/it/challenge_NN/   # or /setN/en/challenge_NN/
lang: it   # or en
---
```

**Home pages** (`index.md`, `index_en.md`): use the block shown above.

## Content rules

### Source files to read
1. `src/set1.rs`, `src/set2.rs`, `src/set3.rs` — extract every `challenge_NN` test.
2. All implementation files: `src/cryptovec/mod.rs`, `src/hex/mod.rs`, `src/base64/mod.rs`, `src/oracle/base.rs`, `src/oracle/mod.rs`, `src/crypters/mod.rs`, every `src/crypters/custom_crypter_*.rs`, `src/usizecrypt/mod.rs`, `src/errors/mod.rs`.

### Challenge file template (IT version)

```markdown
---
[frontmatter as above]
---

# Sfida NN — <Titolo>

[← Sfida precedente](../challenge_N-1/) · [Sfida successiva →](../challenge_N+1/) · [🇬🇧 English](../../en/challenge_NN/) · [Indice Set X](../)

---

## Teoria

<200+ words of flowing Italian prose explaining the cryptographic concept, threat model, and real-world relevance.>

## Concetti chiave

<Bullet list of 4–8 key terms with one-sentence Italian definitions.>

## Spiegazione del codice

### Struttura generale

<Which source files are involved and how they relate.>

### Implementazione

<Full call-path walkthrough from the test down to every primitive. For each function: quote a ```rust block, explain line by line. Minimum 300 words.>

### Il test

<Full test function in a ```rust block, explained.>
```

### Challenge file template (EN version)

Same structure, headings in English:

```markdown
---
[frontmatter as above]
---

# Challenge NN — <Title>

[← Previous](../challenge_N-1/) · [Next →](../challenge_N+1/) · [🇮🇹 Italiano](../../it/challenge_NN/) · [Set X index](../)

---

## Theory

## Key concepts

## Code walkthrough

### Overview

### Implementation

### The test
```

### Set index file content

Each `set*/index.md` and `set*/index_en.md` must include:
- A brief description of the set's theme (2–3 sentences).
- A Markdown table: `| # | Title | Description | IT | EN |` with relative links using the permalink paths.

### Home page content (`index.md` and `index_en.md`)

- Project title and one-paragraph introduction.
- Table of sets with theme, challenge count, and links to set index pages.
- Quick-reference table of all 20 challenges with links to both language versions.

## Naming and numbering rules

- Challenges 1–8 → `set1`, 9–16 → `set2`, 17–20 → `set3`.
- File names: zero-padded, `challenge_01.md` through `challenge_20.md`.
- `nav_order` for challenge files: use the challenge number within the set (1–8, 1–8, 1–4).
- Navigation links inside content: use the permalink paths (e.g. `../challenge_02/`), not relative file paths, so Jekyll resolves them correctly.
- First challenge of a set has no "previous"; last has no "next".

## Quality rules

- Titles must match the official Cryptopals challenge name.
- Code snippets must be fenced ` ```rust ` blocks.
- The Implementation section must trace the full call path — do not skip any helper method.
- Every function explanation must cover: parameters, return type, Rust-specific choices.
- Prose in complete sentences; no point-form paragraphs outside key-concepts lists.
- IT and EN versions semantically equivalent but written naturally in each language.

## After completing all files

Print a summary table: file path | language | approximate word count.
