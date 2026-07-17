# How to Write Documentation in infra-controller

This guide keeps our documentation consistent and professional, no matter who
writes it. It captures the prose and formatting conventions for user-facing docs
(guides, READMEs, reference pages, release notes, and design-doc prose), aligned
with NVIDIA's documentation style. For Rust code style, refer to
[`STYLE_GUIDE.md`](STYLE_GUIDE.md).

Contributors and AI agents: load this file before writing or editing
documentation, and apply the rules below. The 12 numbered categories double as a
review checklist, and the Quick Checklist at the end is the fast pass.

## Scope

Applies to: technical documentation, READMEs, guides, tutorials, reference docs,
design-doc prose, and release notes. Individual teams or authoring environments
can layer their own conventions on top; when a team guide exists, it takes
precedence for its surface. Programmer reference docs relax a few rules (passive
voice is acceptable there).

---

## 1. Brand Consistency

### NVIDIA Naming

- Always spell **NVIDIA** in all caps. Never "Nvidia", "nvidia", "nVidia", or
  "NV".
- Use "an NVIDIA", not "a NVIDIA" (the name starts with an "en" sound).
- Do not put a register mark (®) after "NVIDIA" when it refers to the company;
  use trademark symbols only on product references.
- Architecture names take "NVIDIA" on **every** mention: write "NVIDIA
  Blackwell", never bare "Blackwell".
- In a product list, put "NVIDIA" once at the start instead of repeating it for
  each product, unless a specific product or architecture name requires it.
- Do not overbrand NVIDIA-owned webpages and assets.
- Treat pop-up modals and in-page tabs as new pages: reintroduce "NVIDIA" and
  any trademark symbols as though the surface is new content.

### Voice and Tone

Apply the PACE principles:

- **Professional**: authoritative and credible.
- **Active**: active voice, present tense.
- **Conversational**: natural and approachable.
- **Engaging**: relevant and value-focused.
- The out-loud test: if you would not say it that way to a colleague, do not
  write it. Prefer simpler words ("use", not "leverage"). Use more periods. If
  you can cut a word, cut it.

## 2. Word Choice and Plain English

Write for non-native English speakers and machine translation as well as native
readers (Global English): active voice, short sentences, lists, and
straightforward language. Avoid culture-specific idioms, humor, puns, and
ambiguity.

### Accessibility Language

Replace these words with clearer, more accessible alternatives:

| Avoid  | Use Instead              | Why                              |
|--------|--------------------------|----------------------------------|
| see    | refer to                 | accessibility                    |
| please | (omit in technical docs) | acceptable in marketing only     |
| may    | can                      | "may" is ambiguous (permission)  |
| once   | after                    | "once" implies one-time/urgency  |

### Latinisms

Replace these Latin abbreviations with plain English:

| Avoid        | Use Instead                     |
|--------------|---------------------------------|
| cf.          | compare, refer to, as noted     |
| e.g.         | for example, such as            |
| etc.         | and so on                       |
| i.e.         | that is                         |
| via          | by, through, using              |
| versus (vs.) | compared to                     |
| vice versa   | conversely                      |

Exception: *in silico*, *in vitro*, and *in vivo* are acceptable (italicize).
Formal or academic content, and space-constrained contexts, are also exceptions.

### Colloquialisms and Informal Idioms

Replace vivid idioms with the precise technical term in prose, headings,
callouts, and example narration. Code, command names, and direct quotations from
logs or APIs are exempt. Common replacements:

| Avoid            | Use Instead                       |
|------------------|-----------------------------------|
| bake, baked into | embed, embedded in at build time  |
| smoke test       | basic verification test           |
| footgun          | common pitfall, error-prone usage |
| dead end         | unsupported path, blocked config  |
| spin up          | start                             |

For idioms not in this table, prefer the most precise technical term over the
most colorful one.

### Contractions

Avoid contractions in technical documentation ("it is", not "it's"; "cannot",
not "can't"). Do not recommend contractions as a style improvement.

### Abbreviations and Common Terms

- Do not abbreviate on first use unless the term is common; introduce as "full
  term (ABBR)" and use the abbreviation thereafter.
- Add `s`, not apostrophe-s, for plural acronyms: GPUs, not GPU's.
- Common terms do not need spelling out on first use: AI, CPU, DPU, GPU, PC, SDK.
- Spell out on first use: large language model (LLM), retrieval-augmented
  generation (RAG), small language model (SLM), and vision language model (VLM).
  Spell out **MoE** as "mixture of experts" or "mixture-of-experts".
- **NIM** is a brand name, not an acronym: do not expand or lowercase it.
- Common spellings: data center (two words); dataset, datasheet, pretrained,
  startup, webpage, website, whitepaper (one word); open source (never
  hyphenated, even as a modifier); on-premises (hyphenate as adjective,
  otherwise "on premises"); generative AI (long form first; "gen AI" acceptable
  after); deep learning, machine learning (lowercase unless in a title); ray
  tracing (noun), ray-tracing (adjective); zero-trust (adjective); Wi-Fi
  (capital W and F); pandas, scikit-learn (do not capitalize).

## 3. Numbers and Measurements

- Spell out zero through nine in body text; use numerals for 10 and above.
- Exception: use numerals for specific values, parameters, and technical specs
  even under 10 ("Set the parameter to 5.", "The timeout is 3 seconds.").
- Use numerals for UI text, time, and values before million, billion, or
  trillion.
- Use a thousands separator: 1,397 (not 1397).
- Do not start a sentence with a numeral (rewrite, or spell it out). Starting a
  list item with a numeral is fine.
- Always spell out ordinals: "tenth", not "10th".
- When two numbers of different types sit together, use a numeral for one and
  spell out the other: "fifteen 20-page articles".
- Currency: symbol before the value, no space ($100, €50); spell out or
  abbreviate currency names consistently, preceded by numerals (1,000 yen, 50 USD).
- Numerals stay as-is for established terms: 2D, 3D, 4K, 8K, 4G, 5G, 6G, 24/7.

### Units

- Be consistent: all abbreviated or all spelled out; do not mix within a piece.
- Put a space between number and unit: 40 GB, 30 mm.
- Use correct throughput units: GB/s, not GBps or GB/second.
- Some networking speeds omit the space by convention: 100G, 100GbE.

## 4. Capitalization

- **Headings**: use title case consistently in technical documentation. No
  styling (code, italics), quotes, ampersands, or exclamation marks in headings.
- Title-case mechanics: capitalize the second word of a compound
  (Multi-Display); do not capitalize conjunctions (and, as, but); do not
  capitalize prepositions of three letters or fewer.
- **Proper nouns**: product, event, research, and whitepaper names are always
  title case; product names (TensorRT, Triton) keep their canonical casing.
- **Industries**: lowercase the names ("media and entertainment"), but
  capitalize the abbreviation (M&E).

## 5. Punctuation

### Em Dashes

Avoid the em dash (U+2014) in documentation prose. Substitute a spaced hyphen, a
colon, a semicolon, or parentheses. Four reasons:

1. Heavy em-dash use reads as AI-generated, a credibility cost for authored
   content.
2. The non-ASCII byte breaks exact-match editing tools and trips up some diffs
   and search at the encoding boundary.
3. A spaceless em dash fuses two words into one token for whitespace tokenizers
   and naive search.
4. Mixed em dashes and hyphens drift within a document and accrue consistency
   debt.

**The tight-hyphen trap**: when the em dash was a spaceless separator
(`word—word`), replace it with a spaced separator (`word - word`), a colon, or a
semicolon. Never collapse it to a tight `word-word`: that glues the two tokens
into a compound and changes meaning.

### En Dashes

- Use an en dash for ranges, no spaces: 2015–2017.
- For time ranges in running text, use "to" ("from 12:30 to 1 p.m."); in a
  schedule or listing, use an en dash with no spaces ("12:30–1 p.m."). Do not
  mix "from" with an en dash.
- Add spaces only for a complex range that spans both times and dates.

### Hyphens

- Hyphenate compound adjectives before a noun (built-in drive, real-time
  scenario, command-line output).
- Do not hyphenate the same compound used as a noun ("the command line is easy").
- Do not hyphenate `-ly` adverb compounds (physically based, not
  physically-based).

### Other Punctuation

- **Ampersand**: do not use for "and" unless part of a name or title.
- **Apostrophe**: form singular possessives with 's even after s, x, or z ("the
  CSS's flexibility"); plural nouns ending in s take only an apostrophe. Never
  use an apostrophe for possessive "its" or to form a plural.
- **Colon**: use to introduce a list or elaborate a statement; lowercase the
  word after a colon unless a full sentence follows. Avoid joining two
  independent clauses with a colon.
- **Commas**: use Oxford (serial) commas in lists of three or more; follow an
  introductory phrase with a comma; use a comma before a conjunction joining
  independent clauses; separate thousands.
- **Exclamation marks**: avoid.
- **Parentheses**: use sparingly in body copy; never in headlines or subheads.
- **Period**: one space after, not two. Omit terminal periods in headings, UI
  titles or text, simple list items of three or fewer words, and table cells; if
  any item in a list is a full sentence, punctuate every item in that list.
- **Quotation marks**: use double quotes, not single. Place periods and commas
  inside (U.S. style); other punctuation goes outside unless it is part of the
  quote. Avoid quotation marks for titles or new terms.
- **Semicolons**: prefer splitting into separate sentences or a list.
- **Slashes**: avoid the forward slash for "or" constructions (no "and/or"). It
  is fine for industry-standard terms (read/write), GitHub repos, and Linux
  paths.
- **Optional steps**: write "Optional:" with a colon, not "(Optional)".

## 6. Grammar

- **Active voice**: prefer it; stress who or what performs the action. Passive
  is acceptable only when the subject is unknown, when the action needs the
  emphasis, or in programmer reference docs.
- **Present tense**: describe product behavior in the present ("The dialog
  displays options."), not the future ("will display").
- **Second person**: address the reader as "you", not "users" or "we". Exempt:
  quoted UI labels, API field names, and audience role labels in tables (for
  example, an **End users** column).
- **Which and that**: use "that" (no commas) for essential clauses the sentence
  needs; use "which" (with commas) for nonessential clauses you could remove.
  Test: if removing the clause keeps the core meaning, use "which" with commas.

## 7. Technical Content and Formatting

Format elements consistently:

| Element                      | Format                    | Example                    |
|------------------------------|---------------------------|----------------------------|
| Commands, file names, paths  | Monospace                 | `apt-get install`          |
| Variables in paths           | Angle brackets, monospace | `/home/<username>/.login`  |
| Expressions                  | Monospace                 | `delay > 10`               |
| UI elements (buttons, menus) | Bold                      | **Save As** > **Close**    |
| User input and actions       | Bold                      | Enter **value**            |
| New terms                    | Italic                    | *system-allocated memory*  |
| Publication and media titles | Italic                    | *SDK Programming Guide*    |
| Games, books, films          | Italic (title case)       | *Minecraft*                |
| Error messages (inline)      | Quotation marks           | "Invalid input"            |
| Strings                      | Quotation marks           | "hello"                    |
| Keyboard shortcuts           | No formatting             | Ctrl+Alt+Delete            |

Rules:

- Introduce code examples, lists, tables, and images with a complete sentence
  (they are not parts of speech; end the sentence before them).
- Call them "code example" or "example", never "snippet". Inline references to a
  method can drop the empty parentheses.
- Use monospace plus syntax highlighting for code; do not combine monospace with
  other styling for files and paths.
- Use LaTeX or MathML for equations, inline or displayed.
- File name extensions: period and lowercase (`.tgz`). File types: uppercase, no
  period (TGZ).
- Standalone or multiline output goes in a code block; inline error messages go
  in quotation marks.
- Use footnotes sparingly unless team guidance says otherwise; integrate the
  information into the text where possible.
- GitHub repos: use a forward slash and the repo name ("the /NVIDIA/NeMo GitHub
  repo"), not bare "the GitHub repo".
- Avoid flowery marketing claims and comparisons with third-party products.
- Model names: include the company name and qualifier on first use ("the NVIDIA
  Nemotron-3-8B-QA-4k model", "the Microsoft Kosmos-2 model"); follow each
  vendor's naming conventions.
- Use one term consistently; add a synonym only to connect an industry-standard
  term with an NVIDIA-specific one.
- Trademarks: use the trademark symbol on first product mention in public
  relations and sales content; do not use trademark symbols in learning content
  (blog posts, tutorials, conference sessions).

## 8. Lists and Tables

### Lists

- Introduce with a complete lead-in sentence.
- Two or more items, maximum two levels.
- Use parallel construction and capitalize the first letter of each item.
- Add end punctuation only if items are complete sentences (and then to all).
- Choose a list type:
  - **Bulleted**: order does not matter (introduce with a colon).
  - **Numbered**: sequential steps.
  - **Definition**: a bold term on its own line with an indented definition.

### Tables

- Introduce with a full sentence and a colon.
- Use title case headers and give every table a caption or title.
- Two or more rows; avoid empty cells.

### Procedures

- Numbered steps are optional, especially when steps are separated by code
  blocks, images, or supplemental information.
- Keep a numbered procedure to five to seven steps; break long or nested procedures
  into smaller tasks separated by subheadings.
- Use imperative sentences for actions and declarative sentences for
  explanations.

## 9. Dates and Time

- Dates: Month DD, YYYY (August 12, 2025) unless regional content needs another
  format. Spell out month names in body copy; use approved abbreviations (Jan.,
  Feb., Aug., Sept., Oct., Nov., Dec.; March through July always spelled out)
  only in tables, banners, or constrained spaces.
- No ordinal dates: August 12, not August 12th. Omit the year if it matches the
  publication year.
- Days of the week are capitalized; abbreviate (Sun, Mon, ...) only when space
  is extremely limited, with no period.
- Time: 12-hour format, minutes only when needed (10 a.m., 10:30 a.m., 2 p.m.);
  space and periods in a.m. and p.m.; use ET and PT for Eastern and Pacific Time.
- Prefer "after" over "once": "after" marks what follows; "once" implies urgency
  and one time only.

## 10. Links and References

- Use descriptive link text that matches the destination title; no raw URLs in
  running text.
- Include acronyms in the link text: [large language models (LLMs)].
- Avoid generic text: "here", "read more", "click here".
- Limit inline links per paragraph to protect readability.

## 11. Accessibility

- Provide descriptive alt text for images and descriptive anchor text for links.
- Use proper heading hierarchy (H1 to H2 to H3).
- Meet a color contrast ratio of at least 4.5:1.
- Prefer shorter sentences and paragraphs with even spacing.

## 12. Readability

- Aim for sentences under 30 words.
- Use simple, direct language.
- Use academic conjunctive adverbs sparingly: Additionally, Consequently,
  Furthermore, Hence, Moreover, Thus, Undoubtedly, Whilst.
- Make content scannable with clear headings and lists.
- Write inclusively; avoid gender-specific pronouns and expressions that could
  alienate readers from different backgrounds.

---

## Over-Application Safeguards

Style rules improve clarity; they are not blind find-and-replace. Before
flagging or changing something, confirm it genuinely degrades readability. Do
not "fix" these:

- **Product names in headings**: "NVIDIA NIM" is a brand, not a violation.
- **Code identifiers**: `snake_case` names are not prose.
- **URLs and paths**: `/opt/nvidia/...` should not trigger Latin-word or
  word-swap checks.
- **Quoted terminal output, logs, and API fields**: literal text must not be
  rewritten.
- **Brand names**: NIM stays NIM; NVIDIA stays all-caps; TensorRT and Triton
  keep their casing.

---

## Quick Checklist

- [ ] NVIDIA spelled correctly in all caps; "an NVIDIA".
- [ ] Active voice, present tense, second person ("you").
- [ ] No contractions.
- [ ] No Latinisms ("e.g.", "etc.", "i.e.", "via") or vivid idioms ("spin up", "footgun").
- [ ] No em dashes (U+2014); spaced hyphen, colon, semicolon, or parentheses instead.
- [ ] Numbers and units formatted correctly.
- [ ] Oxford commas; periods inside quotation marks.
- [ ] Headings in title case, no styling or terminal periods.
- [ ] Code elements in monospace; new terms in italic; UI in bold.
- [ ] Lists have a lead-in and parallel structure.
- [ ] Links have descriptive text; no raw URLs.
- [ ] Sentences under 30 words; proper heading hierarchy.
