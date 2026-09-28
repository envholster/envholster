# ENVELOPE-SPEC — envholster vault schema 1 (frozen)

Status: **frozen for schema 1.** This document is normative for the byte-level
format of `secrets.holster` (the committed vault). Any change to the format is
a new schema number and an explicit edit to this document, never silent drift
in code. This specification is complete on its own.

**Acceptance bar:** two independent implementations, written from this document
alone (no Rust source), MUST interoperate: each must open, decrypt, verify, and
byte-identically re-serialize vaults written by the other, and both must pass the
golden vectors of §11.

The companion document `RECOVERY-SPEC.md` freezes the recovery blob
(`secrets.holster.recovery.age`) and the recovery procedure. The plaintext manifest
(`envholster.toml`) is TOML handled by ordinary TOML tooling and is out of scope
here except where §2 names it.

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in RFC 2119.

Threat posture (context for every rule below): git history is hostile and public
repositories are in scope — every historical byte of the vault is permanently
attacker-observable, and the file itself may have been rewritten by an attacker.

---

## 1. Files, names, permissions

| File | Name (frozen constant) | Content |
|---|---|---|
| Vault | `secrets.holster` | this spec |
| Recovery blob | `secrets.holster.recovery.age` | RECOVERY-SPEC.md |
| Manifest | `envholster.toml` | plaintext TOML, committed |

Local filesystem permissions (writer obligation, `doctor` error on violation):
vault, recovery blob, and identity files `0600`; their containing directories
`0700`.

The vault magic is the 12 ASCII bytes `ENVHOLSTERv1`. Schema is `1`.

Fixed sizes: DEK 32 bytes; XChaCha20 nonce 24 bytes; Poly1305 tag 16 bytes;
DEK commitment 32 bytes.

---

## 2. Data model

### 2.1 Cells and DEKs

A vault stores secrets in **cells**. A cell is one (environment × tier) pair;
tiers are `1`, `2`, `3`. Environment names match
`[a-z0-9][a-z0-9_-]{0,31}` — first character alphanumeric, 1–32 bytes total.
By construction an environment name can never contain `:` or `*`, which keeps
the AAD suffix (§5.2) and the enroll wildcard (§4.5) unambiguous. The name
`base` is an ordinary environment at the envelope layer (its reserved semantics
live in the manifest/CLI layer).

Each **occupied** cell owns exactly one 256-bit data-encryption key (**DEK**),
drawn from a CSPRNG at cell creation. Cells are lazy: a cell exists only once a
first record is written into it. Duplicate (env, tier) cells in one vault are a
parse error.

### 2.2 Recipients

Every recipient belongs to exactly one **class**, recorded in the header:

- `hardware` — age plugin identities (allowlisted plugins only, §4.4); unwrap
  is a hardware operation.
- `software` — X25519 identity files, Keychain-wrapped X25519, scrypt
  passphrases, CI identities.
- `recovery` — **exactly one per vault, mandatory**: an offline X25519 identity
  that exists only on paper or removable media, never on an enrolled machine's
  disk. A vault whose header does not contain exactly one recovery-class
  recipient is invalid.

Class/kind consistency (§4.4) is checked at parse: `hardware` recipients MUST
have a `plugin:` kind; `recovery` recipients MUST have kind `x25519`;
`software` recipients MUST have kind `x25519` or `scrypt:<log_n>`.

### 2.3 Recipient id

A recipient id is 16 lowercase hex characters encoding 8 bytes:

- **Keyed kinds** (`x25519`, `plugin:*`): the first 8 bytes of
  `SHA-256("envholster-v1-rcpt:" ‖ full recipient encoding)`, where
  `"envholster-v1-rcpt:"` is the 19 ASCII bytes
  `65 6e 76 68 6f 6c 73 74 65 72 2d 76 31 2d 72 63 70 74 3a` and the full
  recipient encoding is the exact byte string on the recipient's `encoding =`
  line (the complete Bech32 string, e.g. `age1...`).
- **scrypt**: 8 CSPRNG bytes drawn at enrollment (there is no public encoding
  to hash).

Duplicate recipient ids in one header are a parse error.

### 2.4 Enrollment

Each recipient is enrolled either for **all environments** (present and future)
at a single max tier, or for a **named list** of environments each with its own
max tier. On-disk encoding: §4.5. The recovery recipient MUST be enrolled
all-envs at max tier 3 (`enroll = *:3`); anything narrower is invalid.

### 2.5 Wrap matrix (G-A) and the eligible set

The per-class tier cap is structural, not policy:

| Class | cap |
|---|---|
| hardware | 3 |
| software | 1 |
| recovery | 3 |

A recipient r's **effective max tier for environment e** is
`min(enrolled max_tier of r for e, cap(class(r)))`; a recipient not enrolled
for e has no effective tier there. The **eligible set** of cell (e, t) is:

> every recipient whose effective max tier for e is ≥ t, plus the recovery
> recipient (which, being `*:3`, is always eligible).

Writers MUST wrap each cell's DEK to **exactly** its eligible set — no member
missing, no extra member. In particular:

- (e, tier 1): every recipient enrolled for e (software and CI included) plus
  recovery.
- (e, tier 2–3): hardware recipients enrolled for e with max_tier ≥ t, plus
  recovery, **only**. A wrap of a tier ≥ 2 DEK to a software-class recipient is
  a hard error at save time; **no override flag exists**. Consequence: a stolen
  software identity file recovers nothing above tier 1, cryptographically.

Readers MUST reject at parse any cell whose wrap list names a recipient id not
declared in the header, contains duplicate ids, is unsorted, or contains a
wrap that violates the class cap (e.g. a software wrap on a tier-2 cell).
Readers are NOT required to verify completeness of the eligible set (a missing
wrap is a writer bug / availability problem, surfaced by `check`/`status`, not
a parse failure) — see Appendix A.3.

### 2.6 Recipient kinds (forward-versioned)

| `kind =` value | Meaning |
|---|---|
| `x25519` | age native X25519 recipient |
| `scrypt:<log_n>` | age scrypt passphrase recipient; `log_n` decimal in [20, 22] |
| `plugin:<name>` | age plugin recipient; `<name>` charset `[a-z0-9-]{1,32}` AND allowlisted to `{yubikey, se}` |

An unknown kind, an out-of-range `log_n`, or a plugin name outside the
allowlist MUST fail open() with a "vault written by a newer envholster
version" class error — a recipient is never skipped or guessed at. Post-quantum
kinds, when they exist, arrive all-or-nothing per vault (one classical wrap
voids any PQ claim); schema 1 defines none.

---

## 3. File layout overview

`secrets.holster` is UTF-8 text, three regions in order:

1. **Header core** — preamble, recipient blocks, cell blocks, terminated by the
   core-end marker line. The header core's exact bytes are the AAD prefix of
   every cell (§5.2).
2. **Tag section** — the detached 16-byte Poly1305 tag of each cell (tags are
   AEAD outputs and therefore cannot sit inside their own AAD).
3. **Body blocks** — each cell's raw ciphertext, base64.

Any byte after the last body block (or, in a vault with zero cells, after the
`[tags]` line) is a parse error.

### 3.1 Canonical encoding — one byte sequence per logical content

The whole file is canonical: for any logical content there is **exactly one**
accepted byte sequence. Parsers MUST reject any deviation; re-serializing a
parsed vault MUST be byte-identical to the input. This strictness is
load-bearing: the header core bytes are the AAD.

Canonical rules (apply everywhere):

- Line terminator is LF (`0x0a`) only. No CR anywhere. The final line of the
  file is LF-terminated; there is no trailing byte after that LF.
- Key/value lines use exactly one space on each side of `=`
  (`key = value`). No line has trailing whitespace. No line is indented.
- Integers are decimal, no leading zeros (except the single digit `0`), no `+`
  sign. (No negative integers occur in the header.)
- Hex is lowercase.
- Base64 is the standard alphabet (`A–Z a–z 0–9 + /`) with `=` padding.
- No comments exist anywhere in the file. (`#` annotations in this document's
  grammar figures are annotations, not file content.)
- Blank-line placement is fixed (§3.2): exactly one empty line (a lone LF)
  precedes every `[recipient ...]`, `[cell ...]`, and `[body ...]` heading and
  the core-end marker; the `[tags]` line immediately follows the core-end
  marker with no blank line; no other blank lines exist.
- Mandated sort orders (§4) are strict; equal keys (duplicates) are parse
  errors.

### 3.2 Grammar

```
file          = header-core tag-section *body-block
header-core   = preamble *recipient-block *cell-block core-end
preamble      = "ENVHOLSTERv1" LF
                "schema = 1" LF
                "generation = " u64 LF
                "vault-uuid = " uuid LF

recipient-block = LF "[recipient \"" id16 "\"]" LF     ; blocks sorted by id ascending
                "class = " class LF
                "kind = " kind LF
                "label = " label LF
                ["encoding = " encoding LF]            ; absent iff kind is scrypt (§4.4)
                "enroll = " enroll LF

cell-block    = LF "[cell \"" env "\" " tier "]" LF    ; blocks sorted by (env asc, tier asc)
                "commitment = " 64hex LF
                "nonce = " 48hex LF
                "ct-len = " u32 LF
                *wrap-line                             ; ≥1; sorted by recipient id ascending
wrap-line     = "wrap " id16 " = " b64 LF

core-end      = LF "-----ENVHOLSTER CORE END-----" LF

tag-section   = "[tags]" LF *tag-line                  ; one per cell, cell order
tag-line      = "tag " env ":" tier " = " 32hex LF

body-block    = LF "[body \"" env "\" " tier "]" LF    ; one per cell, cell order
                *b64-line
b64-line      = 1*64( b64char ) LF                     ; 64 chars per line, last line shorter

id16   = 16 lowercase hex chars
uuid   = 8-4-4-4-12 lowercase hex, hyphenated (36 chars)
class  = "hardware" / "software" / "recovery"
tier   = "1" / "2" / "3"
env    = [a-z0-9][a-z0-9_-]{0,31}
```

"Sorted ascending" means byte-wise (memcmp) ascending on the raw bytes of the
sort key. Cell order is (env bytes ascending, then tier ascending); this same
order governs cell blocks, tag lines, and body blocks, which MUST correspond
1:1:1.

The **header core** is every byte from offset 0 through the
`-----ENVHOLSTER CORE END-----` line's LF **inclusive**. Implementations MUST
be able to produce these exact bytes for AAD assembly — either by retaining the
raw input or by canonical re-serialization (identical by construction).

### 3.3 Annotated example

Structurally exact; hex/base64 payloads abbreviated with `…` for readability
(a real file carries full-length values):

```
ENVHOLSTERv1
schema = 1
generation = 7
vault-uuid = 3f2a9c10-88e2-4c5b-9d41-6b7f0a2c9e55

[recipient "1c9a2b3d4e5f6071"]
class = software
kind = x25519
label = alice laptop
encoding = age1qqpszry9…
enroll = *:1

[recipient "8b1e2f3a4c5d6e7f"]
class = recovery
kind = x25519
label = paper kit 2026-07
encoding = age1u7fz2…
enroll = *:3

[cell "base" 1]
commitment = 9f86d081884c7d65…                       (64 hex)
nonce = 24f1b60c9d2e7a5583c0…                        (48 hex)
ct-len = 137
wrap 1c9a2b3d4e5f6071 = YWdlLWVuY3J5cHRpb24u…
wrap 8b1e2f3a4c5d6e7f = YWdlLWVuY3J5cHRpb24u…

-----ENVHOLSTER CORE END-----
[tags]
tag base:1 = 0f1e2d3c4b5a69788796a5b4c3d2e1f0

[body "base" 1]
q0svMBQok0T7GdWALRy0Yc2rjcVLYD9nJZWavPKMSk6mS1Uj0Q2LmyfSFO0jRPeq
Ck52aXBhc3M…
```

Note the recipient blocks are id-sorted (`1c…` < `8b…`) and each cell's wrap
lines repeat that order.

---

## 4. Header fields, line by line

### 4.1 Preamble

- Line 1: exactly `ENVHOLSTERv1`. Anything else: not an envholster vault.
- `schema = 1`. A larger value MUST be refused with the migration message of
  §10 ("vault from a newer version — upgrade envholster"). A smaller or
  non-integer value is a parse error.
- `generation = <u64>`: increments by exactly 1 per save (§9). The first file
  a vault-create writes carries `generation = 1` (Appendix A.5).
- `vault-uuid`: 16 bytes rendered as lowercase hyphenated hex (8-4-4-4-12).
  Writers generate the 16 bytes from a CSPRNG at vault creation; no RFC 4122
  version/variant bit structure is required or checked (Appendix A.6). Parsers
  accept any well-formed lowercase hyphenated uuid.

### 4.2 `class`

One of `hardware`, `software`, `recovery`, subject to §2.2 (exactly one
recovery recipient; class/kind consistency per §2.2/§4.4).

### 4.3 `label`

UTF-8, 1–64 bytes, no control characters (bytes `0x00–0x1f` and `0x7f`
forbidden), and MUST NOT begin or end with a space or tab (forced by the
no-trailing-whitespace / single-space-around-`=` canonical rules; a label is
therefore never empty — Appendix A.2). Interior spaces are legal.

### 4.4 `kind` and `encoding`

Per §2.6. The `encoding` line carries the **full** age recipient encoding
(the complete public string, e.g. `age1…`, `age1yubikey1…`, `age1se1…`) —
stored in full because key rotation must be able to re-wrap without external
input. Charset: printable ASCII excluding space (`0x21–0x7e`).

For `kind = scrypt:<log_n>` there is **no public encoding**; the `encoding`
line is **omitted entirely** for scrypt recipients (Appendix A.1). For every
other kind the line is mandatory. A scrypt block containing an `encoding`
line, or a non-scrypt block missing one, is a parse error.

`log_n` MUST be 20, 21, or 22 (§6.2).

### 4.5 `enroll`

Exactly one of two forms — they never mix:

- **Wildcard**: `enroll = *:<max_tier>` — enrolled in every environment,
  present and future. (Cells are lazy; a named-only grammar would silently
  orphan all-envs recipients whenever a new environment's first cell is
  written.) The wildcard stands alone: combining `*` with named entries, or
  listing `*` more than once, is a parse error. `*` is not a legal env name,
  so the forms cannot collide.
- **Named list**: `enroll = <env>:<max_tier>[,<env>:<max_tier>...]` — comma
  separated, **no spaces**, entries sorted by env bytes ascending, duplicate
  env is a parse error. Each entry carries its own max_tier (they may differ).

`<max_tier>` is a single digit `1`–`3`. The recovery recipient MUST carry
exactly `enroll = *:3`; writers MUST enforce this at save, and readers MUST
treat any other recovery enrollment as an invalid vault.

### 4.6 Cell block fields

- Heading `[cell "<env>" <tier>]`: env quoted, tier a bare digit.
- `commitment = <64 hex>`: `HMAC-SHA-256(key = DEK, message =
  "envholster-v1-commit")` where the message is the 20 ASCII bytes
  `65 6e 76 68 6f 6c 73 74 65 72 2d 76 31 2d 63 6f 6d 6d 69 74` (no
  terminator). See §5.4.
- `nonce = <48 hex>`: the 24-byte XChaCha20 nonce most recently used to
  encrypt this cell's body. This field is **write-only output** of the last
  save and **read-only input** to decrypt; a stored nonce is never an
  encryption input (§5.3).
- `ct-len = <u32>`: raw ciphertext byte length. With a detached tag,
  XChaCha20-Poly1305 ciphertext length equals plaintext length, so `ct-len`
  also equals the cell's HB1 plaintext length. AAD-covered like the rest of
  the core, it authenticates each body's length.
- `wrap <id16> = <b64>`: one per eligible recipient (§2.5), sorted by
  recipient id; the value is a single unwrapped base64 token (no line
  wrapping) encoding a complete **binary** (non-armored) single-recipient age
  file whose payload is the 32-byte DEK (§6.1; Appendix A.4).

### 4.7 Tag lines

`tag <env>:<tier> = <32 hex>` — the cell's detached 16-byte Poly1305 tag,
lowercase hex, unquoted env, one line per cell, in cell order. In a vault with
zero cells the `[tags]` line is still present, followed by nothing
(Appendix A.7).

### 4.8 Body blocks

`[body "<env>" <tier>]` followed by the cell's raw ciphertext in padded
standard base64, broken into 64-character lines, each LF-terminated; the last
line carries the remainder (1–64 chars) and is also LF-terminated. The decoded
byte length MUST equal the cell's `ct-len`. Bodies appear in cell order.

A body is never empty: the minimum HB1 plaintext is 4 bytes (§7), so the
minimum ciphertext is 4 bytes.

Git note (by design): the header is diff-friendly for recipient/enrollment
operations, but **every body changes entirely on every save** — deterministic
or "diff-optimized" nonces are a security bug, not a feature.

---

## 5. AEAD, AAD, nonces, commitment

### 5.1 Cipher

**XChaCha20-Poly1305** (24-byte nonce, 16-byte tag, 32-byte key = the cell's
DEK). Encryption and decryption are performed **in place** with the tag
**detached** into the `[tags]` section. Plaintext is the cell's HB1 encoding
(§7).

### 5.2 AAD — exact bytes

The AAD of cell (env e, tier t) is the concatenation:

```
AAD(e, t) = header-core-bytes ‖ "cell:" ‖ e ‖ ":" ‖ tier-digit
```

where:

- `header-core-bytes` — every byte of the file from offset 0 through the LF of
  the `-----ENVHOLSTER CORE END-----` line, inclusive, exactly as on disk;
- `"cell:"` — the 5 ASCII bytes `63 65 6c 6c 3a`;
- `e` — the environment name's bytes;
- `":"` — one byte `3a`;
- `tier-digit` — one ASCII byte `31`, `32`, or `33`.

Example suffix for (prod, 3): the 11 bytes `cell:prod:3`
(`63 65 6c 6c 3a 70 72 6f 64 3a 33`).

Consequences (this is the point of the design): recipient substitution,
enrollment edits, schema or generation flips, nonce or `ct-len` tampering,
cell swaps (same ciphertext under another cell's heading), and
cross-generation header/body mix-and-match all fail decryption for every
legitimate opener.

Because the header core — including `generation` and every cell's `nonce` and
`ct-len` — is inside every cell's AAD, **every save re-encrypts every occupied
cell** (fresh nonce, new ciphertext, new tag), and therefore every occupied
cell's DEK must be available at save time. §8.1 gives the resulting writer
algorithm.

### 5.3 Nonce discipline

A fresh 24-byte nonce is drawn from the OS CSPRNG (e.g. `getrandom`) into a
fixed-size buffer **immediately before each encryption**. No nonce ever lives
on a long-lived structure; the header `nonce` field is output of the last save
and input only to decryption. Gates: two consecutive saves of identical
logical content MUST differ in every cell's nonce and ciphertext; an N-save
property test asserts nonce uniqueness.

### 5.4 DEK commitment

XChaCha20-Poly1305 is not key-committing; with multiple recipients an attacker
who controls wrap blobs could otherwise arrange different recipients to decrypt
the same body to different plaintexts ("invisible salamanders"). Therefore:

- At save, the writer records `commitment = hex(HMAC-SHA-256(DEK,
  "envholster-v1-commit"))` in the cell block.
- After every successful unwrap, and **before** attempting body decryption,
  the reader MUST recompute the HMAC over the just-unwrapped DEK and compare
  it (constant-time) to the header value. Mismatch fails the open.
- Error surfacing MUST NOT distinguish a commitment failure from an AEAD tag
  failure — one indistinguishable "authenticated decryption failed" outcome.

---

## 6. DEK wrapping — the age boundary

### 6.1 One blob per (cell, recipient)

Each DEK is wrapped **per recipient as a separate single-recipient age
operation**: one small age file per (cell, recipient), payload exactly the 32
raw DEK bytes, exactly one recipient stanza. Separate files mean scrypt,
X25519, and plugin recipients never share an age header (this sidesteps age's
mixed-recipient-and-passphrase restriction; verified against age 0.11.x). The
binary age file is base64-encoded onto the `wrap` line (§4.6).

Unwrap MUST read exactly 32 bytes from the age decryptor's reader into a
locked/zeroizing buffer (`read_exact`-style) — never via a convenience API
that returns plaintext in an ordinary heap allocation. A wrap whose decrypted
payload is not exactly 32 bytes is invalid.

### 6.2 scrypt posture

- **Encrypt side**: the work factor is clamped to `log_n ∈ [20, 22]` and
  recorded in the header (`kind = scrypt:<log_n>`).
- **Decrypt side**: implementations MUST enforce a fixed maximum work factor
  of 2^22 on every scrypt unwrap **regardless of the header field** — the
  fixed cap, not the attacker-writable header value, is the operative
  anti-tamper/anti-DoS control. A blob demanding more (e.g. a hostile
  `log_n = 30`) fails with an "excessive work" outcome surfaced as "tampered
  or unsupported work factor".
- Passphrases are generated by default (diceware, ≥ 90 bits of entropy);
  accepting a user-chosen passphrase requires an explicit flag plus a strength
  gate. (CLI behavior; recorded here because it constrains what a conforming
  writer may enroll.)

### 6.3 The unwrap loop (frozen classification rule)

To open cell C with a set of identities, iterate identities against C's wrap
blobs (each blob single-recipient):

- "no matching key" for a blob ⇒ try the next identity/blob; never an error by
  itself.
- decryption failure on a **scrypt** blob ⇒ wrong passphrase or tampered blob
  (safe to interpret: the blob has exactly one recipient). Record that a wrong
  passphrase was seen, **continue the loop** — a wrong passphrase never aborts
  it — and if the loop ends without success, surface "no matching identity"
  together with a re-prompt hint.
- success ⇒ verify the DEK commitment (§5.4), then decrypt the body (§5).

---

## 7. HB1 — cell body plaintext grammar

Hand-rolled canonical length-prefixed binary. All integers **little-endian,
fixed width**. No self-description, no padding, no alignment. The golden
vectors of §11.2 are byte-exact.

```
cell-plaintext = record_count:u32  record*        ; record_count records follow

record:
  name_len:      u16                              ; 1..=128
  name:          name_len bytes UTF-8, charset [A-Za-z0-9_.-]
  tier:          u8                               ; MUST equal the cell's tier
  mode:          u8                               ; §7.1
  guarantee:     u8                               ; §7.1
  created_at:    i64                              ; unix seconds
  updated_at:    i64
  rotated_at:    i64
  ra_flag:       u8                               ; 0 or 1; anything else = parse error
  rotate_after:  i64                              ; present iff ra_flag == 1; seconds
  meta_count:    u16
  meta_entry*:                                    ; meta_count entries, sorted by key bytes asc
    key_len:     u16                              ; ≥1
    key:         key_len bytes UTF-8
    value_len:   u32
    value:       value_len bytes UTF-8
  value_len:     u32
  value:         value_len raw bytes              ; the secret; arbitrary bytes, may be empty
```

Rules:

- Records are sorted by raw `name` bytes ascending; a duplicate name is a
  parse error. `name` charset is `[A-Za-z0-9_.-]`, length 1–128 bytes.
- `tier` MUST equal the containing cell's tier; mismatch is a parse error
  (defense in depth — the cell identity is already authenticated by the AAD).
- Metadata entries are sorted by raw key bytes ascending; duplicate keys are a
  parse error. Keys are non-empty valid UTF-8; metadata **values MUST be valid
  UTF-8** (they are represented as JSON strings in the recovery blob —
  Appendix A.8). Metadata is non-secret only.
- `rotate_after` is a duration in seconds: the intended maximum age of the
  value, measured from `rotated_at` (a record is overdue when
  `now > rotated_at + rotate_after`).
- Every length field MUST be bounds-checked against the remaining buffer.
  After the last record there MUST be no trailing bytes; a parse MUST consume
  the buffer exactly.
- The minimum body is the 4 bytes `00 00 00 00` (`record_count = 0`).

### 7.1 `mode` and `guarantee` discriminants (frozen)

These byte values are frozen for schema 1; the kebab-case names are used
wherever a mode/guarantee is rendered as text (recovery blob, manifest, CLI):

| mode byte | name |
|---|---|
| 0 | `generic` |
| 1 | `env-var` |
| 2 | `ssh-key` |
| 3 | `api-key` |

| guarantee byte | name |
|---|---|
| 0 | `unassigned` |
| 1 | `brokered-resign` |
| 2 | `brokered-derived` |
| 3 | `brokered-header` |
| 4 | `brokered-sign` |
| 5 | `injected-env` |

Any other byte value in either field is a parse error for schema 1
(Appendix A.9).

### 7.2 Reserved metadata keys

Metadata keys beginning with the prefix `envholster.` are **reserved**.
Schema 1 defines exactly one:

- `envholster.needs-rotation`, value exactly the 1-byte string `1` — present
  iff the record is flagged as needing value rotation (set when a recipient
  that could reach the record is removed). When the flag is clear the entry is
  **absent**; a writer MUST NOT emit it with any other value, and a parser
  MUST reject any other value (canonicality).

Writers MUST NOT emit any other `envholster.`-prefixed key, and parsers MUST
reject unknown reserved keys (a new reserved key requires a schema bump —
Appendix A.10). Caller-supplied metadata under the reserved prefix is refused
at the API/CLI layer, so reserved entries can never collide with user data.

### 7.3 Handling constraint (normative for envholster, informative for interop)

HB1 plaintext is assembled and parsed only inside locked memory
(the `envholster-mem` crate); no serde or other reflective serializer touches any
encrypted path — HB1 and the header are hand-written encodings. A foreign
implementation interoperates without adopting these memory rules, but MUST
produce and accept the exact bytes above.

---

## 8. Save and open algorithms; durability

### 8.1 Writer (save) — normative sequence

Precondition: the DEK of **every** occupied cell is available (see §5.2), the
advisory lock of §8.3 is held, and generation G is the value read at open.

1. For each occupied cell, serialize its records to HB1 (§7); record
   `ct-len` = plaintext byte length.
2. Draw a fresh 24-byte nonce per cell.
3. Compute/reuse each cell's wrap set: reuse existing wrap blobs verbatim
   unless the DEK or the recipient set changed for that cell, in which case
   produce new single-recipient blobs for exactly the eligible set (§2.5).
4. Assemble the complete canonical header core with `generation = G + 1` and
   every cell's commitment, new nonce, `ct-len`, and wraps. (Everything in
   the core is known before any encryption happens.)
5. For each cell: encrypt the HB1 plaintext in place under its DEK with
   `AAD(e, t)` per §5.2, detaching the 16-byte tag.
6. Emit the full file: header core, `[tags]` section, body blocks.
7. Durably replace the vault: write to a temp file **in the same directory**,
   `fsync` the file, atomically `rename` over `secrets.holster`, `fsync` the
   directory.
8. Produce the recovery blob for the identical store snapshot (same
   generation G + 1; RECOVERY-SPEC.md) and durably replace
   `secrets.holster.recovery.age` the same way — **vault first, then recovery
   blob**. Writers SHOULD fully prepare and fsync both temp files before
   performing either rename, so that any preparation failure aborts the save
   with both files untouched (Appendix A.11).
9. The save **fails closed** if the recovery blob cannot be written: the save
   MUST be reported as failed. If failure strikes between the two renames, the
   resulting vault/blob generation drift is detectable and is flagged by
   `doctor`; the next successful save restores lockstep.

File modes: newly created vault/blob files `0600`, directories `0700` (§1).

### 8.2 Reader (open) — normative sequence

1. Read the file. Verify the magic line. Parse strictly per §3–§4: any
   non-canonical byte, ordering violation, duplicate, structural mismatch
   (tag/body count or order vs cell blocks, base64 decode length ≠ `ct-len`),
   class/kind inconsistency, recovery-recipient violation, or trailing bytes
   is a parse failure. Equivalent check: re-serialize the parse result and
   byte-compare to the input.
2. Enforce schema (§10) and the kind allowlist (§2.6).
3. To read cell (e, t): run the unwrap loop (§6.3) over the supplied
   identities; verify the DEK commitment (§5.4); base64-decode the body;
   decrypt in place with `AAD(e, t)` and the detached tag; parse HB1 (§7).
4. Tag failure and commitment failure are indistinguishable to callers.

### 8.3 Concurrency

An exclusive advisory `flock` on the vault file is held across the whole
open–modify–save window (concurrent `envholster add` invocations must not lose
an update). Because rename replaces the inode, after acquiring the lock a
writer MUST re-check that its locked file descriptor still corresponds to the
vault path (compare `stat(path)` and `fstat(fd)` device+inode) and re-open and
re-read if not (Appendix A.12).

Concurrent git-branch edits produce a binary conflict at the cell body —
expected; interim guidance is to serialize vault edits (a record-level merge
driver is a later-phase deliverable).

---

## 9. Generation counter — honest scope

`generation` is a u64, incremented by exactly 1 per save, and AAD-covered.
What it buys **at the envelope layer alone**: header/body and cross-generation
mix-and-match **within a file** fail decryption. Whole-file rollback to an
older commit is **undetectable by the file itself** — stated plainly. (Daemon
last-seen-generation tracking and git-side monotonicity checks are later-phase
layers; no claim is made here.)

The recovery blob carries the same generation and is written in lockstep
(§8.1); vault/blob generation drift is a `doctor` finding.

---

## 10. Migration policy (frozen from schema 1)

- **Readers hard-refuse newer schemas**: a schema-N reader encountering
  schema N+1 fails with "vault from a newer version — upgrade envholster"
  (naming the explicit `envholster migrate` command once schema 2 exists). It
  never partially parses, skips, or guesses.
- **Writers never downgrade** a vault's schema, silently or otherwise.
- **Migration is only ever the explicit `envholster migrate` command.** No
  read or save path changes a vault's schema as a side effect.
- Mechanism backing the policy: the `schema` field sits in the header core and
  is therefore inside every cell's AAD from schema 1 — a downgrade flip makes
  every body fail decryption.
- Rotation ≠ revocation (applies across schema changes too): every historical
  commit remains decryptable forever via the old wraps in git history; a
  removed recipient's exposure is closed only by rotating the affected secret
  values at their providers.

---

## 11. Golden vectors (interop contract)

The fixtures below live under `crates/envholster-core/tests/golden/` and are
the interop contract between independent implementations: implementation B
passing them against files produced by implementation A (and vice versa) is
the acceptance test. Vault fixtures are generated once by a
maintainer-invoked generator in the reference implementation and are
regenerated only when this document changes; HB1 fixtures are exact
bytes defined right here. Golden tests use the standard library only (byte
reads and comparisons; the age/AEAD operations go through the crate's own
regular dependencies).

Fixture identities, DEKs, nonces, and uuids are whatever bytes the checked-in
files contain; the **logical content** of each vault is pinned below and its
`expected.json` (the canonical-JSON rendering of the full store, exactly as
defined in RECOVERY-SPEC.md §3) is the byte-exact expectation for both the
decrypted vault content and the decrypted recovery blob.

### 11.1 Directory listing

```
crates/envholster-core/tests/golden/
  hb1/
    empty-cell.bin            two-records.bin           two-records.fields.txt
    bad-unsorted.bin          bad-dup-name.bin          bad-dup-meta.bin
    bad-tier-mismatch.bin     bad-flag.bin              bad-trailing.bin
  vault-basic/
    secrets.holster           secrets.holster.recovery.age
    software.identity         recovery.identity         expected.json
  vault-named/
    secrets.holster           secrets.holster.recovery.age
    software.identity         recovery.identity         expected.json
  vault-scrypt/
    secrets.holster           secrets.holster.recovery.age
    passphrase.txt            recovery.identity         expected.json
  vault-tier2/
    secrets.holster           secrets.holster.recovery.age
    software.identity         recovery.identity         expected.json
  negative/
    schema2.holster           unknown-kind.holster      unknown-plugin.holster
    dup-recipient.holster     mixed-wildcard.holster    noncanonical-header.holster
    tampered-generation.holster                         tampered-body.holster
    swapped-cells.holster     bad-commitment.holster    trailing-bytes.holster
```

(All fixture secret values are sentinels; nothing real is ever committed.)

### 11.2 HB1 byte vectors (exact bytes, defined here)

**`hb1/empty-cell.bin`** — exactly 4 bytes:

```
00 00 00 00
```

Proves: the minimal legal body (`record_count = 0`).

**`hb1/two-records.bin`** — the following 154 bytes exactly (parse with cell
tier = 1). Field-by-field annotation; `two-records.fields.txt` restates this
annotation in the repo:

```
02 00 00 00                                        record_count = 2

; record 1 — name "ALPHA"
05 00                                              name_len = 5
41 4c 50 48 41                                     "ALPHA"
01                                                 tier = 1
01                                                 mode = 1 (env-var)
00                                                 guarantee = 0 (unassigned)
00 b9 55 69 00 00 00 00                            created_at = 1767225600
00 b9 55 69 00 00 00 00                            updated_at = 1767225600
00 b9 55 69 00 00 00 00                            rotated_at = 1767225600
00                                                 ra_flag = 0 (no rotate_after)
00 00                                              meta_count = 0
05 00 00 00                                        value_len = 5
61 6c 70 68 61                                     value = "alpha"

; record 2 — name "BETA"
04 00                                              name_len = 4
42 45 54 41                                        "BETA"
01                                                 tier = 1
03                                                 mode = 3 (api-key)
05                                                 guarantee = 5 (injected-env)
00 b9 55 69 00 00 00 00                            created_at = 1767225600
01 b9 55 69 00 00 00 00                            updated_at = 1767225601
02 b9 55 69 00 00 00 00                            rotated_at = 1767225602
01                                                 ra_flag = 1
00 a7 76 00 00 00 00 00                            rotate_after = 7776000
02 00                                              meta_count = 2
19 00                                              key_len = 25
65 6e 76 68 6f 6c 73 74 65 72 2e 6e 65 65 64 73
2d 72 6f 74 61 74 69 6f 6e                         "envholster.needs-rotation"
01 00 00 00                                        value_len = 1
31                                                 "1"
08 00                                              key_len = 8
70 72 6f 76 69 64 65 72                            "provider"
07 00 00 00                                        value_len = 7
65 78 61 6d 70 6c 65                               "example"
03 00 00 00                                        value_len = 3
00 ff 10                                           value (binary)
```

Proves: little-endian fixed widths, name sort order (`ALPHA` < `BETA`), the
`rotate_after` presence flag in both states, metadata key sorting and the
reserved `envholster.needs-rotation` entry, and binary-safe values. Round-trip
requirement: parse → re-encode MUST reproduce the bytes exactly.

**Negative HB1 vectors** (each MUST be rejected):

| File | Defect |
|---|---|
| `bad-unsorted.bin` | `two-records.bin` with the two records swapped |
| `bad-dup-name.bin` | two records both named `ALPHA` |
| `bad-dup-meta.bin` | record 2 with `provider` listed twice |
| `bad-tier-mismatch.bin` | record 1's tier byte set to `02` (parsed for a tier-1 cell) |
| `bad-flag.bin` | record 1's `ra_flag` set to `02` |
| `bad-trailing.bin` | `two-records.bin` plus one trailing `00` byte |

### 11.3 Vault vectors (logical content pinned)

Common to all: timestamps `1767225600` (2026-01-01T00:00:00Z) unless stated;
`saved_at` in each blob = `1767225600`; every record's guarantee = 0
(unassigned) except where the HB1 vector above differs.

**`vault-basic/`** — generation **3**. Recipients: software x25519
(label `golden software`, `enroll = *:1`) and recovery x25519
(label `golden recovery`, `enroll = *:3`). Cells:

- (base, 1): record `ALPHA` — mode `env-var`, value `golden-alpha-value`,
  no rotate_after, no metadata.
- (prod, 1): record `API_KEY` — mode `api-key`, value
  `golden-api-key-value`, rotate_after 7776000, metadata
  `provider = example`; record `DB_PASSWORD` — mode `api-key`, value
  `golden-db-password`, metadata `envholster.needs-rotation = 1`.

Proves: full header grammar including a **wildcard-enrolled recipient**
(required by §3), byte-identical re-serialization, AAD assembly,
unwrap via a software identity AND via the recovery identity, commitment
verification, HB1 decode, generation > 1, and blob lockstep (blob generation
= 3; `expected.json` matches both the vault content and the `age -d` output
byte-exactly). This directory is also the CI cold-recovery-drill fixture
(RECOVERY-SPEC.md §7).

**`vault-named/`** — generation 1. Recipients: software x25519 with
`enroll = dev:1,prod:1` (named list) and recovery. Cells: (dev, 1) with record
`DEV_TOKEN` (mode `api-key`, value `golden-dev-token`); (staging, 1) with
record `STG_TOKEN` (mode `api-key`, value `golden-stg-token`) — wrapped **to
recovery only** (the software recipient is not enrolled for `staging`).
Proves: named-list enrollment grammar, per-env wrap scoping (the software
identity unwraps `dev` but ends in "no matching identity" on `staging`;
recovery unwraps both), and that the eligible set is per-cell.

**`vault-scrypt/`** — generation 1. Recipients: scrypt
(`kind = scrypt:20`, label `golden passphrase`, `enroll = *:1`, **no
`encoding` line**, random 16-hex id) and recovery. Cell (base, 1) with record
`SCRYPT_SECRET` (mode `generic`, value `golden-scrypt-value`).
`passphrase.txt` holds the fixture passphrase
(`golden-fixture-passphrase-do-not-reuse`, LF-terminated). Proves: scrypt
enrollment encoding (omitted `encoding` line, `log_n` in `kind`), scrypt wrap
unwrapping under the decrypt-side work cap, and the §6.3 loop classification
(a wrong passphrase yields the continue-and-hint behavior, not an abort).
`log_n = 20` (the minimum) keeps CI cost bounded.

**`vault-tier2/`** — generation 1. Recipients: hardware plugin
(`kind = plugin:yubikey`, label `golden yubikey`, `enroll = *:3`), software
x25519 (`enroll = *:1`), recovery. Cells: (prod, 1) with record `LOW` (mode
`generic`, value `golden-low-value`) wrapped to all three; (prod, 2) with
record `HIGH` (mode `generic`, value `golden-high-value`) wrapped to
**hardware + recovery only**. Proves: plugin-recipient header parsing, the
wrap matrix on disk (a tier-2 cell carries no software wrap), and the gate
"a software identity cannot unwrap a tier ≥ 2 cell" — the software identity
opens (prod, 1) and ends in "no matching identity" on (prod, 2); the recovery
identity opens both. The hardware wrap blob is produced at fixture-generation
time with the plugin available; CI never unwraps it (no hardware in CI) — the
hardware path is covered by the standing human hardware checklist.

### 11.4 Negative vault vectors (each MUST fail as stated)

All derived from `vault-basic` unless noted. "Fails decrypt" means the header
parses canonically but authenticated decryption fails for every cell/identity;
"parse error" means the file is rejected before any cryptography.

| File | Mutation | Required outcome |
|---|---|---|
| `schema2.holster` | `schema = 2` | refused: "vault from a newer version" (§10) |
| `unknown-kind.holster` | a recipient with `kind = mlkem768` | refused: unknown recipient kind (§2.6) |
| `unknown-plugin.holster` | `kind = plugin:tpm` | refused: plugin not allowlisted (§2.6) |
| `dup-recipient.holster` | two recipient blocks with the same id | parse error |
| `mixed-wildcard.holster` | `enroll = *:1,dev:1` | parse error (§4.5) |
| `noncanonical-header.holster` | two spaces around one `=` | parse error (§3.1) |
| `tampered-generation.holster` | `generation = 3` edited to `4` | header parses; every cell fails decrypt (AAD) |
| `tampered-body.holster` | one body byte flipped (still valid base64, same length) | that cell fails decrypt |
| `swapped-cells.holster` | two equal-`ct-len` bodies swapped between cells (built from a variant of vault-basic whose two cells carry equal-length plaintexts) | both cells fail decrypt (AAD cell suffix) |
| `bad-commitment.holster` | one `commitment` value altered | unwrap succeeds; open fails with the same indistinguishable outcome as a tag failure (§5.4) — and note the AAD change alone already fails the body |
| `trailing-bytes.holster` | one byte appended after the final body line | parse error |

### 11.5 What the golden suite proves, in one line each

- HB1 vectors: the body grammar, byte-exact, both directions.
- `vault-basic`: the whole envelope round-trip plus recovery lockstep.
- `vault-named`: enrollment scoping is cryptographic, not cosmetic.
- `vault-scrypt`: the passphrase path and its work-factor posture.
- `vault-tier2`: the wrap matrix (G-A) holds on disk.
- `negative/*`: canonical strictness and AAD coverage actually reject what
  they claim to reject.

---

## Appendix A — Resolved ambiguities (binding for schema 1)

Where the original design left a byte-level question open, this spec pins the
answer a clean-room implementer needs; each resolution below is forced (or
most directly implied) by the design's other constraints, and is binding.

1. **scrypt `encoding` line is omitted, not empty.** the design said "empty
   for scrypt", but an empty value cannot be canonically encoded: `encoding = `
   would end in a trailing space (forbidden) and `encoding =` would break the
   one-space-around-`=` rule. Omission is the only encoding compatible with
   canonicality, and matches the implementation's `encoded: Option<String>` (None
   only for scrypt).
2. **Labels are non-empty and trimmed.** Same canonicality forcing: an empty
   or space-terminated label would create a trailing-whitespace line.
3. **Readers check wrap legality, writers check wrap completeness.** Writers
   validate the wrap set on every save; readers additionally reject
   matrix-illegal wraps (cheap, header-local) but treat an *incomplete*
   eligible set as a diagnostic, not a parse failure.
4. **Wrap blobs are binary age files.** They are already base64-wrapped by the
   header line; armoring inside base64 would be double-encoding. The recovery
   blob (a standalone file) is the armored one.
5. **A fresh vault's first on-disk generation is 1.** "Increments by exactly 1
   per save" + creation-is-the-first-save.
6. **vault-uuid is 16 CSPRNG bytes, hyphen-formatted.** The dependency set
   contains no uuid crate and the implementation type is a bare `[u8; 16]`; no RFC 4122
   version bits are claimed or checked.
7. **Blank-line and empty-section rules** (§3.1–§3.2): one blank line before
   every block heading and the core-end marker; none before `[tags]`; the
   `[tags]` line is present even with zero cells. Pinned so that "exactly one
   accepted byte sequence" is decidable.
8. **HB1 metadata values MUST be UTF-8** even though the wire type is raw
   bytes — forced by the recovery blob, which renders metadata as JSON
   strings, and by the implementation's `BTreeMap<String, String>`.
9. **Unknown mode/guarantee bytes are parse errors in schema 1.** The
   discriminant tables are frozen per schema; new values require a schema
   bump (consistent with the §10 policy and the fail-closed posture for
   unknown recipient kinds).
10. **Unknown reserved metadata keys are parse errors.** The reserved
    namespace is versioned by schema, like everything else.
11. **Lockstep vs write ordering** (§8.1): prepare-both-then-rename-vault-first
    reconciles "save fails closed without the blob" with "vault first, then
    recovery blob"; a failure window between the renames
    remains and is exactly what the `doctor` generation-drift check exists
    for.
12. **flock + rename race**: after acquiring the advisory lock, re-verify the
    locked fd still names the path (dev+inode) — otherwise a writer that
    queued behind a completed save would operate on a stale inode.
