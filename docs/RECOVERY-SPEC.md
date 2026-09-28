# RECOVERY-SPEC — envholster printed-kit recovery (frozen)

Status: **frozen for schema 1.** This document is normative for the recovery
blob (`secrets.holster.recovery.age`), the disaster-recovery procedure, the
init ceremony, and the CI cold-recovery drill. The envelope details it depends
on are specified in `ENVELOPE-SPEC.md`. Encoding changes require an explicit
edit to both documents. The v1 launch verification clarification below
strengthens checking without changing any encoded bytes or cold-recovery
commands. This specification is complete on its own.

**This document is printed into every recovery kit.** It is written to be
usable by a person holding only the kit, the repository, and a computer with
the `age` and `jq` command-line tools — **zero envholster code required**.

The key words MUST, MUST NOT, SHOULD, and MAY are as in RFC 2119.

---

## 1. The recovery recipient

Every vault has **exactly one** recovery recipient: an age X25519 identity
(`AGE-SECRET-KEY-1…`) that exists **only on paper or removable media — never
on an enrolled machine's disk**. It is enrolled for every environment at the
maximum tier (`enroll = *:3` in the vault header), and every cell's DEK is
wrapped to it; `envholster doctor` scans known identity paths and flags the
recovery identity if it is ever found on disk.

**Honest scope, stated plainly:** whoever holds the recovery identity can
decrypt *everything* — every environment, every tier, and (via git history)
every past generation of the vault. Guard the kit accordingly. Losing the kit
does not lose your data while enrolled machine identities still work, but a
vault whose recovery identity is lost cannot be recovered after machine loss —
which is why the `recovery create` ceremony (§5) refuses to complete without proof the
stored identity works.

**Fingerprint** (used throughout this document): the recovery recipient's
16-lowercase-hex recipient id, computed exactly as in ENVELOPE-SPEC.md §2.3 —
the first 8 bytes of `SHA-256("envholster-v1-rcpt:" ‖ <the full age1…
recipient string>)`. It appears in the vault header as the recovery
recipient's block id, so a kit can always be matched to its vault by eye.

Until `envholster recovery create` has run, `init` keeps the freshly generated recovery identity at `~/.config/envholster/recovery/<vault-uuid>.identity` (0600). `doctor` reports that file as a finding until it is gone. `recovery create` moves it to paper or removable media, proves the round trip, and deletes it.

---

## 2. The recovery blob — `secrets.holster.recovery.age`

A sibling file of the vault, committed to the repository alongside it.

- It is a **true armored age file** (`-----BEGIN AGE ENCRYPTED FILE-----` …
  `-----END AGE ENCRYPTED FILE-----`, LF line endings), encrypted to the
  recovery recipient **only** (exactly one recipient), decryptable by vanilla
  `age -d` with no envholster code whatsoever.
- Its plaintext is the canonical JSON (§3) of the **full store**: every
  environment, every tier, every record, values included.
- **Lockstep (fail-closed):** the blob is rewritten on **every** vault save,
  carrying the same `generation` as the vault; a save that cannot write the
  blob MUST be reported as failed. Vault-vs-blob generation drift is a
  `doctor` finding. Because the blob is re-encrypted per save, recovery
  recipient changes rotate it automatically. Write ordering and atomicity:
  ENVELOPE-SPEC.md §8.1 (temp file + fsync + rename + directory fsync, vault
  first, then blob).

Note the blob is assembled inside locked memory and streamed into the age
encryptor (an envholster implementation obligation, see the `envholster-mem`
crate; irrelevant to a recovery operator, who only ever decrypts).

---

## 3. Canonical JSON layout (frozen)

The blob plaintext is canonical JSON: **UTF-8; object keys sorted
lexicographically by their raw bytes; no insignificant whitespace (no spaces,
no newlines between tokens); no trailing newline after the closing `}`;
integers in plain decimal (no exponent, no leading zeros, `-` only for
negatives, full 64-bit range written exactly); strings minimally escaped**
(`"` → `\"`, `\` → `\\`, control characters U+0000–U+001F as `\b \t \n \f \r`
where those short forms exist, otherwise `\u00xx` with lowercase hex; all
other characters emitted literally as UTF-8). For any store there is exactly
one valid encoding; golden tests byte-compare it.

Top-level object (keys shown in their sorted order):

```json
{
  "envs":       { "<env>": { "<tier>": { "<record-name>": <record> } } },
  "generation": <u64 — matches the vault header>,
  "saved_at":   <i64 unix seconds of the save that wrote this blob>,
  "schema":     1,
  "vault_uuid": "<lowercase hyphenated uuid — matches the vault header>"
}
```

- `envs` contains one key per environment that has at least one cell; each
  environment maps tier strings (`"1"`, `"2"`, `"3"` — JSON keys are strings)
  to that cell's records. Every cell present in the vault appears, even if it
  currently holds zero records (empty object). Environments with no cells are
  absent.
- `<record>` (keys in sorted order):

```json
{
  "created_at":   <i64 unix seconds>,
  "guarantee":    "<kebab-case name>",
  "metadata":     { "<key>": "<value>", ... },
  "mode":         "<kebab-case name>",
  "rotate_after": <i64 seconds — PRESENT ONLY IF SET; omitted otherwise>,
  "rotated_at":   <i64 unix seconds>,
  "updated_at":   <i64 unix seconds>,
  "value":        "<standard padded base64 of the raw secret bytes>"
}
```

- `mode` and `guarantee` are written as **kebab-case string names**, never
  numbers, so the blob stays self-describing in 2036:

  | mode | guarantee |
  |---|---|
  | `generic` | `unassigned` |
  | `env-var` | `brokered-resign` |
  | `ssh-key` | `brokered-derived` |
  | `api-key` | `brokered-header` |
  |  | `brokered-sign` |
  |  | `injected-env` |

- `metadata` mirrors the record's HB1 metadata verbatim (string → string,
  key-sorted, possibly `{}`), **including** the reserved
  `envholster.needs-rotation` entry when set — the blob adds no fields of its
  own for it.
- The record's tier is its position in the tree (`envs.<env>.<tier>`), not a
  field.

### 3.1 Example

Pretty-printed here for readability ONLY — the real blob plaintext has no
whitespace.

```json
{
  "envs": {
    "base": {
      "1": {
        "ALPHA": {
          "created_at": 1767225600,
          "guarantee": "unassigned",
          "metadata": {},
          "mode": "env-var",
          "rotated_at": 1767225600,
          "updated_at": 1767225600,
          "value": "Z29sZGVuLWFscGhhLXZhbHVl"
        }
      }
    },
    "prod": {
      "1": {
        "API_KEY": {
          "created_at": 1767225600,
          "guarantee": "unassigned",
          "metadata": {"provider": "example"},
          "mode": "api-key",
          "rotate_after": 7776000,
          "rotated_at": 1767225600,
          "updated_at": 1767225600,
          "value": "Z29sZGVuLWFwaS1rZXktdmFsdWU="
        },
        "DB_PASSWORD": {
          "created_at": 1767225600,
          "guarantee": "unassigned",
          "metadata": {"envholster.needs-rotation": "1"},
          "mode": "api-key",
          "rotated_at": 1767225600,
          "updated_at": 1767225600,
          "value": "Z29sZGVuLWRiLXBhc3N3b3Jk"
        }
      }
    }
  },
  "generation": 3,
  "saved_at": 1767225600,
  "schema": 1,
  "vault_uuid": "3f2a9c10-88e2-4c5b-9d41-6b7f0a2c9e55"
}
```

(This is the logical content of the `vault-basic` golden fixture,
ENVELOPE-SPEC.md §11.3; the checked-in `expected.json` there is the canonical
single-line form.)

---

## 4. Disaster recovery — the procedure

You need: this kit; the repository (or just the two committed files
`secrets.holster.recovery.age` and, for cross-checks, `secrets.holster`); a
machine with `age` (v1.1+ or any compatible implementation) and `jq`.

**Step 1 — reconstruct the identity file.** Type the identity from the kit
(or read it from the removable media / scan the QR code) into a file:

```
$ cat > recovery-identity.txt
AGE-SECRET-KEY-1XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
^D
$ chmod 600 recovery-identity.txt
```

**Step 2 — extract one secret. The frozen one-liner:**

```
age -d -i recovery-identity.txt secrets.holster.recovery.age | jq -r '.envs.prod."3".DATABASE_URL.value' | base64 -d
```

Substitute your environment for `prod`, the tier digit for `"3"` (quotes
required — it is a JSON key), and your secret's name for `DATABASE_URL`. For
names that are not plain identifiers (they may contain `.` and `-`), use the
bracket form: `.envs.prod."3"["MY.WEIRD-NAME"].value`. On very old macOS,
`base64 -D` (capital D) replaces `base64 -d`.

**Step 3 — or dump everything:**

```
age -d -i recovery-identity.txt secrets.holster.recovery.age | jq .
```

lists the entire store (values base64); pipe individual `.value` fields
through `base64 -d` as above.

**Cross-checks** (recommended): compare `vault_uuid` and `generation` with
`secrets.holster`, and match the kit fingerprint to the recovery recipient.
These checks detect mismatches; they do not authenticate the backup contents.
Anyone with the public recovery recipient can encrypt a forged snapshot with
matching metadata. With envholster available, run `recovery verify` against the
trusted vault before relying on a snapshot. Without it, use a backup from a
trusted source and investigate discrepancies; a higher generation alone is not
proof of authenticity. A self-consistent historical pair does not prove freshness.

**Afterwards:** you have handled raw secret values on this machine. Treat the
machine as sensitive, delete `recovery-identity.txt` and any plaintext output
when done, and rotate any values you exposed beyond need.

---

## 5. The recovery ceremony (`recovery create`)

The ceremony below belongs to `envholster recovery create`, not to `init`.
`init` creates the vault immediately and parks the recovery identity on disk
(§1); `recovery create` moves it offline and MUST NOT succeed unless every step
below completes. There is no skip flag.

1. **Locate the parked identity.** `init` generated the recovery X25519 keypair,
   enrolled its recipient `*:3`, created the vault (generation 1, lockstep
   blob), and parked the identity at
   `~/.config/envholster/recovery/<vault-uuid>.identity` (0600). `recovery
   create` reads that file and checks its public key against the vault's
   recovery recipient; if the file is gone the kit already exists and the
   command refuses (`recovery verify` is the tool for an existing kit).
2. **Store offline.** The operator chooses exactly one destination (`--to
   <path>` or `--paper`, or a prompt):
   - **Removable media:** the identity is written (mode `0600`) to an
     operator-supplied path that MUST NOT be on the machine's own disk. The
     command refuses a destination on the same filesystem as HOME, the
     project, or a temp directory unless `--allow-same-disk` is passed
     explicitly (for a mount the check cannot tell apart), or
   - **Paper:** the identity is displayed **once** — Bech32
     (`AGE-SECRET-KEY-1…`) plus a QR code — for the operator to print or
     transcribe.
   After this step the identity is **never re-printable**; the kit page (§6)
   carries instructions only.
3. **Fingerprint re-entry (paper only).** The command displays the
   fingerprint (§1) and the operator MUST re-type it. A mismatch returns to
   the display step. This proves the operator actually looked at and
   recorded the material they are about to be responsible for. A file
   written to removable media needs no such proof; its round trip is step 4.
4. **Sentinel round-trip proof.** The command encrypts a random sentinel to the
   recovery *recipient*, then decrypts it using the identity **as stored**:
   - removable media: the identity file is read back from the removable path;
   - paper: the operator re-enters the full `AGE-SECRET-KEY-1…` string from
     their paper copy (this is the only way to prove the paper copy is
     correct).
   The decrypted sentinel MUST equal the original. **`recovery create` does
   not succeed without this proof** — an untested recovery path is treated
   as no recovery path.
5. **Full verification, then delete.** With ONLY the identity as stored, the
   command runs the §6 `recovery verify` check against the live vault (every
   cell's recovery wrap unwraps; the blob matches the vault). Only after that
   passes is the parked file deleted from this machine. A failure at any
   earlier step leaves the parked file in place, and `doctor` keeps reporting
   it.
6. **Print the kit** (§6).

`init --recover-from <id>` (machine loss): the same trust anchor in reverse —
the operator supplies the recovery identity, envholster proves it against the
committed vault, and re-enrolls a fresh machine identity by re-wrapping via
the recovery unwraps.

---

## 6. The printed kit

The kit MUST contain, and `envholster recovery create` MUST emit for printing:

1. the recovery **identity** — Bech32 (`AGE-SECRET-KEY-1…`) **and** QR code;
2. the **fingerprint** (§1);
3. the **vault UUID** (matches the `vault-uuid` header line);
4. a copy of **this document** (RECOVERY-SPEC.md);
5. the **one-line disaster command** of §4 verbatim;
6. the **creation date**.

`envholster recovery create` prints items 4–6 plus fingerprint and UUID once
the ceremony passes — **never the identity again**, which is shown or written
exactly once during that ceremony.

`envholster recovery verify` selects the actual recovery identity from the
explicit identity source, or asks for the stored kit identity. Explicit
`--identity` or identity environment variables exclude ambient local keys.
Verification MUST freshly unwrap each persisted cell through its recovery wrap,
verify the DEK commitment, authenticate its header and ciphertext, and decode
its records. Cached unlocks and unsaved edits MUST NOT substitute for persisted
contents.

It MUST then decrypt the recovery blob with that recovery identity and compare
its complete canonical JSON against those authenticated records: environments,
tiers, names, values, metadata, record attributes, schema, generation, and UUID.
Missing, extra, duplicated, noncanonical, or altered fields fail verification.
`saved_at` is informational: it must be a canonically encoded signed 64-bit
integer, but the primary vault stores no independent value to authenticate it
against. It is not proof of when a backup was created.

Run this check after migration and recipient changes and as a periodic recovery
drill. The current CLI supports recipient addition, not recipient removal or
provider rotation; those are not automatic revocation controls in this release.

---

## 7. CI cold-recovery drill (every gate)

The drill proves, continuously, that the committed recovery blob is
decryptable by a stranger with commodity tools. It runs in **every**
gate run — the blob is re-encrypted on every save and rotates with
recipient/DEK changes, so a one-time check would rot silently.

**Environment:** a clean container image containing only the `age` CLI, `jq`,
and coreutils (`base64`, `grep`, `cmp`). The envholster binary and source MUST
NOT be present or invoked — the container definition is the enforcement.

**Inputs:** the `vault-basic` golden fixture
(`crates/envholster-core/tests/golden/vault-basic/` — ENVELOPE-SPEC.md §11.3):
`secrets.holster`, `secrets.holster.recovery.age`, `recovery.identity`,
`expected.json`.

**Steps (all MUST pass):**

1. `age -d -i recovery.identity secrets.holster.recovery.age > store.json`
   — vanilla age decryption succeeds.
2. `cmp store.json expected.json` — the plaintext is byte-identical to the
   frozen canonical JSON.
3. For each fixture secret, the frozen one-liner recovers the exact value,
   e.g.:
   `jq -r '.envs.prod."1".API_KEY.value' store.json | base64 -d` equals
   `golden-api-key-value` (and likewise `ALPHA` and `DB_PASSWORD`).
4. Lockstep check with no envholster code:
   `jq -r .generation store.json` equals the number on the plain-text
   `generation = …` line of `secrets.holster`
   (`grep '^generation = ' secrets.holster`), and `jq -r .vault_uuid`
   likewise matches the `vault-uuid = …` line.
5. **Fresh-VM variant:** the same steps executed in a
   freshly provisioned VM/container built from public package sources only,
   proving the procedure needs nothing pre-installed beyond `age` and `jq`.

The fixture is regenerated only when ENVELOPE-SPEC.md or this document
changes; the drill therefore also detects accidental format drift in
either implementation or spec.

---

## 8. Honest limits (read before relying on this kit)

- **The blob is a snapshot.** It matches the vault generation it was saved
  with. Git history contains every prior blob; each decrypts with the same
  recovery identity.
- **Rollback is not detectable by the files themselves.** A whole-repo
  rollback to an older commit presents an older, internally consistent
  vault + blob pair (ENVELOPE-SPEC.md §9).
- **Rotation ≠ revocation.** Removing a recipient or rotating a DEK never
  makes old commits undecryptable for holders of old identities; only rotating
  the secret *values* at their providers closes exposure.
- **The recovery identity is a master key.** Its compromise is total (all
  envs, all tiers, all history). Its loss is recoverable only while enrolled
  machine identities still exist — replace the kit immediately (generate a
  new recovery identity, enroll it, remove the old one, rotate DEKs) if
  either event is suspected.
