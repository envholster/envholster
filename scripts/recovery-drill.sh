#!/usr/bin/env bash
# recovery-drill.sh — cold-recovery drill (plan/02-envelope §7; plan/08-delivery
# §8.2 standing row).
#
# Proves the disaster path: the committed fixture recovery blobs decrypt to the
# full store using ONLY the vanilla age CLI + jq — zero envholster code. This is
# the drill a user performs from the printed kit per docs/RECOVERY-SPEC.md.
#
# Fixture layout (crates/envholster-core/tests/golden/, one subdir per fixture
# vault — the same layout tests/golden.rs consumes):
#   <vault-*>/secrets.holster.recovery.age
#                                  armored age file to the recovery recipient ONLY
#   <vault-*>/recovery.identity    fixture recovery X25519 identity (test-only;
#                                  a real recovery identity NEVER lives in a repo)
#   <vault-*>/secrets.holster      fixture vault (optional here; used for the
#                                  generation-lockstep check when present)
# Every subdir of GOLDEN_DIR containing secrets.holster.recovery.age is drilled;
# a blob at the GOLDEN_DIR root (flat layout) is drilled too if present.
#
# Checks (all normative statements from plan/02 §7), run per fixture set:
#   1. `age -d -i <identity> <blob>` succeeds — true armored age file, vanilla CLI.
#   2. Payload is canonical JSON: sorted keys, no insignificant whitespace.
#   3. Shape: {schema, generation, vault_uuid, saved_at, envs -> tiers -> records}.
#   4. schema == 1; generation >= 1; vault_uuid is a lowercase hyphenated UUID.
#   5. Every record value is valid padded standard-alphabet base64 (decoded to
#      /dev/null — secret bytes are NEVER printed, fixture or not).
#   6. mode/guarantee are kebab-case string names (2036 self-description).
#   7. The RECOVERY-SPEC jq one-liner shape extracts a value end-to-end.
#   8. Lockstep: blob generation == vault header generation (when vault present).
#
# Environment overrides (for Linux CI containers where age is not a brew binary):
#   ENVHOLSTER_AGE_BIN     path to age        (default /opt/homebrew/bin/age)
#   ENVHOLSTER_JQ_BIN      path to jq         (default: jq on PATH)
#   ENVHOLSTER_GOLDEN_DIR  fixture directory  (default: crates/envholster-core/tests/golden)
#
# Exit: 0 = drill passed; non-zero = drill failed. Never prints a secret value.

set -u -o pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
AGE="${ENVHOLSTER_AGE_BIN:-/opt/homebrew/bin/age}"
JQ="${ENVHOLSTER_JQ_BIN:-jq}"
GOLDEN_DIR="${ENVHOLSTER_GOLDEN_DIR:-$REPO_ROOT/crates/envholster-core/tests/golden}"

fail() {
    echo "RECOVERY DRILL: FAIL — $*" >&2
    exit 1
}

step() {
    echo "recovery-drill: $*"
}

# --- Tooling: age CLI + jq only, nothing else -------------------------------
[ -x "$AGE" ] || fail "age CLI not found/executable at '$AGE' (override with ENVHOLSTER_AGE_BIN)"
command -v "$JQ" >/dev/null 2>&1 || fail "jq not found at '$JQ' (override with ENVHOLSTER_JQ_BIN)"
step "using age: $AGE ($("$AGE" --version 2>/dev/null || echo 'version unknown'))"
step "using jq:  $(command -v "$JQ") ($("$JQ" --version 2>/dev/null || echo 'version unknown'))"

# --- Fixture discovery --------------------------------------------------------
# Canonical layout (matches tests/golden.rs): per-vault subdirs each holding
# secrets.holster.recovery.age + recovery.identity. A flat GOLDEN_DIR with the
# blob at its root is also accepted (identity: recovery.identity, or the
# printed-kit name recovery-identity.txt).
[ -d "$GOLDEN_DIR" ] || fail "golden fixture directory missing: $GOLDEN_DIR
  The committed golden fixtures are a P0 deliverable (plan/02 §7, plan/08 §8.2)."

FIXTURE_DIRS=()
[ -f "$GOLDEN_DIR/secrets.holster.recovery.age" ] && FIXTURE_DIRS+=("$GOLDEN_DIR")
for d in "$GOLDEN_DIR"/*/; do
    [ -f "${d%/}/secrets.holster.recovery.age" ] && FIXTURE_DIRS+=("${d%/}")
done
[ "${#FIXTURE_DIRS[@]}" -ge 1 ] || fail "no fixture recovery blob found under $GOLDEN_DIR
  Expected <vault-*>/secrets.holster.recovery.age (plan/02 §7, plan/08 §8.2)."

# --- Private scratch dir; plaintext never persists ---------------------------
TMPDIR_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/envholster-recovery-drill.XXXXXX")" \
    || fail "could not create scratch directory"
chmod 700 "$TMPDIR_ROOT"
trap 'rm -rf "$TMPDIR_ROOT"' EXIT

# --- The drill: all 8 checks against one fixture set --------------------------
drill_one() {
    local DIR="$1"
    local LABEL BLOB IDENTITY VAULT TMPDIR_DRILL PLAINTEXT
    local RECORD_COUNT FIRST_ENV FIRST_TIER FIRST_NAME DECODED_LEN
    local VAULT_GEN BLOB_GEN b64 i
    LABEL="$(basename "$DIR")"
    BLOB="$DIR/secrets.holster.recovery.age"
    VAULT="$DIR/secrets.holster"
    if [ -f "$DIR/recovery.identity" ]; then
        IDENTITY="$DIR/recovery.identity"
    elif [ -f "$DIR/recovery-identity.txt" ]; then
        IDENTITY="$DIR/recovery-identity.txt"
    else
        fail "[$LABEL] fixture recovery identity missing: $DIR/recovery.identity"
    fi

    TMPDIR_DRILL="$TMPDIR_ROOT/$LABEL"
    mkdir -p "$TMPDIR_DRILL" && chmod 700 "$TMPDIR_DRILL" \
        || fail "[$LABEL] could not create scratch subdirectory"
    PLAINTEXT="$TMPDIR_DRILL/store.json"

    # --- 1. Decrypt with vanilla age -----------------------------------------
    step "[$LABEL] decrypting recovery blob with vanilla age -d ..."
    "$AGE" -d -i "$IDENTITY" "$BLOB" > "$PLAINTEXT" 2>"$TMPDIR_DRILL/age.err" \
        || fail "[$LABEL] age -d could not decrypt the recovery blob: $(cat "$TMPDIR_DRILL/age.err")"
    [ -s "$PLAINTEXT" ] || fail "[$LABEL] age -d produced an empty payload"
    step "[$LABEL] decrypt OK ($(wc -c < "$PLAINTEXT" | tr -d ' ') bytes of JSON)"

    # --- 2. Canonical JSON: sorted keys, no insignificant whitespace ---------
    # jq -cS re-emits compact JSON with lexicographically sorted keys; a
    # canonical payload must round-trip byte-identically (modulo the trailing
    # newline jq adds).
    "$JQ" -cS . "$PLAINTEXT" > "$TMPDIR_DRILL/canon.json" 2>/dev/null \
        || fail "[$LABEL] payload is not valid JSON"
    # Normalize a single trailing newline on both sides before comparing.
    printf '%s' "$(cat "$PLAINTEXT")" > "$TMPDIR_DRILL/orig.norm"
    printf '%s' "$(cat "$TMPDIR_DRILL/canon.json")" > "$TMPDIR_DRILL/canon.norm"
    cmp -s "$TMPDIR_DRILL/orig.norm" "$TMPDIR_DRILL/canon.norm" \
        || fail "[$LABEL] payload is not canonical JSON (sorted keys / no insignificant whitespace — plan/02 §7)"
    step "[$LABEL] canonical JSON OK"

    # --- 3–4. Shape and header fields -----------------------------------------
    "$JQ" -e '
        (keys == (["envs","generation","saved_at","schema","vault_uuid"] | sort)) and
        (.schema == 1) and
        ((.generation | type) == "number") and (.generation >= 1) and
        ((.saved_at   | type) == "number") and
        (.vault_uuid | test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")) and
        ((.envs | type) == "object")
    ' "$PLAINTEXT" >/dev/null \
        || fail "[$LABEL] payload shape/header check failed (need {schema:1, generation>=1, vault_uuid uuid, saved_at, envs} — plan/02 §7)"
    step "[$LABEL] shape OK: schema=1, generation=$("$JQ" -r .generation "$PLAINTEXT"), vault_uuid=$("$JQ" -r .vault_uuid "$PLAINTEXT")"

    # --- Records present; tiers are "1"/"2"/"3" keys ---------------------------
    RECORD_COUNT="$("$JQ" '[.envs[][]? | objects | keys[]] | length' "$PLAINTEXT")" \
        || fail "[$LABEL] could not enumerate records"
    [ "$RECORD_COUNT" -ge 1 ] || fail "[$LABEL] recovery blob contains zero records — fixture must exercise the full store"
    "$JQ" -e '[.envs[] | keys[]] | all(test("^[123]$"))' "$PLAINTEXT" >/dev/null \
        || fail "[$LABEL] tier keys must be \"1\"/\"2\"/\"3\" (plan/02 §7: envs -> tiers -> records)"
    step "[$LABEL] records OK: $RECORD_COUNT record(s) across $("$JQ" '.envs | length' "$PLAINTEXT") env(s)"

    # --- 5. Every value decodes as padded standard base64 (never printed) -----
    "$JQ" -e '[.envs[][][] | .value]
        | all((type == "string")
              and test("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"))' \
        "$PLAINTEXT" >/dev/null \
        || fail "[$LABEL] every record value must be a padded standard-alphabet base64 string (plan/02 §7)"
    i=0
    while IFS= read -r b64; do
        i=$((i + 1))
        printf '%s' "$b64" | base64 -d > /dev/null 2>&1 \
            || fail "[$LABEL] record value #$i is not valid standard-alphabet padded base64"
    done < <("$JQ" -r '.envs[][][] | .value' "$PLAINTEXT")
    [ "$i" -eq "$RECORD_COUNT" ] || fail "[$LABEL] expected $RECORD_COUNT values, found $i"
    step "[$LABEL] base64 values OK ($i/$RECORD_COUNT decoded, none printed)"

    # --- 6. mode/guarantee are kebab-case string names -------------------------
    "$JQ" -e '[.envs[][][] | .mode, .guarantee] | all((type == "string") and test("^[a-z0-9]+(-[a-z0-9]+)*$"))' \
        "$PLAINTEXT" >/dev/null \
        || fail "[$LABEL] mode/guarantee must be kebab-case string names (plan/02 §7 self-description)"
    step "[$LABEL] mode/guarantee self-description OK"

    # --- 7. Disaster-path one-liner shape (RECOVERY-SPEC jq pipeline) ----------
    # The printed-kit path is: age -d ... | jq -r '.envs.<env>."<tier>".<NAME>.value' | base64 -d
    # Prove that exact pipeline shape end-to-end on the first record, without
    # ever echoing the decoded bytes.
    FIRST_ENV="$("$JQ" -r '.envs | keys[0]' "$PLAINTEXT")"
    FIRST_TIER="$("$JQ" -r --arg e "$FIRST_ENV" '.envs[$e] | keys[0]' "$PLAINTEXT")"
    FIRST_NAME="$("$JQ" -r --arg e "$FIRST_ENV" --arg t "$FIRST_TIER" '.envs[$e][$t] | keys[0]' "$PLAINTEXT")"
    DECODED_LEN="$("$AGE" -d -i "$IDENTITY" "$BLOB" 2>/dev/null \
        | "$JQ" -r --arg e "$FIRST_ENV" --arg t "$FIRST_TIER" --arg n "$FIRST_NAME" '.envs[$e][$t][$n].value' \
        | base64 -d | wc -c | tr -d ' ')" \
        || fail "[$LABEL] disaster-path pipeline (age -d | jq -r '.envs...value' | base64 -d) failed"
    [ "$DECODED_LEN" -ge 1 ] || fail "[$LABEL] disaster-path pipeline produced zero bytes for envs.$FIRST_ENV.\"$FIRST_TIER\".$FIRST_NAME"
    step "[$LABEL] disaster path OK: envs.$FIRST_ENV.\"$FIRST_TIER\".$FIRST_NAME -> $DECODED_LEN plaintext byte(s) (value not shown)"

    # --- 8. Lockstep: blob generation == vault header generation (c3b) ---------
    if [ -f "$VAULT" ]; then
        VAULT_GEN="$(awk -F' = ' '/^generation = /{print $2; exit}' "$VAULT")"
        BLOB_GEN="$("$JQ" -r .generation "$PLAINTEXT")"
        [ -n "$VAULT_GEN" ] || fail "[$LABEL] fixture vault present but no 'generation = <u64>' header line found"
        [ "$VAULT_GEN" = "$BLOB_GEN" ] \
            || fail "[$LABEL] generation drift: vault=$VAULT_GEN blob=$BLOB_GEN (lockstep violated — plan/02 §7 c3b)"
        step "[$LABEL] lockstep OK: vault generation $VAULT_GEN == blob generation $BLOB_GEN"
    else
        step "[$LABEL] note: fixture vault ($VAULT) not present; lockstep check skipped"
    fi
}

for dir in "${FIXTURE_DIRS[@]}"; do
    drill_one "$dir"
done

echo "RECOVERY DRILL: PASS — ${#FIXTURE_DIRS[@]} fixture set(s) recovered with age CLI + jq only, zero envholster code"
