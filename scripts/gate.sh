#!/usr/bin/env bash
# Local quality gate — the same checks CI runs (AGENTS.md). Run after every
# change, before reporting done. A SKIP is not a pass.
#
#   G0  dependency edits are human-approved (root Cargo.toml / Cargo.lock)
#   G1  cargo fmt --all --check
#   G2  cargo build --workspace --locked
#   G3  cargo test --workspace --locked
#   G4  cargo clippy --workspace --all-targets --locked -- -D warnings
#   G5  cargo deny check
#   G6  cargo audit
#   G7  every crate forbids unsafe code (envholster-mem excepted: it is the
#       one place that must call mlock/madvise)
#   G8  scripts/recovery-drill.sh (age + jq only, zero envholster code)
#   G9  signed installer fixtures and the real onboarding terminal flow
set -u
cd "$(dirname "$0")/.."

PASS=0; FAIL=0; SKIP=0
banner() { printf '\n== %s ==\n' "$1"; }
section_pass() { PASS=$((PASS + 1)); printf 'PASS  %s\n' "$1"; }
section_fail() { FAIL=$((FAIL + 1)); printf 'FAIL  %s\n' "$1"; }
section_skip() { SKIP=$((SKIP + 1)); printf 'SKIP  %s — %s\n' "$1" "$2"; }
run_section() {
    local name="$1"; shift
    banner "$name"
    if "$@"; then section_pass "$name"; else section_fail "$name"; fi
}

# --- G0: dependency changes are human-approved -----------------------------
# A diff to the root Cargo.toml or Cargo.lock against the merge base must be
# signed off: ENVHOLSTER_DEPENDENCY_SIGNOFF="<who>: <why>" in the environment,
# or a `Dependency-Change-Approved-By:` trailer on a commit in the range.
g0() {
    # Fail CLOSED: without history to compare against, the check cannot
    # run, and "cannot run" must not read as "nothing changed". CI fetches
    # full history (fetch-depth: 0) for exactly this reason.
    local base
    base="$(git merge-base HEAD origin/main 2>/dev/null || true)"
    if [ -z "$base" ]; then
        base="$(git rev-parse --verify HEAD~1 2>/dev/null || true)"
    fi
    if [ -z "$base" ]; then
        echo "REFUSED: no merge base with origin/main and no parent commit (shallow"
        echo "  checkout?). Fetch history: git fetch --unshallow origin main"
        return 1
    fi
    local committed working
    if ! committed="$(git diff --name-only "$base" -- Cargo.toml Cargo.lock)"; then
        echo "REFUSED: git diff against $base failed"
        return 1
    fi
    if ! working="$(git diff --name-only -- Cargo.toml Cargo.lock)"; then
        echo "REFUSED: git diff of the working tree failed"
        return 1
    fi
    local changed
    changed="$(printf '%s\n%s\n' "$committed" "$working" | sed '/^$/d' | sort -u)"
    if [ -z "$changed" ]; then
        echo "no dependency file changed since $base"
        return 0
    fi
    echo "dependency files changed since $base:"; echo "$changed" | sed 's/^/  /'
    if [ -n "${ENVHOLSTER_DEPENDENCY_SIGNOFF:-}" ]; then
        echo "sign-off (env): $ENVHOLSTER_DEPENDENCY_SIGNOFF"
        return 0
    fi
    if git log --format=%B "$base"..HEAD 2>/dev/null | grep -q '^Dependency-Change-Approved-By:'; then
        echo "sign-off (commit trailer):"
        git log --format=%B "$base"..HEAD | grep '^Dependency-Change-Approved-By:' | sed 's/^/  /'
        return 0
    fi
    echo "REFUSED: Cargo.toml/Cargo.lock changed without a human sign-off."
    echo "  Either export ENVHOLSTER_DEPENDENCY_SIGNOFF=\"<name>: <why>\" or add a"
    echo "  'Dependency-Change-Approved-By: <name>' trailer to the commit."
    return 1
}
run_section "G0 dependency sign-off" g0

run_section "G1 rustfmt" cargo fmt --all --check
run_section "G2 build" cargo build --workspace --locked
run_section "G3 tests" cargo test --workspace --locked
run_section "G4 clippy" cargo clippy --workspace --all-targets --locked -- -D warnings

banner "G5 cargo-deny"
if command -v cargo-deny >/dev/null 2>&1; then
    if cargo deny check; then section_pass "G5 cargo-deny"; else section_fail "G5 cargo-deny"; fi
else
    section_skip "G5 cargo-deny" "cargo-deny not installed (cargo install --locked cargo-deny)"
fi

banner "G6 cargo-audit"
if command -v cargo-audit >/dev/null 2>&1; then
    if cargo audit; then section_pass "G6 cargo-audit"; else section_fail "G6 cargo-audit"; fi
else
    section_skip "G6 cargo-audit" "cargo-audit not installed (cargo install --locked cargo-audit)"
fi

# --- G7: forbid(unsafe_code) everywhere but envholster-mem -----------------
g7() {
    local ok=0
    for lib in crates/*/src/lib.rs crates/*/src/main.rs; do
        [ -f "$lib" ] || continue
        case "$lib" in crates/envholster-mem/*) continue ;; esac
        if grep -q '^#!\[forbid(unsafe_code)\]' "$lib"; then
            echo "ok   $lib"
        else
            echo "MISSING forbid(unsafe_code): $lib"; ok=1
        fi
    done
    # No crate besides envholster-mem may contain an unsafe block, fn, or impl
    # (the word alone appears in comments that explain this very rule).
    if grep -rn --include='*.rs' -E 'unsafe (\{|fn |impl )' crates/envholster-core crates/envholster; then
        echo "unsafe code outside envholster-mem"; ok=1
    fi
    return $ok
}
run_section "G7 forbid(unsafe_code)" g7

banner "G8 recovery drill"
if command -v age >/dev/null 2>&1 || [ -n "${ENVHOLSTER_AGE_BIN:-}" ]; then
    if command -v jq >/dev/null 2>&1; then
        if scripts/recovery-drill.sh; then section_pass "G8 recovery drill"; else section_fail "G8 recovery drill"; fi
    else
        section_skip "G8 recovery drill" "jq not installed"
    fi
else
    section_skip "G8 recovery drill" "age CLI not installed (set ENVHOLSTER_AGE_BIN or install age)"
fi

banner "G9 install and onboarding"
if command -v python3 >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1; then
    if python3 scripts/test-install.py && python3 scripts/test-setup-ui.py; then
        section_pass "G9 install and onboarding"
    else
        section_fail "G9 install and onboarding"
    fi
else
    section_skip "G9 install and onboarding" "python3 and openssl are required"
fi

printf '\n== summary: %d pass, %d fail, %d skip ==\n' "$PASS" "$FAIL" "$SKIP"
if [ "$SKIP" -gt 0 ]; then echo "a SKIP is not a pass — install the missing tool and re-run"; fi
# A SKIP is a check that did not run; the gate only passes when every check ran and passed.
[ "$FAIL" -eq 0 ] && [ "$SKIP" -eq 0 ]
