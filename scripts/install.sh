#!/bin/sh
# Releases embed a reviewed public key. Verify before executing downloaded code.
set -eu
umask 077
usage() {
    cat <<'EOF'
Envholster — install, then choose projects to protect.
Usage: sh install.sh [installer options] [-- setup options]
  --version vX.Y.Z  Select a signed release; omit for latest
  --root DIR       Install under DIR/bin (default ~/.local)
  --from-source    Build this checkout using locked Cargo dependencies
  --no-setup       Install only
  --no-path        Leave shell configuration untouched
  --agents APPS    Configure codex,claude,cursor explicitly
  --rollback       Restore the previous installer-managed binary
  --uninstall      Remove the managed binary and its PATH line
Setup opens automatically, including with curl | sh. Unattended example:
  -- --root ~/Projects --all --yes --recovery-dir /Volumes/Backup/keys
Vaults, identities, recovery keys and project configuration survive uninstall.
EOF
}
fail() { printf 'Envholster: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required."; }
source_checkout=yes
if [ "$source_checkout" = yes ] && [ -f "$0" ] && [ "$(basename -- "$0")" = install.sh ] && [ -f "$(dirname -- "$0")/../crates/envholster/Cargo.toml" ]; then
    binary_mode=no
    for option do case "$option" in --version|--rollback|--uninstall) binary_mode=yes ;; esac; done
    if [ "$binary_mode" = no ]; then
        [ "${1:-}" != --from-source ] || shift
        exec sh "$(dirname -- "$0")/install-source.sh" "$@"
    fi
fi
version=latest
install_root=${HOME:?HOME is required}/.local
setup_mode=interactive
selected_agents=
path_mode=auto
operation=install
while [ "$#" -gt 0 ]; do
    case "$1" in
        --root|--version|--agents)
            [ "$#" -ge 2 ] && [ -n "$2" ] || { usage >&2; exit 2; }
            case "$1" in
                --root) install_root=$2 ;;
                --version) version=$2 ;;
                --agents) [ "$setup_mode" = interactive ] || fail 'Choose --agents or --no-setup.'; selected_agents=$2; setup_mode=agents ;;
            esac
            shift 2 ;;
        --no-setup) [ "$setup_mode" = interactive ] || fail 'Choose --agents or --no-setup.'; setup_mode=skip; shift ;;
        --no-path) path_mode=skip; shift ;;
        --rollback|--uninstall) [ "$operation" = install ] || fail 'Choose one operation.'; operation=${1#--}; shift ;;
        --from-source) fail '--from-source requires a source checkout.' ;;
        --) shift; break ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
if [ -n "$selected_agents" ]; then
    case ",$selected_agents," in *,,*) fail 'Empty agent selection.' ;; esac
    remaining=$selected_agents
    while [ -n "$remaining" ]; do
        case "${remaining%%,*}" in codex|claude|cursor) ;; *) fail 'Supported agents: codex,claude,cursor.' ;; esac
        case "$remaining" in *,*) remaining=${remaining#*,} ;; *) remaining= ;; esac
    done
fi
case "$version" in latest) ;; *) printf '%s\n' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || fail 'Version must be vX.Y.Z.' ;; esac
case "$install_root" in /*) ;; *) install_root=$PWD/$install_root ;; esac
case "$install_root" in *'
'*|*':'*) fail 'Install paths cannot contain a newline or colon.' ;; esac
bin_dir=$install_root/bin
installed_binary=$bin_dir/envholster
receipt=$bin_dir/.envholster-install
previous=$bin_dir/.envholster-previous
previous_receipt=$bin_dir/.envholster-previous-install
temp_dir=
staged=
cleanup() {
    if [ -n "$temp_dir" ]; then
        for name in public.pem manifest signature binary receipt profile; do rm -f -- "$temp_dir/$name"; done
        rmdir -- "$temp_dir" 2>/dev/null || :
    fi
    [ -z "$staged" ] || rm -f -- "$staged"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
hash() { openssl dgst -sha256 "$1" | awk '{print $NF}'; }
owned() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ -f "$2" ] && [ ! -L "$2" ] || return 1
    [ "$(sed -n '1p' "$2")" = envholster-install-v1 ] || return 1
    [ "$(find "$1" -prune -links 1)" = "$1" ] && [ "$(find "$2" -prune -links 1)" = "$2" ] || return 1
    [ "$(hash "$1")" = "$(sed -n '3p' "$2")" ]
}
quote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
path_line="export PATH=$(quote "$bin_dir"):\"\$PATH\" # envholster installer"
make_temp() { temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/envholster-install.XXXXXXXX") || fail 'Cannot create private temporary storage.'; }
need openssl
if [ "$operation" != install ]; then
    owned "$installed_binary" "$receipt" || fail 'The installed binary has no matching receipt. It was left untouched.'
    make_temp
    if [ "$operation" = rollback ]; then
        owned "$previous" "$previous_receipt" || fail 'No verified previous installation is available.'
        cp "$installed_binary" "$temp_dir/binary"
        cp "$receipt" "$temp_dir/receipt"
        mv -f "$previous" "$installed_binary"
        mv -f "$previous_receipt" "$receipt"
        mv "$temp_dir/binary" "$previous"
        chmod 755 "$previous"
        mv "$temp_dir/receipt" "$previous_receipt"
        printf 'Restored Envholster %s.\n' "$(sed -n '2p' "$receipt")"
        exit 0
    fi
    for profile in "$HOME/.zshrc" "${ZDOTDIR:-$HOME}/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.bash_login" "$HOME/.profile"; do
        if [ -f "$profile" ] && [ ! -L "$profile" ] && [ "$(find "$profile" -prune -links 1)" = "$profile" ] && grep -Fqx -- "$path_line" "$profile"; then
            grep -Fvx -- "$path_line" "$profile" > "$temp_dir/profile" || [ "$?" -eq 1 ]
            cat "$temp_dir/profile" > "$profile"
        fi
    done
    rm -f -- "$installed_binary" "$receipt"
    if owned "$previous" "$previous_receipt"; then rm -f -- "$previous" "$previous_receipt"; fi
    printf '%s\n' 'Envholster uninstalled. Vaults, identities, recovery keys and project launch configuration were kept.' 'Restore wrapped scripts with envholster setup project --remove before uninstalling.'
    exit 0
fi
need curl
case "$(uname -s)/$(uname -m)" in
    Darwin/arm64) target=aarch64-apple-darwin ;;
    Darwin/x86_64) target=x86_64-apple-darwin ;;
    Linux/x86_64) target=x86_64-unknown-linux-gnu ;;
    Linux/aarch64|Linux/arm64) target=aarch64-unknown-linux-gnu ;;
    *) fail 'Supported platforms: macOS and glibc Linux, on ARM64 or x86-64.' ;;
esac
make_temp
cat > "$temp_dir/public.pem" <<'ENVHOLSTER_PUBLIC_KEY'
RELEASE_PUBLIC_KEY_NOT_CONFIGURED
ENVHOLSTER_PUBLIC_KEY
openssl pkey -pubin -in "$temp_dir/public.pem" -noout >/dev/null 2>&1 || fail 'This source template has no release trust key. Use a source checkout or the signed release installer.'
base=https://github.com/envholster/envholster/releases
download() { curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --show-error --silent --location --retry 2 --connect-timeout 20 --max-time 300 "$1" --output "$2" || fail 'Download failed; existing installation is unchanged.'; }
if [ "$version" = latest ]; then manifest_url=$base/latest/download/release-manifest.txt;
else manifest_url=$base/download/$version/release-manifest.txt; fi
printf '%s\n' 'Downloading and verifying Envholster ...'
download "$manifest_url" "$temp_dir/manifest"
selected_version=$(awk '$1 == "version" && NF == 2 {print $2}' "$temp_dir/manifest")
printf '%s\n' "$selected_version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || fail 'Invalid release version.'
[ "$version" = latest ] || [ "$selected_version" = "$version" ] || fail 'Release version mismatch.'
download "$base/download/$selected_version/release-manifest.sig" "$temp_dir/signature"
openssl dgst -sha256 -verify "$temp_dir/public.pem" -signature "$temp_dir/signature" "$temp_dir/manifest" >/dev/null 2>&1 || fail 'Release signature verification failed. Nothing was installed.'
[ "$(sed -n '1p' "$temp_dir/manifest")" = envholster-release-v1 ] || fail 'Unsupported release manifest.'
asset=envholster-$selected_version-$target
expected=$(awk -v name="$asset" '$1 == "asset" && $3 == name && NF == 3 {print $2}' "$temp_dir/manifest")
[ "${#expected}" -eq 64 ] && printf '%s\n' "$expected" | grep -Eq '^[0-9a-f]{64}$' || fail 'No unique checksum exists for this platform.'
download "$base/download/$selected_version/$asset" "$temp_dir/binary"
[ "$(hash "$temp_dir/binary")" = "$expected" ] || fail 'Binary checksum verification failed. Nothing was installed.'
if [ -e "$installed_binary" ] || [ -L "$installed_binary" ]; then
    owned "$installed_binary" "$receipt" || fail 'An existing binary has no matching receipt. Choose another --root or move that installation yourself.'
fi
if [ -e "$previous" ] || [ -e "$previous_receipt" ] || [ -L "$previous" ] || [ -L "$previous_receipt" ]; then
    owned "$previous" "$previous_receipt" || fail 'The previous-installation backup changed; it was left untouched.'
fi
if [ -e "$receipt" ] || [ -L "$receipt" ]; then
    owned "$installed_binary" "$receipt" || fail 'The installation receipt is not paired with its binary.'
fi
mkdir -p "$bin_dir"
[ ! -L "$bin_dir" ] || fail 'The installation bin directory is a symlink.'
staged=$(mktemp "$bin_dir/.envholster-new.XXXXXXXX") || fail 'Cannot create a private staging file.'
cat "$temp_dir/binary" > "$staged" || fail 'Cannot stage the verified binary.'
chmod 755 "$staged"
"$staged" --version >/dev/null || fail 'This binary cannot run on this OS. Use the source installer; the existing installation is unchanged.'
if [ -f "$installed_binary" ]; then
    cp -p "$installed_binary" "$previous"
    cp "$receipt" "$previous_receipt"
fi
printf 'envholster-install-v1\n%s\n%s\n' "$selected_version" "$expected" > "$temp_dir/receipt"
mv -f "$staged" "$installed_binary"
staged=
cp "$temp_dir/receipt" "$receipt"
chmod 600 "$receipt"
printf 'Installed Envholster %s in %s\n' "$selected_version" "$bin_dir"
case ":${PATH:-}:" in
    *":$bin_dir:"*) ;;
    *)
        if [ "$path_mode" != skip ]; then
            case "${SHELL:-}" in
                */zsh) profile=${ZDOTDIR:-$HOME}/.zshrc ;;
                */bash) if [ -f "$HOME/.bash_profile" ]; then profile=$HOME/.bash_profile;
                    elif [ -f "$HOME/.bash_login" ]; then profile=$HOME/.bash_login;
                    else profile=$HOME/.profile; fi ;;
                *) profile=$HOME/.profile ;;
            esac
            bash_rc=$profile
            case "${SHELL:-}" in */bash) bash_rc=$HOME/.bashrc ;; esac
            last_profile=
            for profile in "$profile" "$bash_rc"; do
            [ "$profile" != "$last_profile" ] || continue
            last_profile=$profile
            if [ ! -L "$profile" ] && { [ ! -e "$profile" ] || { [ -f "$profile" ] && [ -w "$profile" ] && [ "$(find "$profile" -prune -links 1)" = "$profile" ]; }; }; then
                if ! grep -Fqx -- "$path_line" "$profile" 2>/dev/null; then printf '\n%s\n' "$path_line" >> "$profile"; fi
                printf 'For this shell, run: . %s\n' "$(quote "$profile")"
            else printf 'Add this directory to PATH: %s\n' "$bin_dir"; fi
            done
        else printf 'For this shell, run: %s\n' "$path_line"; fi ;;
esac
PATH=$bin_dir:${PATH:-/usr/bin:/bin}
export PATH
if [ "$setup_mode" = agents ]; then "$installed_binary" setup agents --app "$selected_agents"; fi
if [ "$setup_mode" = skip ]; then printf '%s\n' 'Setup skipped. Run envholster setup when ready.';
else
    # A piped shell consumes stdin as code. Setup reads the controlling terminal.
    if ( : </dev/tty ) 2>/dev/null; then
        "$installed_binary" setup "$@" </dev/tty || { code=$?; printf '%s\n' 'The binary is installed. Rerun envholster setup to continue.' >&2; exit "$code"; }
    else "$installed_binary" setup "$@"; fi
fi
