#!/bin/sh
# Source build fallback; the release installer delegates here for local checkouts.
set -eu

usage() {
    cat <<'EOF'
Usage: sh scripts/install.sh [--root DIR] [--no-setup | --agents APPS] [-- setup options]

Build and install from this checkout with Cargo's locked dependencies.
Interactive installs start the project-folder picker and guided onboarding.
For unattended setup, pass explicit project selections and --yes after --.
--root overrides CARGO_INSTALL_ROOT, CARGO_HOME, and the default ~/.cargo.
No sudo, shell-profile changes, or agent execution.
EOF
}

install_root=${CARGO_INSTALL_ROOT:-${CARGO_HOME:-${HOME:?HOME is required}/.cargo}}
setup_mode=interactive
selected_agents=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --root)
            [ "$#" -ge 2 ] && [ -n "$2" ] || { usage >&2; exit 2; }
            install_root=$2
            shift 2 ;;
        --no-setup)
            [ "$setup_mode" = interactive ] || { usage >&2; exit 2; }
            setup_mode=skip
            shift ;;
        --agents)
            [ "$setup_mode" = interactive ] && [ "$#" -ge 2 ] && [ -n "$2" ] || { usage >&2; exit 2; }
            selected_agents=$2
            case ",$selected_agents," in
                *,,*) usage >&2; exit 2 ;;
            esac
            remaining=$selected_agents
            while [ -n "$remaining" ]; do
                app=${remaining%%,*}
                case "$app" in codex|claude|cursor) ;; *) usage >&2; exit 2 ;; esac
                case "$remaining" in *,*) remaining=${remaining#*,} ;; *) remaining= ;; esac
            done
            setup_mode=agents
            shift 2 ;;
        -h|--help) usage; exit 0 ;;
        --from-source|--no-path) shift ;;
        --) shift; break ;;
        *) usage >&2; exit 2 ;;
    esac
done

command -v cargo >/dev/null 2>&1 || {
    printf '%s\n' 'Cargo is required. Install the pinned Rust toolchain described in rust-toolchain.toml, then rerun this script.' >&2
    exit 1
}
source_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
case "$install_root" in /*) ;; *) install_root="$PWD/$install_root" ;; esac

# Select the checkout's pinned toolchain even when invoked from the app directory.
(cd "$source_root" && cargo install --locked --path "$source_root/crates/envholster" --root "$install_root")
installed_binary=$install_root/bin/envholster
[ -x "$installed_binary" ] || { printf '%s\n' 'Cargo did not produce the expected envholster executable.' >&2; exit 1; }
printf 'Installed envholster in %s\n' "$install_root/bin"
case ":${PATH:-}:" in
    *":$install_root/bin:"*) ;;
    *) printf 'Add this directory to PATH before launching apps: %s\n' "$install_root/bin" ;;
esac

if [ "$setup_mode" = agents ]; then
    "$installed_binary" setup agents --app "$selected_agents"
    if ( : </dev/tty ) 2>/dev/null || [ "$#" -gt 0 ]; then setup_mode=interactive; fi
fi
case "$setup_mode" in
    interactive)
        PATH="$install_root/bin:${PATH:-/usr/bin:/bin}"
        export PATH
        if ( : </dev/tty ) 2>/dev/null; then "$installed_binary" setup "$@" </dev/tty;
        else "$installed_binary" setup "$@"; fi ;;
    skip) printf '%s\n' 'Optional setup skipped. Run envholster setup later.' ;;
esac
