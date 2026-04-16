#!/usr/bin/env bash

set -e
set -u
set -o pipefail
set -x

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BINARY=${BINARY:-"ssh-agent-proxy"}
readonly INSTALL_DIR=${INSTALL_DIR:-"${HOME}/.local/bin"}
readonly LOG_DIR=${LOG_DIR:-"${HOME}/.local/share/${BINARY}"}
readonly CONFIG=${CONFIG:-"${HOME}/.config/${BINARY}.toml"}
readonly PLIST_DIR=${PLIST_DIR:-"${HOME}/Library/LaunchAgents"}
readonly PLIST=${PLIST:-"${PLIST_DIR}/software.typed.ssh-agent-proxy.plist"}

main() {
    declare -r cmd="${1:-install}"
    case "$cmd" in
        install)
            mkdir -p "$INSTALL_DIR" "$LOG_DIR"
            launchctl bootout "gui/$(id -u)" "$PLIST" || true

            cp "target/release/$BINARY" "$INSTALL_DIR/$BINARY"
            mkdir -p "$PLIST_DIR"
            sed -e "s|__BINARY__|$INSTALL_DIR/$BINARY|" \
                -e "s|__CONFIG__|$CONFIG|" \
                -e "s|__LOG_DIR__|$LOG_DIR|" \
                "$SCRIPT_DIR/launchd.plist.template" > "$PLIST"
            launchctl bootstrap "gui/$(id -u)" "$PLIST"
            printf '%s\n' "Installed and started $BINARY"
            ;;
        uninstall)
            if launchctl list | grep -q "$(basename "$PLIST" .plist)"; then
                launchctl bootout "gui/$(id -u)" "$PLIST"
            fi
            rm -f "$PLIST"
            rm -f "$INSTALL_DIR/$BINARY"
            printf '%s\n' "Uninstalled $BINARY"
            exit 0
            ;;
        *)
            printf '%s\n' "Unknown command: $cmd" >&2
            printf '%s\n' "Usage: $0 [install|uninstall]" >&2
            exit 1
            ;;
    esac
}

main "$@"