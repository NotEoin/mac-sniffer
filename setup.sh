#!/usr/bin/env bash
#
# setup.sh - put a wireless interface into monitor mode (or restore it).
#
# Usage:
#   sudo ./setup.sh up   <iface>        # enable monitor mode on <iface>
#   sudo ./setup.sh down <iface>        # restore managed mode
#   sudo ./setup.sh list                # list wireless interfaces
#
# Examples:
#   sudo ./setup.sh up   wlan1          # creates wlan1mon (airmon-ng default)
#   sudo ./setup.sh down wlan1mon
#
# Requires: aircrack-ng (provides airmon-ng), iw.
# Installs hints (Debian/Ubuntu): sudo apt install aircrack-ng iw
# Installs hints (Arch):          sudo pacman -S aircrack-ng iw
# Installs hints (Fedora):        sudo dnf install aircrack-ng iw

set -euo pipefail

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarn:\033[0m %s\n' "$*" >&2; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        die "must be run as root (use sudo)"
    fi
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

cmd_list() {
    require_cmd iw
    info "wireless interfaces:"
    iw dev | awk '$1=="Interface"{iface=$2} $1=="type"{print "  " iface " (" $2 ")"}'
}

cmd_up() {
    local iface="$1"
    require_root
    require_cmd airmon-ng
    require_cmd iw

    if ! iw dev "$iface" info >/dev/null 2>&1; then
        die "interface '$iface' does not exist (try: sudo ./setup.sh list)"
    fi

    info "killing processes that interfere with monitor mode (NetworkManager, wpa_supplicant, ...)"
    airmon-ng check kill >/dev/null || warn "airmon-ng check kill reported issues; continuing"

    info "switching '$iface' into monitor mode"
    # airmon-ng usually creates "<iface>mon". On newer aircrack-ng it may keep the same name.
    airmon-ng start "$iface"

    # Figure out which interface name is now in monitor mode.
    local mon_iface=""
    for candidate in "${iface}mon" "$iface"; do
        if iw dev "$candidate" info 2>/dev/null | grep -q "type monitor"; then
            mon_iface="$candidate"
            break
        fi
    done

    if [[ -z "$mon_iface" ]]; then
        die "failed to enter monitor mode (check 'iw dev' output)"
    fi

    info "monitor interface ready: $mon_iface"
    printf '\n'
    printf '  Next: run the sniffer with this interface, e.g.\n'
    printf '      sudo python -m probe_sniffer --iface %s\n' "$mon_iface"
    printf '\n'
    printf '  When done, restore managed mode with:\n'
    printf '      sudo ./setup.sh down %s\n' "$mon_iface"
    printf '\n'
}

cmd_down() {
    local iface="$1"
    require_root
    require_cmd airmon-ng

    info "stopping monitor mode on '$iface'"
    airmon-ng stop "$iface" || warn "airmon-ng stop reported issues"

    info "restarting NetworkManager (if installed)"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart NetworkManager 2>/dev/null || warn "could not restart NetworkManager (you may need to do it manually)"
    fi

    info "done"
}

main() {
    if [[ $# -lt 1 ]]; then
        sed -n '3,18p' "$0"
        exit 1
    fi

    local action="$1"; shift || true

    case "$action" in
        up)
            [[ $# -ge 1 ]] || die "usage: sudo ./setup.sh up <iface>"
            cmd_up "$1"
            ;;
        down)
            [[ $# -ge 1 ]] || die "usage: sudo ./setup.sh down <iface>"
            cmd_down "$1"
            ;;
        list)
            cmd_list
            ;;
        -h|--help|help)
            sed -n '3,18p' "$0"
            ;;
        *)
            die "unknown action '$action' (expected: up|down|list)"
            ;;
    esac
}

main "$@"
