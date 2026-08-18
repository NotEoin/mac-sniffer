#!/usr/bin/env bash
#
# live-capture.sh - record the README figure end to end, then put the network
# back exactly as it was.
#
#   sudo ./tools/capture/live-capture.sh                  # both runs, 15 min each
#   sudo ./tools/capture/live-capture.sh --only pinned    # just the pinned run
#   sudo ./tools/capture/live-capture.sh --duration 300   # a quick rehearsal
#
# WHAT IT DOES. Puts the card into monitor mode, records two fifteen-minute
# captures of the same room, and draws media/live-capture.png from them:
#
#   hopping   1/6/11 weighted, sampling non-DFS 5GHz. Sees the most devices;
#             crosses bands, so the caption has to disclose the crossings.
#   pinned    2437 MHz throughout. Fewer devices, but nothing is double
#             counted and the curves are smooth.
#
# Each run is two sniffers on one interface at once - one clustering, one with
# --no-fingerprint - because the figure is the comparison between them. Each is
# rendered in both a light and a dark theme.
#
# THE SAFETY GATE. Monitor mode takes the wireless card away from
# NetworkManager, so a machine whose only route is that card goes offline with
# no way back except physical access. This refuses to start unless it can prove
# there is working internet over something else. --force skips the proof; only
# use it sitting in front of the machine.
#
# NETWORKING IS RESTORED ON EVERY EXIT PATH - success, failure, or Ctrl-C -
# by an EXIT trap. The one exception is --keep-monitor, for iterating on the
# figure without cycling the card each time.
#
# Requires: iw, ip, nmcli, rfkill, ping, and python with scapy and matplotlib. Root.

set -uo pipefail

# ------------------------------------------------------------------ config --

IFACE="${IFACE:-}"                 # physical card; auto-detected when empty
MON="${MON:-mon0}"                 # the monitor vif this script creates
DURATION="${DURATION:-900}"        # seconds per run
WINDOW="${WINDOW:-300}"            # tracker sliding window
INTERVAL="${INTERVAL:-30}"         # seconds between interval reports
DWELL="${DWELL:-3}"                # seconds per channel while hopping
PIN_FREQ="${PIN_FREQ:-2437}"       # channel 6
ONLY="both"                        # both | hopping | pinned
PROMOTE="pinned"                   # which run becomes media/live-capture.png
HEADCOUNT=""                       # optional reference line on the figure
FORCE=0
KEEP_MONITOR=0

# Deliberately lopsided: 1, 6 and 11 are the only non-overlapping 2.4GHz
# channels and carry almost all probe traffic, so an even sweep would spend
# its life on channels nobody probes.
HOP_PLAN=(1 6 11 1 6 11 36 1 6 11 40 1 6 11 44 1 6 11 48 1 6 11 149 1 6 11 157)

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RUNDIR="$HERE/runs/$RUN_ID"

# ----------------------------------------------------------------- output ---

say()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m ok \033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() { sed -n '3,33p' "$0"; exit "${1:-1}"; }

# -------------------------------------------------------------- arguments ---

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iface)        IFACE="${2:?--iface needs a value}"; shift 2 ;;
        --mon)          MON="${2:?--mon needs a value}"; shift 2 ;;
        --duration)     DURATION="${2:?--duration needs seconds}"; shift 2 ;;
        --window)       WINDOW="${2:?--window needs seconds}"; shift 2 ;;
        --interval)     INTERVAL="${2:?--interval needs seconds}"; shift 2 ;;
        --dwell)        DWELL="${2:?--dwell needs seconds}"; shift 2 ;;
        --freq)         PIN_FREQ="${2:?--freq needs MHz}"; shift 2 ;;
        --only)         ONLY="${2:?--only needs both|hopping|pinned}"; shift 2 ;;
        --promote)      PROMOTE="${2:?--promote needs hopping|pinned|none}"; shift 2 ;;
        --headcount)    HEADCOUNT="${2:?--headcount needs a number}"; shift 2 ;;
        --force)        FORCE=1; shift ;;
        --keep-monitor) KEEP_MONITOR=1; shift ;;
        -h|--help)      usage 0 ;;
        *)              die "unknown option '$1' (try --help)" ;;
    esac
done

case "$ONLY" in both|hopping|pinned) ;; *) die "--only must be both, hopping or pinned" ;; esac
case "$PROMOTE" in hopping|pinned|none) ;; *) die "--promote must be hopping, pinned or none" ;; esac
[[ "$DURATION" =~ ^[0-9]+$ ]] || die "--duration must be a whole number of seconds"
[[ -z "$HEADCOUNT" || "$HEADCOUNT" =~ ^[0-9]+$ ]] || die "--headcount must be a whole number"
if [[ "$ONLY" != "both" && "$PROMOTE" != "none" && "$PROMOTE" != "$ONLY" ]]; then
    die "--promote $PROMOTE but --only $ONLY: that run will not exist"
fi

# ------------------------------------------------------------------ state ---
# Set as we go so the EXIT trap knows exactly how much there is to undo.

MON_CREATED=0
IFACE_DOWNED=0
NM_UNMANAGED=0
HOP_PID=""
CLUSTERED_PID=""
RAW_PID=""
RESTORED=0

# -------------------------------------------------------------- preflight ---

[[ $EUID -eq 0 ]] || die "must run as root -> sudo $0 $*"

for cmd in iw ip nmcli rfkill; do
    command -v "$cmd" >/dev/null 2>&1 || die "missing required command: $cmd"
done

# Only the safety gate below uses ping, and --force skips the gate.
if [[ $FORCE -eq 0 ]]; then
    command -v ping >/dev/null 2>&1 \
        || die "missing required command: ping (needed for the internet check; --force skips it)"
fi

# The sniffer's scapy backend and the plotting both need a python that has
# their dependencies. Prefer an explicit PY, then the venv the other capture
# tooling uses, then whatever python3 is on PATH.
PY="${PY:-}"
if [[ -z "$PY" ]]; then
    for candidate in \
        "/home/${SUDO_USER:-$USER}/.local/share/probe-sniffer-venv/bin/python" \
        "$REPO/.venv/bin/python" \
        "$(command -v python3 2>/dev/null)"
    do
        [[ -x "$candidate" ]] && { PY="$candidate"; break; }
    done
fi
[[ -n "$PY" && -x "$PY" ]] || die "no usable python found (set PY=/path/to/python)"

"$PY" -c 'import scapy' 2>/dev/null \
    || die "$PY cannot import scapy - install it, or set PY to the venv that has it"
"$PY" -c 'import matplotlib' 2>/dev/null \
    || die "$PY cannot import matplotlib - needed to draw the figure"
[[ -f "$REPO/tools/plot_capture.py" ]] || die "cannot find $REPO/tools/plot_capture.py"

phy_of() { basename "$(readlink -f "/sys/class/net/$1/phy80211" 2>/dev/null)" 2>/dev/null; }

# Auto-detect the card when one was not named: the first managed wireless
# interface that is not the monitor vif we are about to make.
if [[ -z "$IFACE" ]]; then
    IFACE=$(iw dev 2>/dev/null | awk '$1=="Interface"{i=$2} $1=="type" && $2=="managed"{print i; exit}')
    [[ -n "$IFACE" ]] || die "could not find a managed wireless interface (name one with --iface)"
    say "using wireless interface '$IFACE' (override with --iface)"
fi
[[ -d "/sys/class/net/$IFACE" ]] || die "no such interface: $IFACE"
PHY="$(phy_of "$IFACE")"
[[ -n "$PHY" ]] || die "$IFACE does not look like a wireless interface"

# ------------------------------------------------------------ safety gate ---

verify_other_internet() {
    local candidates found=""
    candidates=$(ip -o route show default 2>/dev/null \
        | awk '{for (i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' \
        | grep -vx "$IFACE" | sort -u)
    [[ -n "$candidates" ]] || return 1
    for c in $candidates; do
        # A route over a dead link is worse than no route at all.
        [[ "$(cat "/sys/class/net/$c/carrier" 2>/dev/null)" == "1" ]] || continue
        if ping -I "$c" -c2 -W3 1.1.1.1 >/dev/null 2>&1; then found="$c"; break; fi
    done
    [[ -n "$found" ]] || return 1
    echo "$found"
}

OTHER_LINK=""
if [[ $FORCE -eq 1 ]]; then
    warn "--force: skipping the internet check"
    warn "if $IFACE is this machine's only route, it is about to go offline"
    for i in 5 4 3 2 1; do printf '\r  continuing in %ss (Ctrl-C to abort) ' "$i"; sleep 1; done
    printf '\r%*s\r' 50 ''
elif OTHER_LINK=$(verify_other_internet); then
    ok "internet confirmed over '$OTHER_LINK' - safe to release $IFACE"
else
    die "$(cat <<EOF
no working non-wifi internet found.

Monitor mode cuts $IFACE off completely, so starting now would take this
machine offline with no way back except physical access. Refusing.

Current default routes:
$(ip route show default | sed 's/^/    /')

Plug in the wired link and re-run, or pass --force if you are sitting at
the machine.
EOF
)"
fi

# Everything from here is teed into the run log as well as the terminal, so a
# run that goes wrong leaves the network changes it made on the record.
mkdir -p "$RUNDIR"
exec > >(tee -a "$RUNDIR/live-capture.log") 2>&1

# ---------------------------------------------------------- channel plan ---
# Defined before the teardown below, because the EXIT trap calls stop_hopper
# and a failure during setup would otherwise fire the trap before this existed.

start_hopper() {
    local log="$1"
    ( while :; do
          for ch in "${HOP_PLAN[@]}"; do
              if iw dev "$MON" set channel "$ch" >/dev/null 2>&1; then
                  printf '%s channel %s\n' "$(date +%H:%M:%S)" "$ch" >> "$log"
              fi
              sleep "$DWELL"
          done
      done ) &
    HOP_PID=$!
}

stop_hopper() {
    [[ -n "$HOP_PID" ]] || return 0
    pkill -P "$HOP_PID" 2>/dev/null
    kill "$HOP_PID" 2>/dev/null
    wait "$HOP_PID" 2>/dev/null
    HOP_PID=""
}

# --------------------------------------------------------------- teardown ---
# Registered before anything is changed, so every exit path unwinds the same
# way. Idempotent: a failure part-way through setup calls this too.

restore() {
    [[ $RESTORED -eq 1 ]] && return 0
    RESTORED=1

    stop_hopper
    for pid in "$CLUSTERED_PID" "$RAW_PID"; do
        [[ -n "$pid" ]] && kill -INT "$pid" 2>/dev/null
    done

    if [[ $KEEP_MONITOR -eq 1 ]]; then
        echo
        warn "--keep-monitor: leaving $MON up and $IFACE unmanaged"
        warn "hand the card back with: sudo iw dev $MON del && sudo nmcli dev set $IFACE managed yes"
        return 0
    fi

    echo
    say "restoring the network"
    if [[ $MON_CREATED -eq 1 ]]; then
        ip link set "$MON" down 2>/dev/null
        iw dev "$MON" del 2>/dev/null && ok "$MON removed"
    fi
    if [[ $IFACE_DOWNED -eq 1 ]]; then
        iw dev "$IFACE" set type managed 2>/dev/null
        ip link set "$IFACE" up 2>/dev/null
    fi
    if [[ $NM_UNMANAGED -eq 1 ]]; then
        rfkill unblock wifi 2>/dev/null
        nmcli dev set "$IFACE" managed yes 2>/dev/null
        systemctl restart NetworkManager 2>/dev/null \
            || warn "could not restart NetworkManager - you may need to do it by hand"

        local state=""
        for _ in $(seq 1 45); do
            state=$(nmcli -t -f DEVICE,STATE dev status 2>/dev/null \
                | grep "^${IFACE}:" | cut -d: -f2-)
            [[ "$state" == connected* ]] && break
            sleep 1
        done
        if [[ "$state" == connected* ]]; then
            ok "$IFACE reconnected"
        else
            warn "$IFACE did not reconnect (state: ${state:-unknown})"
            warn "try: sudo systemctl restart NetworkManager"
        fi
    fi
}
trap restore EXIT
trap 'echo; warn "interrupted"; exit 130' INT TERM

# ------------------------------------------------------------ monitor mode ---

say "taking $IFACE ($PHY) away from NetworkManager"
nmcli dev set "$IFACE" managed no >/dev/null 2>&1 && NM_UNMANAGED=1
nmcli dev disconnect "$IFACE" >/dev/null 2>&1
sleep 1

# A dedicated monitor vif, not `iw dev $IFACE set type monitor`: on iwlwifi the
# latter is accepted, reports "type monitor", and then delivers no frames at
# all. A silent zero is the worst failure a sniffer can have.
say "adding monitor interface $MON on $PHY"
iw dev "$MON" del 2>/dev/null
iw phy "$PHY" interface add "$MON" type monitor \
    || die "could not add a monitor interface on $PHY"
MON_CREATED=1
ip link set "$MON" up || die "could not bring $MON up"

# The card must not be scanning underneath us: a managed interface sharing the
# phy drags the monitor vif across bands, which is exactly the double count the
# pinned run exists to avoid.
ip link set "$IFACE" down 2>/dev/null
IFACE_DOWNED=1
ok "$MON is up, $IFACE is down"

# Do not trust the type flag - prove frames arrive before spending half an hour.
say "checking frames actually arrive on $MON"
FRAMES=$("$PY" - "$MON" <<'PY' 2>/dev/null
import sys
from scapy.all import conf, sniff
conf.verb = 0
try:
    print(len(sniff(iface=sys.argv[1], timeout=8)))
except Exception:
    print(0)
PY
)
[[ "${FRAMES:-0}" -gt 0 ]] || die "$MON reports monitor mode but delivered no frames in 8s"
ok "$FRAMES frames in 8s - $MON is genuinely capturing"

# ----------------------------------------------------------------- runs -----

{
    echo "run_id=$RUN_ID"
    echo "started=$(date -Is)"
    echo "duration_s=$DURATION"
    echo "window_s=$WINDOW"
    echo "interval_s=$INTERVAL"
    echo "runs=$ONLY"
    echo "card=$IFACE"
    echo "phy=$PHY"
    echo "monitor_iface=$MON"
    echo "pin_freq_mhz=$PIN_FREQ"
    echo "hop_dwell_s=$DWELL"
    echo "other_link=${OTHER_LINK:-none (forced)}"
    echo "kernel=$(uname -r)"
    echo "driver=$(basename "$(readlink -f "/sys/class/net/$IFACE/device/driver" 2>/dev/null)" 2>/dev/null)"
    echo "python=$("$PY" -V 2>&1)"
    echo "scapy=$("$PY" -c 'import scapy; print(scapy.__version__)' 2>/dev/null)"
} > "$RUNDIR/run-meta.txt"

say "run $RUN_ID"
sed 's/^/    /' "$RUNDIR/run-meta.txt"

# run_capture <name> <caption phrase>
run_capture() {
    local name="$1" plan="$2"
    local dir="$RUNDIR/$name"
    mkdir -p "$dir"

    echo
    say "$name run: ${DURATION}s on $MON ($plan)"
    say "this only listens - nothing is transmitted"

    if [[ "$name" == "hopping" ]]; then
        start_hopper "$dir/channels.log"
        ok "hopper running, ${DWELL}s dwell over ${#HOP_PLAN[@]} steps"
    else
        iw dev "$MON" set freq "$PIN_FREQ" \
            || die "could not pin $MON to $PIN_FREQ MHz"
        ok "pinned to $PIN_FREQ MHz"
    fi

    # Two sniffers over one interface: the figure is the comparison between
    # them, and running them on separate captures would compare different air.
    ( cd "$REPO" && PYTHONPATH="$REPO" "$PY" -m probe_sniffer --iface "$MON" \
        --backend scapy --interval "$INTERVAL" --window "$WINDOW" \
        > "$dir/clustered.log" 2>&1 ) &
    CLUSTERED_PID=$!
    ( cd "$REPO" && PYTHONPATH="$REPO" "$PY" -m probe_sniffer --iface "$MON" \
        --backend scapy --interval "$INTERVAL" --window "$WINDOW" \
        --no-fingerprint > "$dir/raw.log" 2>&1 ) &
    RAW_PID=$!

    sleep 3
    for pid in "$CLUSTERED_PID" "$RAW_PID"; do
        kill -0 "$pid" 2>/dev/null || { cat "$dir"/*.log; die "a sniffer died on startup"; }
    done

    local end=$(( $(date +%s) + DURATION ))
    while [[ $(date +%s) -lt $end ]]; do
        sleep "$INTERVAL"
        kill -0 "$CLUSTERED_PID" 2>/dev/null || { warn "clustering sniffer stopped early"; break; }
        local left=$(( end - $(date +%s) ))
        [[ $left -lt 0 ]] && left=0
        printf '    %dm%02ds left  |  clustered=%s  raw=%s\n' \
            $(( left / 60 )) $(( left % 60 )) \
            "$(latest_count "$dir/clustered.log")" \
            "$(latest_count "$dir/raw.log")"
    done

    # SIGINT, not SIGKILL: the shutdown note carries the channel and band
    # crossing counts, and the figure's caption is drawn from it.
    say "stopping the sniffers"
    kill -INT "$CLUSTERED_PID" "$RAW_PID" 2>/dev/null
    for _ in $(seq 1 10); do
        kill -0 "$CLUSTERED_PID" 2>/dev/null || kill -0 "$RAW_PID" 2>/dev/null || break
        sleep 1
    done
    kill -TERM "$CLUSTERED_PID" "$RAW_PID" 2>/dev/null
    wait "$CLUSTERED_PID" 2>/dev/null
    wait "$RAW_PID" 2>/dev/null
    CLUSTERED_PID=""; RAW_PID=""
    stop_hopper

    local ticks
    ticks=$(grep -c 'in vicinity' "$dir/clustered.log" 2>/dev/null || echo 0)
    [[ "$ticks" -gt 0 ]] || { warn "no interval reports in $dir/clustered.log"; return 1; }
    ok "$name run complete: $ticks interval reports"
    echo "$plan" > "$dir/plan.txt"
    return 0
}

latest_count() {
    grep 'in vicinity' "$1" 2>/dev/null | tail -1 \
        | sed -n 's/.*): \([0-9]\+\).*/\1/p' | tail -1
}

# render <name>
render() {
    local name="$1"
    local dir="$RUNDIR/$name"
    local plan
    plan="$(cat "$dir/plan.txt" 2>/dev/null)"
    local extra=()
    [[ -n "$HEADCOUNT" ]] && extra=(--headcount "$HEADCOUNT")

    for theme in light dark; do
        "$PY" "$REPO/tools/plot_capture.py" "$dir/clustered.log" "$dir/raw.log" \
            --theme "$theme" --plan "$plan" "${extra[@]}" --quiet \
            --out "$dir/figure-$theme.png" \
            || { warn "could not draw the $theme figure for $name"; return 1; }
    done
    ok "$name figures: $dir/figure-light.png, $dir/figure-dark.png"
}

DID_HOPPING=0
DID_PINNED=0
[[ "$ONLY" == "both" || "$ONLY" == "hopping" ]] \
    && run_capture hopping "1/6/11 weighted sweep with non-DFS 5 GHz" && DID_HOPPING=1
[[ "$ONLY" == "both" || "$ONLY" == "pinned" ]] \
    && run_capture pinned "pinned to $PIN_FREQ MHz" && DID_PINNED=1

[[ $DID_HOPPING -eq 1 || $DID_PINNED -eq 1 ]] || die "no run produced any data"

# Hand the card back before plotting: the figure does not need the radio, and
# half a minute of matplotlib is half a minute of no wifi for nothing.
restore

echo
say "drawing the figures"
[[ $DID_HOPPING -eq 1 ]] && render hopping
[[ $DID_PINNED -eq 1 ]] && render pinned

# --------------------------------------------------------------- promote ----

if [[ "$PROMOTE" != "none" ]]; then
    src="$RUNDIR/$PROMOTE"
    if [[ -f "$src/figure-light.png" ]]; then
        mkdir -p "$REPO/media"
        cp "$src/figure-light.png" "$REPO/media/live-capture.png"
        cp "$src/figure-dark.png"  "$REPO/media/live-capture-dark.png"
        ok "media/live-capture.png and media/live-capture-dark.png <- $PROMOTE run"
    else
        warn "nothing to promote: the $PROMOTE run produced no figure"
    fi
fi

# Everything above ran as root; hand the files back to whoever called sudo.
if [[ -n "${SUDO_USER:-}" ]]; then
    chown -R "$SUDO_USER":"$(id -gn "$SUDO_USER")" "$HERE/runs" "$REPO/media" 2>/dev/null
fi

echo
ok "run directory: $RUNDIR"
[[ $DID_HOPPING -eq 1 ]] && printf '    hopping  %s\n' "$RUNDIR/hopping/figure-light.png"
[[ $DID_PINNED  -eq 1 ]] && printf '    pinned   %s\n' "$RUNDIR/pinned/figure-light.png"
if [[ $DID_HOPPING -eq 1 && $DID_PINNED -eq 1 ]]; then
    echo
    say "compare the two, then promote whichever you prefer:"
    printf '    cp %s/hopping/figure-light.png media/live-capture.png\n' "$RUNDIR"
    printf '    cp %s/hopping/figure-dark.png  media/live-capture-dark.png\n' "$RUNDIR"
fi
echo
