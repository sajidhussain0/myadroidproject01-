#!/usr/bin/env bash
#
# frida-emulator.sh
#
# Automates the Waydroid + Frida setup/connection workflow for
# io.hextree.fridatarget (Hextree Android Dynamic Instrumentation labs).
#
# What it does:
#   1. Checks local tools (frida, frida-ps, adb, waydroid) are installed
#   2. Checks Waydroid is running
#   3. Connects ADB to the Waydroid device if not already connected
#   4. Confirms the frida-server binary exists on the device
#   5. Starts frida-server on the device (via waydroid root shell) if not running
#   6. Sets up adb port forwarding for 27042
#   7. Tests the Frida connection with frida-ps
#
# Usage:
#   chmod +x frida-emulator.sh
#   ./frida-emulator.sh
#
# Edit the CONFIG section below if your IP, port, or package changes.

set -uo pipefail

# ---------------------------- CONFIG ----------------------------
ADB_SERIAL="${ADB_SERIAL:-192.168.240.112:5555}"
FRIDA_PORT="${FRIDA_PORT:-27042}"
FRIDA_SERVER_PATH="${FRIDA_SERVER_PATH:-/data/local/tmp/frida-server}"
TARGET_PACKAGE="${TARGET_PACKAGE:-io.hextree.fridatarget}"
TARGET_PROCESS="${TARGET_PROCESS:-FridaTarget}"
# ------------------------------------------------------------------

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; NC="\033[0m"
info()  { echo -e "${GREEN}[*]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[x]${NC} $*"; }
die()   { err "$*"; exit 1; }

# ---------------------------- 0. CHECK TOOLS ----------------------------
info "Checking local tools..."
for cmd in frida frida-ps adb; do
    command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' not found on PATH. Install Frida tools / adb first."
done
command -v waydroid >/dev/null 2>&1 || warn "'waydroid' command not found on PATH (sudo may still work if it's elsewhere)."

info "frida version: $(frida --version 2>/dev/null || echo unknown)"

# ---------------------------- 0b. CHECK WAYDROID ----------------------------
info "Checking Waydroid status..."
if ! sudo waydroid status >/dev/null 2>&1; then
    die "Waydroid does not appear to be running. Start it manually, then re-run this script."
fi
info "Waydroid is running."

# ---------------------------- 0c. CHECK / CONNECT ADB ----------------------------
info "Checking ADB connection to ${ADB_SERIAL}..."
state="$(adb -s "$ADB_SERIAL" get-state 2>/dev/null)"
if [[ "$state" != "device" ]]; then
    warn "ADB not connected to ${ADB_SERIAL} (state: '${state:-none}'). Attempting adb connect..."
    adb connect "$ADB_SERIAL" || die "adb connect to ${ADB_SERIAL} failed."
    sleep 1
    state="$(adb -s "$ADB_SERIAL" get-state 2>/dev/null)"
    [[ "$state" == "device" ]] || die "ADB still not connected after retry (state: '${state:-none}'). Check the emulator IP."
fi
info "ADB connected (state: device)."

# Sanity check target package is installed
if ! adb -s "$ADB_SERIAL" shell pm list packages 2>/dev/null | grep -q "$TARGET_PACKAGE"; then
    warn "Package ${TARGET_PACKAGE} not found via 'pm list packages'. Continuing anyway."
fi

# ---------------------------- 1. CHECK FRIDA-SERVER BINARY ----------------------------
info "Checking frida-server binary on device (${FRIDA_SERVER_PATH})..."
if ! sudo waydroid shell -- ls -l "$FRIDA_SERVER_PATH" >/dev/null 2>&1; then
    die "frida-server not found at ${FRIDA_SERVER_PATH} inside Waydroid. Push/install it first."
fi

# ---------------------------- 1b. START FRIDA-SERVER IF NOT RUNNING ----------------------------
info "Checking whether frida-server is already running..."
if adb -s "$ADB_SERIAL" shell pidof frida-server >/dev/null 2>&1 && \
   [[ -n "$(adb -s "$ADB_SERIAL" shell pidof frida-server 2>/dev/null)" ]]; then
    info "frida-server already running on device."
else
    info "Starting frida-server on device..."
    # Note: 'su' is not available on this image; use the waydroid root shell instead.
    sudo waydroid shell -- sh -c "chmod 755 $FRIDA_SERVER_PATH; nohup $FRIDA_SERVER_PATH > ${FRIDA_SERVER_PATH}.log 2>&1 &" \
        || warn "Could not confirm frida-server start command ran (some Waydroid images reject 'shell sh -c ...')."
    sleep 2
    if adb -s "$ADB_SERIAL" shell pidof frida-server >/dev/null 2>&1 && \
       [[ -n "$(adb -s "$ADB_SERIAL" shell pidof frida-server 2>/dev/null)" ]]; then
        info "frida-server started successfully."
    else
        err "frida-server does not appear to be running. Start it manually:"
        echo "    sudo waydroid shell"
        echo "    chmod 755 ${FRIDA_SERVER_PATH}"
        echo "    ${FRIDA_SERVER_PATH} > ${FRIDA_SERVER_PATH}.log 2>&1 &"
        echo "    pidof frida-server"
        die "Aborting: frida-server not confirmed running."
    fi
fi

# ---------------------------- 2. PORT FORWARDING ----------------------------
info "Setting up adb forwarding for tcp:${FRIDA_PORT}..."
adb -s "$ADB_SERIAL" forward --remove "tcp:${FRIDA_PORT}" >/dev/null 2>&1
adb -s "$ADB_SERIAL" forward "tcp:${FRIDA_PORT}" "tcp:${FRIDA_PORT}" \
    || die "adb forward failed."
info "Forwarding tcp:${FRIDA_PORT} -> tcp:${FRIDA_PORT} on device."

# ---------------------------- 3. TEST CONNECTION ----------------------------
info "Testing Frida connection (frida-ps -H 127.0.0.1:${FRIDA_PORT})..."
if frida-ps -H "127.0.0.1:${FRIDA_PORT}" >/tmp/frida-ps-out.$$ 2>&1; then
    info "Frida connection OK. Sample of running processes:"
    head -n 10 "/tmp/frida-ps-out.$$"
    rm -f "/tmp/frida-ps-out.$$"
else
    err "frida-ps could not connect. Last output:"
    cat "/tmp/frida-ps-out.$$"
    rm -f "/tmp/frida-ps-out.$$"
    die "Connection test failed. See section 14 (troubleshooting) in your notes."
fi

# ---------------------------- 4. READY ----------------------------
echo
info "Environment ready."
echo "  Attach to running app:  frida -H 127.0.0.1:${FRIDA_PORT} -n ${TARGET_PROCESS} -l test.js"
echo "  Spawn app by package:   frida -H 127.0.0.1:${FRIDA_PORT} -f ${TARGET_PACKAGE} -l test.js"
echo "  Trace Java namespace:   frida-trace -H 127.0.0.1:${FRIDA_PORT} -j '${TARGET_PACKAGE%%.*}.!' -n ${TARGET_PROCESS}"
echo "  List processes:         frida-ps -H 127.0.0.1:${FRIDA_PORT} -ai"
