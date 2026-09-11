#!/usr/bin/env bash
# scripts/e2e-local.sh — local end-to-end test of the daemon's TLS phone link.
#
# Runs the whole approve/deny/reconnect/timeout/unregistered-gating chain
# without root and without touching the system: everything (keys, TLS
# identity, unix socket, logs, binaries) lives in a throwaway tmpdir.
#
# Scenarios, in order:
#   1. approve:  phone-sim signs approve over TLS → session status approved
#   2. deny:     phone-sim signs deny    over TLS → session status denied
#   3. reconnect: a killed link is unregistered (session creation 503) and a
#                fresh phone-sim connection approves again
#   4. gating:   a session is pushed to the registered link only; a second,
#                unregistered link receives no pending
#   5. timeout:  the gated session expires with no decision → status expired
#                (waits out the daemon's 60s session TTL)
#   6. wrong fp: phone-sim refuses a server whose fingerprint does not match,
#                and refuses to run without -fp at all
#
# Usage:
#   bash scripts/e2e-local.sh
# Dependencies: go, curl, jq. Total runtime ~90s (dominated by scenario 5).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d /tmp/phone-fprint-e2e.XXXXXX)"
KEYS="$TMP/keys"
TLS="$TMP/tls"
SOCK="$TMP/daemon.sock"
mkdir -p "$KEYS"

DAEMON_BIN="$TMP/fingerkeyd"
SIM_BIN="$TMP/phone-sim"
DAEMON_LOG="$TMP/daemon.log"
DAEMON_PID=""
SIM_PID=""
SIM_PIDS=""

cleanup() {
  for p in $SIM_PIDS $DAEMON_PID; do
    [ -n "$p" ] && kill "$p" 2>/dev/null || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() {
  echo "FAIL: $*" >&2
  echo "--- daemon log ---" >&2
  cat "$DAEMON_LOG" >&2 2>/dev/null || true
  exit 1
}

# wait_for <file> <grep-pattern> <seconds>
wait_for() {
  local file="$1" pattern="$2" seconds="${3:-10}" i
  for ((i = 0; i < seconds * 5; i++)); do
    grep -q "$pattern" "$file" 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}

command -v go >/dev/null || fail "go is required"
command -v curl >/dev/null || fail "curl is required"
command -v jq >/dev/null || fail "jq is required"

echo "== building daemon and phone-sim =="
(cd "$ROOT/daemon" && go build -o "$DAEMON_BIN" .)
(cd "$ROOT/scripts" && go build -o "$SIM_BIN" ./phone-sim)

echo "== generating test keypairs =="
read -r PRIV_B64 PUB_B64 <<<"$("$SIM_BIN" -keygen)"
read -r UNREG_PRIV_B64 UNREG_PUB_B64 <<<"$("$SIM_BIN" -keygen)"
printf '%s\n' "$PUB_B64" >"$KEYS/sim.pub" # the registered phone
# UNREG_PUB_B64 is deliberately NOT written to the keys dir.

# start_daemon: find a free loopback port (the daemon logs "tls unavailable"
# and keeps serving the unix socket when the port is taken, so retry on that).
start_daemon() {
  local port
  for _ in 1 2 3 4 5; do
    port=$((20000 + RANDOM % 20000))
    : >"$DAEMON_LOG"
    "$DAEMON_BIN" -socket "$SOCK" -keys-dir "$KEYS" -tls-dir "$TLS" \
      -addr "127.0.0.1:$port" >"$DAEMON_LOG" 2>&1 &
    DAEMON_PID=$!
    if wait_for "$DAEMON_LOG" "tls listening" 5; then
      return 0
    fi
    if grep -q "tls unavailable" "$DAEMON_LOG"; then
      kill "$DAEMON_PID" 2>/dev/null || true
      wait "$DAEMON_PID" 2>/dev/null || true
      continue
    fi
    fail "daemon failed to start"
  done
  fail "could not find a free loopback port"
}
start_daemon

ADDR="$(sed -n 's/.*tls listening on \([0-9.]*:[0-9]*\) .*/\1/p' "$DAEMON_LOG" | head -1)"
FP="$(sed -n 's/.*fp=\([0-9a-f]\{64\}\).*/\1/p' "$DAEMON_LOG" | head -1)"
[ -n "$ADDR" ] || fail "no tls address in daemon log"
[ -n "$FP" ] || fail "no fingerprint in daemon log"
echo "== daemon ready: addr=$ADDR fp=$FP =="

# create_session → POST /v1/session on the root-only unix socket, echoes JSON.
create_session() {
  curl -s --unix-socket "$SOCK" -X POST http://localhost/v1/session \
    -d '{"user":"alice","service":"sudo","tty":"pts/1"}'
}

# session_status <id> → echoes the status field.
session_status() {
  curl -s --unix-socket "$SOCK" "http://localhost/v1/session/$1" | jq -r .status
}

# start_sim <decision> <priv_b64> <logfile> [extra phone-sim args...]
start_sim() {
  "$SIM_BIN" -addr "$ADDR" -fp "$FP" -key "$2" -decision "$1" "${@:4}" \
    >"$3" 2>&1 &
  SIM_PID=$!
  SIM_PIDS="$SIM_PIDS $SIM_PID"
}

# stop_sim kills the current sim and waits for it.
stop_sim() {
  kill "$SIM_PID" 2>/dev/null || true
  wait "$SIM_PID" 2>/dev/null || true
}

# --- scenario 1: approve ---
echo "== scenario 1: approve =="
SIM_LOG="$TMP/sim-approve.log"
start_sim approve "$PRIV_B64" "$SIM_LOG" -once
wait_for "$SIM_LOG" "welcome registered=true" 10 || fail "approve: sim not registered"
resp="$(create_session)"
ID="$(echo "$resp" | jq -r .id)"
[ -n "$ID" ] && [ "$ID" != "null" ] || fail "approve: session create failed: $resp"
wait_for "$SIM_LOG" "decision-result id=$ID status=approved" 10 || fail "approve: no approved decision-result"
wait "$SIM_PID" || fail "approve: phone-sim exited nonzero"
status="$(session_status "$ID")"
[ "$status" = "approved" ] || fail "approve: session status=$status, want approved"
pass "approve: session $ID approved over TLS"

# --- scenario 2: deny ---
echo "== scenario 2: deny =="
SIM_LOG="$TMP/sim-deny.log"
start_sim deny "$PRIV_B64" "$SIM_LOG" -once
wait_for "$SIM_LOG" "welcome registered=true" 10 || fail "deny: sim not registered"
resp="$(create_session)"
ID="$(echo "$resp" | jq -r .id)"
[ -n "$ID" ] && [ "$ID" != "null" ] || fail "deny: session create failed: $resp"
wait_for "$SIM_LOG" "decision-result id=$ID status=denied" 10 || fail "deny: no denied decision-result"
wait "$SIM_PID" || fail "deny: phone-sim exited nonzero"
status="$(session_status "$ID")"
[ "$status" = "denied" ] || fail "deny: session status=$status, want denied"
pass "deny: session $ID denied over TLS"

# --- scenario 3: reconnect ---
echo "== scenario 3: reconnect =="
SIM_LOG="$TMP/sim-reconnect.log"
start_sim approve "$PRIV_B64" "$SIM_LOG" -once
wait_for "$SIM_LOG" "welcome registered=true" 10 || fail "reconnect: sim not registered"
kill -9 "$SIM_PID" 2>/dev/null || true
wait "$SIM_PID" 2>/dev/null || true
# The killed link must be unregistered: session creation fails fast with 503.
resp=""
for _ in $(seq 1 25); do
  resp="$(create_session)"
  case "$resp" in
    *"no phone connected"*) break ;;
  esac
  sleep 0.2
done
case "$resp" in
  *"no phone connected"*) ;;
  *) fail "reconnect: dead link still registered: $resp" ;;
esac
# A fresh link works again.
SIM_LOG2="$TMP/sim-reconnect2.log"
start_sim approve "$PRIV_B64" "$SIM_LOG2" -once
wait_for "$SIM_LOG2" "welcome registered=true" 10 || fail "reconnect: second sim not registered"
resp="$(create_session)"
ID="$(echo "$resp" | jq -r .id)"
[ -n "$ID" ] && [ "$ID" != "null" ] || fail "reconnect: session create failed: $resp"
wait_for "$SIM_LOG2" "decision-result id=$ID status=approved" 10 || fail "reconnect: no approved decision-result"
pass "reconnect: dead link unregistered, fresh link approved session $ID"

# --- scenario 4: unregistered gating + scenario 5: timeout ---
echo "== scenario 4: unregistered hello gets no pending =="
start_sim hold "$PRIV_B64" "$TMP/sim-reg.log"    # registered, never answers
wait_for "$TMP/sim-reg.log" "welcome registered=true" 10 || fail "gating: registered sim not registered"
start_sim approve "$UNREG_PRIV_B64" "$TMP/sim-unreg.log" # not in the keys dir
wait_for "$TMP/sim-unreg.log" "welcome registered=false" 10 || fail "gating: expected registered=false"
resp="$(create_session)"
ID="$(echo "$resp" | jq -r .id)"
[ -n "$ID" ] && [ "$ID" != "null" ] || fail "gating: session create failed: $resp"
wait_for "$TMP/sim-reg.log" "pending id=$ID" 10 || fail "gating: registered sim must receive the pending"
sleep 1
if grep -q "pending id=" "$TMP/sim-unreg.log"; then
  fail "gating: unregistered sim received a pending"
fi
pass "gating: pending pushed to registered link only"

echo "== scenario 5: timeout (waits out the 60s session TTL) =="
status=""
for _ in $(seq 1 70); do
  status="$(session_status "$ID")"
  [ "$status" = "expired" ] && break
  sleep 1
done
[ "$status" = "expired" ] || fail "timeout: session status=$status, want expired"
pass "timeout: session $ID expired without a decision"

# --- scenario 6: wrong/missing fingerprint refused ---
echo "== scenario 6: wrong fingerprint =="
WRONG_FP="$(printf 'f%.0s' $(seq 1 64))"
if "$SIM_BIN" -addr "$ADDR" -fp "$WRONG_FP" -key "$PRIV_B64" -decision approve -once \
  >"$TMP/sim-badfp.log" 2>&1; then
  fail "wrong fp: phone-sim accepted a server with an unpinned fingerprint"
fi
grep -q "fingerprint mismatch" "$TMP/sim-badfp.log" \
  || fail "wrong fp: expected fingerprint mismatch in log: $(cat "$TMP/sim-badfp.log")"
if "$SIM_BIN" -addr "$ADDR" -key "$PRIV_B64" -decision approve -once \
  >"$TMP/sim-nofp.log" 2>&1; then
  fail "missing fp: phone-sim connected without a fingerprint"
fi
grep -q -- "-fp is required" "$TMP/sim-nofp.log" || fail "missing fp: wrong error message"
pass "wrong/missing fingerprint refused"

echo "== e2e-local: all scenarios passed =="
