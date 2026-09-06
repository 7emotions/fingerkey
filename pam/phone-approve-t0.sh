#!/usr/bin/env bash
#
# phone-approve-t0.sh -- Wave 1 (T0, lab-only) pam_exec helper.
#
# Creates an approve session on the local phone-approval daemon, prints the
# approval URL to the user's tty (STDERR -- pam_exec captures stdout), then
# blocks polling for a decision.
#
# Exit 0   -> session approved
# Exit 1   -> denied / expired / timeout / transport or parse error
#
# pam_exec maps any non-zero exit to PAM_SYSTEM_ERR (NOT PAM_AUTH_ERR). Under
# an `auth sufficient` PAM rule that failure is non-fatal, so the normal
# password stack (pam_unix) still runs as the fallback.
#
# SECURITY NOTE: decisions are UNSIGNED over plain loopback HTTP. This is a
# de-risk / lab-only helper; the signed challenge lives in the compiled PAM
# module (later waves). No PAM_AUTHTOK handling: do NOT pair with
# `expose_authtok`.
#
# Env:
#   PAM_USER      (set by pam_exec for auth runs)
#   PAM_SERVICE   (set by pam_exec for auth runs)
#   PAM_TTY       (set by pam_exec for auth runs)
#   TIMEOUT       poll deadline in seconds (default 60)
#   DAEMON_URL    daemon base URL (default http://127.0.0.1:8765)
#
# Requires: curl, jq

set -u

DAEMON_URL="${DAEMON_URL:-http://127.0.0.1:8765}"
TIMEOUT="${TIMEOUT:-60}"

# pam_exec sets PAM_* only for auth runs; default them so the helper also
# runs standalone. `set -u` stays on.
PAM_USER="${PAM_USER:-}"
PAM_SERVICE="${PAM_SERVICE:-}"
PAM_TTY="${PAM_TTY:-}"

# A non-numeric TIMEOUT would make the deadline arithmetic below abort with an
# opaque error; reject it up front instead.
case "$TIMEOUT" in
    ''|*[!0-9]*)
        echo "phone-approve-t0: TIMEOUT must be a positive integer (got '$TIMEOUT')" >&2
        exit 1
        ;;
esac

if ! command -v curl >/dev/null 2>&1; then
    echo "phone-approve-t0: curl not found" >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "phone-approve-t0: jq not found" >&2
    exit 1
fi

# 1. Create the session.
payload=$(printf '{"user":"%s","service":"%s","tty":"%s"}' "$PAM_USER" "$PAM_SERVICE" "$PAM_TTY")

create_resp=$(curl -s -X POST "$DAEMON_URL/v1/session" -H 'Content-Type: application/json' -d "$payload")
create_rc=$?
if [ "$create_rc" -ne 0 ]; then
    echo "phone-approve-t0: failed to create session at $DAEMON_URL (curl exit $create_rc)" >&2
    exit 1
fi

session_id=$(printf '%s' "$create_resp" | jq -r '.id // empty' 2>/dev/null)
approve_url=$(printf '%s' "$create_resp" | jq -r '.approve_url // empty' 2>/dev/null)

if [ -z "$session_id" ]; then
    echo "phone-approve-t0: no 'id' in daemon response: $create_resp" >&2
    exit 1
fi
if [ -z "$approve_url" ]; then
    echo "phone-approve-t0: no 'approve_url' in daemon response: $create_resp" >&2
    exit 1
fi

# STDERR reaches the user's tty; pam_exec captures stdout instead.
echo "phone-approve-t0: approve this login at: $approve_url" >&2

# 2. Poll for a decision until the deadline. pam_exec blocks in waitpid with
# no timeout of its own, so this helper enforces the deadline.
deadline=$(( $(date +%s) + TIMEOUT ))

while :; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "phone-approve-t0: session $session_id not approved within ${TIMEOUT}s" >&2
        exit 1
    fi

    poll_resp=$(curl -s "$DAEMON_URL/v1/session/$session_id")
    poll_rc=$?
    if [ "$poll_rc" -ne 0 ]; then
        echo "phone-approve-t0: failed to poll session $session_id (curl exit $poll_rc)" >&2
        exit 1
    fi

    state=$(printf '%s' "$poll_resp" | jq -r '.status // empty' 2>/dev/null)

    case "$state" in
        approved)
            exit 0
            ;;
        denied|expired)
            echo "phone-approve-t0: session $session_id $state" >&2
            exit 1
            ;;
        '')
            echo "phone-approve-t0: malformed status response for session $session_id: $poll_resp" >&2
            exit 1
            ;;
    esac

    sleep 1
done
