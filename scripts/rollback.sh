#!/usr/bin/env bash
# Revert the phone fingerprint approval installation:
#   - disable + remove the systemd unit
#   - remove the daemon, helper and PAM module binaries
#   - restore /etc/pam.d/sudo and /etc/pam.d/polkit-1 from their newest
#     .orig-* backups (or strip the pam_phone_approve.so line if no
#     backup exists; the .orig-* backups themselves are kept)
#   - remove the paired-key store and the TLS cert/key dirs
#     (/run/phone-fprint-auth is a systemd RuntimeDirectory, so it
#     disappears automatically when the unit stops)
#
# Must run as root.
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "error: must run as root (sudo $0)" >&2
    exit 1
fi

UNIT="/etc/systemd/system/phone-approve-daemon.service"
DAEMON_BIN="/usr/local/libexec/phone-approve-daemon"
PAIR_BIN="/usr/local/bin/phone-approve"
HELPER_BIN="/usr/local/libexec/phone-approve-t0"
PAM_MODULE="/usr/lib/x86_64-linux-gnu/security/pam_phone_approve.so"
STATE_PARENT="/var/lib/phone-fprint-auth"
KEYS_DIR="${STATE_PARENT}/keys"
TLS_DIR="${STATE_PARENT}/tls"
PAM_FILES=(
    "/etc/pam.d/sudo"
    "/etc/pam.d/polkit-1"
)

echo "== systemd =="
# Ignore failures when the unit is already disabled/inactive/absent.
systemctl disable --now phone-approve-daemon 2>/dev/null || true
rm -f "${UNIT}"
systemctl daemon-reload
echo "disabled + removed phone-approve-daemon unit"

echo "== binaries =="
rm -f "${DAEMON_BIN}" "${PAIR_BIN}" "${HELPER_BIN}" "${PAM_MODULE}"
echo "removed ${DAEMON_BIN}, ${PAIR_BIN}, ${HELPER_BIN}, ${PAM_MODULE}"

# restore_pam_file puts back the newest .orig-* backup of a PAM service
# file, or strips the pam_phone_approve.so line if no backup exists.
# The .orig-* backups are never deleted (pre-install state is kept).
restore_pam_file() {
    local pam_file="$1"
    local newest_backup=""
    local f

    echo "== PAM restore (${pam_file}) =="
    for f in "${pam_file}".orig-*; do
        [[ -e "${f}" ]] || continue
        if [[ -z "${newest_backup}" ]] || [[ "${f}" -nt "${newest_backup}" ]]; then
            newest_backup="${f}"
        fi
    done
    if [[ -n "${newest_backup}" ]]; then
        cp -p "${newest_backup}" "${pam_file}"
        echo "restored ${pam_file} from ${newest_backup} (backup kept)"
    else
        if grep -q 'pam_phone_approve.so' "${pam_file}"; then
            sed -i '/pam_phone_approve.so/d' "${pam_file}"
            echo "removed pam_phone_approve.so line from ${pam_file} (no backup found)"
        else
            echo "no backup found and no module line present — ${pam_file} untouched"
        fi
    fi
}

for pam_file in "${PAM_FILES[@]}"; do
    restore_pam_file "${pam_file}"
done

echo "== state dirs =="
rm -rf "${TLS_DIR}" "${KEYS_DIR}"
echo "removed ${TLS_DIR} (cert+key) and ${KEYS_DIR} (paired keys)"
# /run/phone-fprint-auth is a systemd RuntimeDirectory and is cleaned up
# automatically when the unit stops — nothing to do here.
echo "/run/phone-fprint-auth is a systemd RuntimeDirectory — auto-removed on unit stop"

echo
echo "== rollback complete =="
echo "  unit:     disabled + removed"
echo "  binaries: ${DAEMON_BIN}, ${PAIR_BIN}, ${HELPER_BIN}, ${PAM_MODULE} removed"
echo "  pam:      ${PAM_FILES[*]} restored from backup (or module line stripped)"
echo "  state:    ${TLS_DIR} + ${KEYS_DIR} removed (${STATE_PARENT} left in place)"
