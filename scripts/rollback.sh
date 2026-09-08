#!/usr/bin/env bash
# Revert the phone fingerprint approval installation:
#   - disable + remove the systemd unit
#   - remove the daemon, helper and PAM module binaries
#   - restore /etc/pam.d/sudo from the newest .orig-* backup
#     (or strip the pam_phone_approve.so line if no backup exists)
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
PAM_FILE="/etc/pam.d/sudo"

echo "== systemd =="
# Ignore failures when the unit is already disabled/inactive/absent.
systemctl disable --now phone-approve-daemon 2>/dev/null || true
rm -f "${UNIT}"
systemctl daemon-reload
echo "disabled + removed phone-approve-daemon unit"

echo "== binaries =="
rm -f "${DAEMON_BIN}" "${PAIR_BIN}" "${HELPER_BIN}" "${PAM_MODULE}"
echo "removed ${DAEMON_BIN}, ${PAIR_BIN}, ${HELPER_BIN}, ${PAM_MODULE}"

echo "== PAM restore (${PAM_FILE}) =="
newest_backup=""
for f in "${PAM_FILE}".orig-*; do
    [[ -e "${f}" ]] || continue
    if [[ -z "${newest_backup}" ]] || [[ "${f}" -nt "${newest_backup}" ]]; then
        newest_backup="${f}"
    fi
done
if [[ -n "${newest_backup}" ]]; then
    cp -p "${newest_backup}" "${PAM_FILE}"
    rm -f "${newest_backup}"
    echo "restored ${PAM_FILE} from ${newest_backup} (backup removed)"
else
    if grep -q 'pam_phone_approve.so' "${PAM_FILE}"; then
        sed -i '/pam_phone_approve.so/d' "${PAM_FILE}"
        echo "removed pam_phone_approve.so line from ${PAM_FILE} (no backup found)"
    else
        echo "no backup found and no module line present — ${PAM_FILE} untouched"
    fi
fi

echo
echo "== rollback complete =="
echo "  unit:     disabled + removed"
echo "  binaries: ${DAEMON_BIN}, ${PAIR_BIN}, ${HELPER_BIN}, ${PAM_MODULE} removed"
echo "  pam:      ${PAM_FILE} restored from backup (or module line stripped)"
