#!/usr/bin/env bash
# Install the phone fingerprint approval stack:
#   - build + install the approval daemon, helper and PAM module
#   - create the dedicated phonefprint system user and key store dir
#   - install + enable the systemd unit
#   - wire pam_phone_approve.so into /etc/pam.d/sudo (above @include common-auth)
#
# Idempotent — safe to re-run. Must run as root.
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "error: must run as root (sudo $0)" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

DAEMON_BIN="/usr/local/libexec/phone-approve-daemon"
PAIR_BIN="/usr/local/bin/phone-approve"
HELPER_BIN="/usr/local/libexec/phone-approve-t0"
PAM_MODULE="/usr/lib/x86_64-linux-gnu/security/pam_phone_approve.so"
UNIT_SRC="etc/systemd/phone-approve-daemon.service"
UNIT_DST="/etc/systemd/system/phone-approve-daemon.service"
KEYS_PARENT="/var/lib/phone-fprint-auth"
KEYS_DIR="/var/lib/phone-fprint-auth/keys"
DAEMON_USER="phonefprint"
PAM_LINE="auth sufficient pam_phone_approve.so"

# wire_pam_file inserts the approval module line into a PAM service file
# as the FIRST auth line, above @include common-auth. Idempotent.
wire_pam_file() {
    local file="$1"
    local backup

    if grep -q 'pam_phone_approve.so' "${file}"; then
        echo "pam: '${PAM_LINE}' already present in ${file} — skipping"
        return 0
    fi
    backup="${file}.orig-$(date +%s)"
    if [[ ! -e "${backup}" ]]; then
        cp -p "${file}" "${backup}"
        echo "pam: backed up ${file} -> ${backup}"
    fi
    # Insert as the FIRST auth line, above @include common-auth.
    sed -i "/^@include[[:space:]]\\+common-auth\$/i ${PAM_LINE}" "${file}"
    if ! grep -q 'pam_phone_approve.so' "${file}"; then
        echo "error: failed to insert '${PAM_LINE}' into ${file}" >&2
        exit 1
    fi
    echo "pam: inserted '${PAM_LINE}' into ${file}"
}

echo "== build =="
mkdir -p /usr/local/libexec
go build -o "${DAEMON_BIN}" ./daemon
chown root:root "${DAEMON_BIN}"
chmod 0755 "${DAEMON_BIN}"
echo "built ${DAEMON_BIN}"

mkdir -p /usr/local/bin
go build -o "${PAIR_BIN}" ./scripts/phone-approve
chown root:root "${PAIR_BIN}"
chmod 0755 "${PAIR_BIN}"
echo "built ${PAIR_BIN}"

make -C pam
echo "built pam/pam_phone_approve.so"

echo "== system user =="
if id -u "${DAEMON_USER}" &>/dev/null; then
    echo "user ${DAEMON_USER} already exists"
else
    useradd --system --no-create-home --shell /usr/sbin/nologin "${DAEMON_USER}"
    echo "created user ${DAEMON_USER}"
fi

echo "== key store dir =="
install -d -m 0755 "${KEYS_PARENT}"
echo "ensured ${KEYS_PARENT} (0755, traversable by ${DAEMON_USER})"
install -d -o "${DAEMON_USER}" -g "${DAEMON_USER}" -m 0700 "${KEYS_DIR}"
echo "ensured ${KEYS_DIR} (${DAEMON_USER} 0700)"

echo "== install files =="
install -o root -g root -m 0755 pam/phone-approve-t0.sh "${HELPER_BIN}"
install -o root -g root -m 0644 pam/pam_phone_approve.so "${PAM_MODULE}"
install -o root -g root -m 0644 "${UNIT_SRC}" "${UNIT_DST}"
echo "installed ${HELPER_BIN}, ${PAM_MODULE}, ${UNIT_DST}"

echo "== systemd =="
systemctl daemon-reload
systemctl enable --now phone-approve-daemon
echo "enabled + started phone-approve-daemon"

echo "== PAM wiring =="
wire_pam_file /etc/pam.d/sudo
wire_pam_file /etc/pam.d/polkit-1

echo
echo "== install complete =="
echo "  daemon:   ${DAEMON_BIN} (running as ${DAEMON_USER})"
echo "  pair cli: ${PAIR_BIN}"
echo "  helper:   ${HELPER_BIN}"
echo "  module:   ${PAM_MODULE}"
echo "  unit:     ${UNIT_DST} (enabled + started)"
echo "  key dir:  ${KEYS_DIR} (${DAEMON_USER} 0700; parent ${KEYS_PARENT} 0755)"
echo "  pam:      /etc/pam.d/sudo + /etc/pam.d/polkit-1 -> ${PAM_LINE} above @include common-auth"
