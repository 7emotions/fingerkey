#!/usr/bin/env bash
# Install FingerKey from PRE-BUILT binaries (no Go toolchain, no compilation).
# This is the script shipped inside the GitHub Release tarball; it installs the
# binaries the CI already built, instead of rebuilding them like scripts/install.sh.
#
# Run from the extracted release tarball, which must contain:
#   fingerkeyd  fingerkey  pam_fingerkey.so  fingerkeyd.service
#   install.sh (this file)
#
# Usage: sudo ./install.sh
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "error: must run as root (sudo $0)" >&2
    exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON_BIN="/usr/local/libexec/fingerkeyd"
PAIR_BIN="/usr/local/bin/fingerkey"
PAM_MODULE="/usr/lib/x86_64-linux-gnu/security/pam_fingerkey.so"
UNIT_DST="/etc/systemd/system/fingerkeyd.service"
DAEMON_USER="phonefprint"
KEYS_PARENT="/var/lib/phone-fprint-auth"
KEYS_DIR="${KEYS_PARENT}/keys"
TLS_DIR="${KEYS_PARENT}/tls"
PAM_LINE="auth sufficient pam_fingerkey.so"

for f in fingerkeyd fingerkey pam_fingerkey.so fingerkeyd.service; do
    [[ -f "${HERE}/${f}" ]] || { echo "error: missing ${f} in ${HERE} — extract the full tarball" >&2; exit 1; }
done

echo "== system user =="
if id -u "${DAEMON_USER}" &>/dev/null; then
    echo "user ${DAEMON_USER} already exists"
else
    useradd --system --no-create-home --shell /usr/sbin/nologin "${DAEMON_USER}"
    echo "created user ${DAEMON_USER}"
fi

echo "== key store + tls dirs =="
install -d -m 0755 "${KEYS_PARENT}"
install -d -o "${DAEMON_USER}" -g "${DAEMON_USER}" -m 0700 "${KEYS_DIR}"
install -d -o "${DAEMON_USER}" -g "${DAEMON_USER}" -m 0700 "${TLS_DIR}"

echo "== binaries =="
install -o root -g root -m 0755 "${HERE}/fingerkeyd" "${DAEMON_BIN}"
install -o root -g root -m 0755 "${HERE}/fingerkey" "${PAIR_BIN}"
install -o root -g root -m 0644 "${HERE}/pam_fingerkey.so" "${PAM_MODULE}"
install -o root -g root -m 0644 "${HERE}/fingerkeyd.service" "${UNIT_DST}"

echo "== systemd =="
systemctl daemon-reload
systemctl enable --now fingerkeyd

echo "== PAM wiring =="
for pam_file in /etc/pam.d/sudo /etc/pam.d/polkit-1; do
    if grep -q 'pam_fingerkey.so' "${pam_file}"; then
        echo "pam: '${PAM_LINE}' already present in ${pam_file} — skipping"
    else
        cp -p "${pam_file}" "${pam_file}.orig-$(date +%s)"
        sed -i "/^@include[[:space:]]\\+common-auth\$/i ${PAM_LINE}" "${pam_file}"
        echo "pam: inserted '${PAM_LINE}' into ${pam_file}"
    fi
done

echo
echo "== install complete =="
echo "  daemon:   ${DAEMON_BIN} (running as ${DAEMON_USER})"
echo "  pair cli: ${PAIR_BIN}"
echo "  module:   ${PAM_MODULE}"
echo "  unit:     ${UNIT_DST} (enabled + started)"
echo "  pam:      /etc/pam.d/sudo + /etc/pam.d/polkit-1 -> ${PAM_LINE}"
