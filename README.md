# phone-fprint-auth

Replace sudo/pkexec password entry with fingerprint approval from your phone over the local LAN.

When a privilege escalation runs, a PAM module asks a local daemon to create a pending approval session. Your phone sees the pending request, you unlock it with your fingerprint, and it sends back an Ed25519-signed decision. No password is ever typed or transmitted.

## How it works

```
sudo / pkexec
  → PAM module (pam_phone_approve) creates a session on the daemon
  → daemon issues a random nonce + context (user, service, tty)
  → your phone long-polls GET /v1/pending, shows the request
  → you approve or deny with BiometricPrompt (fingerprint)
  → phone signs the decision with its private key and POSTs it
  → daemon verifies the Ed25519 signature, returns PAM_SUCCESS or PAM_AUTH_ERR
```

Approve: sudo/pkexec proceeds. Deny or timeout (60s): the PAM module falls through and the normal password prompt appears.

## Components

| Path | What it is |
| --- | --- |
| `daemon/` | Go single-binary HTTPS-only service on port 8766. Holds pending sessions, issues nonces, verifies signed decisions. Endpoints are split across two listeners: the root-only unix socket `/run/phone-fprint-auth/daemon.sock` (`POST /v1/session`, `GET /v1/session/{id}`) and the TLS TCP listener (`GET /v1/pending?wait=60` (long-poll), `POST /v1/session/{id}/decision` (signed), `GET /healthz`). The TLS cert lives at `/var/lib/phone-fprint-auth/tls/` (`cert.pem` + `key.pem`); print its fingerprint with `sudo phone-approve tls-fingerprint`. |
| `pam/pam_phone_approve.c` | Native C PAM module. `pam_sm_authenticate` creates a session and polls up to 60s, returns `PAM_SUCCESS` on approve, `PAM_AUTH_ERR` otherwise. |
| `pam/phone-approve-t0.sh` | Legacy T0 pam_exec helper. De-risk only; not wired into the final system. |
| `scripts/install.sh` | Root install: builds and installs daemon, helper, module and systemd unit; creates the `phonefprint` user; wires the module into `/etc/pam.d/sudo` and `/etc/pam.d/polkit-1`. |
| `scripts/rollback.sh` | Reverses the install and restores the original PAM files. |
| `scripts/phone-approve` | Pair CLI (root): `pair <name> <pubkey_b64>`, `list`, `remove <name>`, `tls-fingerprint`. |
| `scripts/phone-sim` | Simulator for testing. Long-polls, signs and posts decisions like a real phone over TLS (`-pin <fingerprint>` or `-insecure` for testing). |
| `app/` | Flutter Android app (package `com.phonefprint.auth`). Pairing screen shows the device public key as QR or copyable text; approval screen long-polls and signs with BiometricPrompt. |

## Prerequisites

Target OS is Ubuntu/Debian. On the machine being protected:

- Go (the daemon is built from source by `install.sh`)
- `gcc`, `make` (PAM module build)
- `curl`, `jq` (manual daemon checks)
- `pamtester`, `libpam0g-dev` (PAM testing and headers)
- `shellcheck` (script linting)

To build the Android app:

- Flutter with the Android SDK toolchain (`flutter analyze`, `flutter test`, `flutter build apk --release`)

You also need an Android phone on the same LAN as the protected machine.

## Build and install

From a checkout of this repo:

```sh
sudo ./scripts/install.sh
```

Run as root (the script refuses otherwise; `sudo` is fine). The script is **idempotent**, so re-running is safe. What it does:

1. Builds the daemon and the PAM module.
2. Installs `phone-approve-daemon` to `/usr/local/libexec/`, the PAM module to `/usr/lib/x86_64-linux-gnu/security/`, and the systemd unit to `/etc/systemd/system/`.
3. Creates the system user `phonefprint` and `/var/lib/phone-fprint-auth/keys/` (owned by `phonefprint`, mode 0700).
4. Generates a self-signed TLS certificate at `/var/lib/phone-fprint-auth/tls/` (`cert.pem` 0644, `key.pem` 0600, owned by `phonefprint`) — only if absent; re-running keeps the existing cert, since regenerating breaks pinned phones.
5. Enables and starts `phone-approve-daemon` (HTTPS-only on `:8766`, run as `phonefprint`).
6. Inserts `auth sufficient pam_phone_approve.so` as the first auth line in both `/etc/pam.d/sudo` and `/etc/pam.d/polkit-1`.

Print the certificate fingerprint — the phone app needs it at pairing:

```sh
sudo phone-approve tls-fingerprint
```

Before touching a PAM file, the script copies it to `<file>.orig-<timestamp>`. The module line sits above `@include common-auth`, so an approve skips the password prompt and anything else falls through to normal password auth.

## Pair your phone

1. Open the app on your phone. The pairing screen shows the device public key as a QR code and as copyable text.
2. Install the app and generate the keypair (done on first launch of the pairing screen).
3. In the app, enter the daemon URL and the certificate fingerprint. The URL must be `https://<machine-ip>:8766` (plain `http://` is refused). The fingerprint is the 64-lowercase-hex SHA-256 of the daemon's TLS cert, shown on the machine by `sudo phone-approve tls-fingerprint`. The app pins it and refuses to talk to the daemon if the presented cert does not match.
4. On the machine, add the key under a name you choose:

```sh
sudo phone-approve pair my-phone <pubkey_b64>
```

For example, `sudo phone-approve pair pixel-8 AAAA...base64...`.

The daemon loads paired keys only at startup, so restart it after pairing:

```sh
sudo systemctl restart phone-approve-daemon
```

`sudo phone-approve list` shows paired keys; `sudo phone-approve remove <name>` removes one. The `pair` and `remove` commands require root because the key store is owned by `phonefprint`.

## Usage

1. Keep the app open and on the same LAN as the machine. (It long-polls the daemon; it cannot see pending requests while backgrounded or on another network.)
2. Run `sudo` or any pkexec action (for example `pkexec ...` or a GUI policy dialog).
3. The app shows the request with the user, service and tty context. Approve with your fingerprint.
4. The command proceeds. If you deny, or nothing happens within 60 seconds, the normal password prompt appears.

To test without a phone, use the simulator:

```sh
go run ./scripts/phone-sim --help
```

## Audit

The daemon writes one `key=value` line per event to its journal (captured by journald from stderr):

```sh
journalctl -u phone-approve-daemon -o cat | grep 'event='
```

Events:

- `event=session-created` — a PAM module created a session (`id`, `user`, `service`, `tty`).
- `event=decision` — a signed decision was accepted (`id`, `decision=approve|deny`, `key=<paired name>` — the key that signed it).
- `event=decision-failed` — a decision was rejected (`id`, `reason`: `bad-decision`, `invalid-signature`, `unpaired-key`, `unknown-session`, `not-pending`).

## Rollback

```sh
sudo ./scripts/rollback.sh
```

This reverses the install: stops and removes the systemd unit, removes the binaries and key store, and restores `/etc/pam.d/sudo` and `/etc/pam.d/polkit-1` from their `.orig-*` backups.

## Threat model and security notes

- **LAN only.** The daemon binds `:8766` on the local network. Do not expose it to the internet.
- **Signed challenge, not a static token.** The device signs a message that binds the fresh per-session nonce and the context (`user`, `service`, `tty`). The nonce is one-time, the session expires after 60 seconds, and the context is part of the signed payload, so a captured decision cannot be replayed against a different request.
- **No password is ever transmitted.** Not by the PAM module, not by the daemon, not by the phone.
- **Only the public key lives on the daemon.** The phone keeps its private key. Compromising the daemon does not leak anything that can sign an approval.
- **The signed byte format** is `"phone-fprint-auth/v1" || 0x00 || action || 0x00 || u8len(user) || user || u8len(service) || service || u8len(tty) || tty || nonce`, Ed25519, with single-byte length prefixes.

Residual risks:

- **Session creation is root-only.** `POST /v1/session` and `GET /v1/session/{id}` live on the unix socket `/run/phone-fprint-auth/daemon.sock` (socket `0700`, parent dir `0700`). Only root — or a setuid-root process such as the PAM module — can create or poll a session, so a LAN peer cannot forge prompt spam or decoy requests.
- **The phone link is TLS-encrypted.** The TCP listener is HTTPS-only (TLS ≥ 1.2) with a self-signed certificate whose SHA-256 the app pins at pairing; there is no plain-HTTP fallback. Authenticity of decisions still comes from the Ed25519 signature; TLS adds confidentiality and tamper resistance on the LAN.
- **`/v1/pending` is readable by any LAN peer over TLS.** There is no client authentication on the phone surface, so a LAN peer can long-poll and read pending requests. Only approve when you just ran `sudo` or `pkexec` yourself, and check the context shown in the app.
- **Password fallback is preserved.** `pam_phone_approve.so` is `sufficient`, not `required`. If the daemon is down, you deny, or you time out, PAM falls through to `common-auth`, so you are never locked out of your own machine.

## Project layout

| Path | Contents |
| --- | --- |
| `app/` | Flutter Android app. Release APK at `app/build/app/outputs/flutter-apk/app-release.apk`. |
| `daemon/` | Go approval daemon: HTTP surface, session store, key loading, Ed25519 verification, unit tests. |
| `etc/` | Systemd unit and related config. |
| `pam/` | PAM module C source, legacy T0 helper, build Makefile. |
| `scripts/` | `install.sh`, `rollback.sh`, `phone-approve` pair CLI, `phone-sim` simulator. |
