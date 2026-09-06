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
| `daemon/` | Go single-binary HTTP service on port 8766. Holds pending sessions, issues nonces, verifies signed decisions. Endpoints: `POST /v1/session`, `GET /v1/session/{id}`, `POST /v1/session/{id}/decision` (signed), `GET /v1/pending?wait=60` (long-poll), `GET /healthz`. |
| `pam/pam_phone_approve.c` | Native C PAM module. `pam_sm_authenticate` creates a session and polls up to 60s, returns `PAM_SUCCESS` on approve, `PAM_AUTH_ERR` otherwise. |
| `pam/phone-approve-t0.sh` | Legacy T0 pam_exec helper. De-risk only; not wired into the final system. |
| `scripts/install.sh` | Root install: builds and installs daemon, helper, module and systemd unit; creates the `phonefprint` user; wires the module into `/etc/pam.d/sudo` and `/etc/pam.d/polkit-1`. |
| `scripts/rollback.sh` | Reverses the install and restores the original PAM files. |
| `scripts/phone-approve` | Pair CLI (root): `pair <name> <pubkey_b64>`, `list`, `remove <name>`. |
| `scripts/phone-sim` | Simulator for testing. Long-polls, signs and posts decisions like a real phone. |
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
4. Enables and starts `phone-approve-daemon` (listens on `:8766`, run as `phonefprint`).
5. Inserts `auth sufficient pam_phone_approve.so` as the first auth line in both `/etc/pam.d/sudo` and `/etc/pam.d/polkit-1`.

Before touching a PAM file, the script copies it to `<file>.orig-<timestamp>`. The module line sits above `@include common-auth`, so an approve skips the password prompt and anything else falls through to normal password auth.

## Pair your phone

1. Open the app on your phone. The pairing screen shows the device public key as a QR code and as copyable text.
2. Install the app and generate the keypair (done on first launch of the pairing screen).
3. On the machine, add the key under a name you choose:

```sh
sudo scripts/phone-approve pair my-phone <pubkey_b64>
```

For example, `sudo scripts/phone-approve pair pixel-8 AAAA...base64...`.

The daemon loads paired keys only at startup, so restart it after pairing:

```sh
sudo systemctl restart phone-approve-daemon
```

`sudo scripts/phone-approve list` shows paired keys; `sudo scripts/phone-approve remove <name>` removes one. The `pair` and `remove` commands require root because the key store is owned by `phonefprint`.

## Usage

1. Keep the app open and on the same LAN as the machine. (It long-polls the daemon; it cannot see pending requests while backgrounded or on another network.)
2. Run `sudo` or any pkexec action (for example `pkexec ...` or a GUI policy dialog).
3. The app shows the request with the user, service and tty context. Approve with your fingerprint.
4. The command proceeds. If you deny, or nothing happens within 60 seconds, the normal password prompt appears.

To test without a phone, use the simulator:

```sh
scripts/phone-sim --help
```

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

- **Session creation is unauthenticated.** Any device on the LAN can POST to `/v1/session` (rate-limited to 10 per minute) and cause prompt spam, or show a decoy prompt. Only approve when you just ran `sudo` or `pkexec` yourself, and check the context shown in the app.
- **Cleartext HTTP on the LAN.** The channel is not TLS-encrypted. Confidentiality is not the goal here; authenticity comes from the Ed25519 signature, and no secret or password travels over the wire.
- **Password fallback is preserved.** `pam_phone_approve.so` is `sufficient`, not `required`. If the daemon is down, you deny, or you time out, PAM falls through to `common-auth`, so you are never locked out of your own machine.

## Project layout

| Path | Contents |
| --- | --- |
| `app/` | Flutter Android app. Release APK at `app/build/app/outputs/flutter-apk/app-release.apk`. |
| `daemon/` | Go approval daemon: HTTP surface, session store, key loading, Ed25519 verification, unit tests. |
| `etc/` | Systemd unit and related config. |
| `pam/` | PAM module C source, legacy T0 helper, build Makefile. |
| `scripts/` | `install.sh`, `rollback.sh`, `phone-approve` pair CLI, `phone-sim` simulator. |
