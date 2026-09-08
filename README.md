# phone-fprint-auth

Replace sudo/pkexec password entry with fingerprint approval from your phone over Bluetooth.

When a privilege escalation runs, a PAM module asks a local daemon to create a pending approval session. The daemon pushes the request to your phone over a Bluetooth Classic SPP link, you unlock it with your fingerprint, and the phone sends back an Ed25519-signed decision. No password is ever typed or transmitted.

## How it works

```
sudo / pkexec
  → PAM module (pam_phone_approve) creates a session on the daemon
  → daemon issues a random nonce + context (user, service, tty)
  → daemon pushes a {"type":"pending",...} frame to the phone over the SPP link
  → you approve or deny with BiometricPrompt (fingerprint)
  → phone signs the decision with its private key, sends {"type":"decision",...}
  → daemon verifies the Ed25519 signature, answers decision-result,
    returns PAM_SUCCESS or PAM_AUTH_ERR
```

Approve: sudo/pkexec proceeds. Deny or timeout (60s): the PAM module falls through and the normal password prompt appears. Phone not connected or app closed: the daemon answers session creation with 503 and PAM falls back to the password prompt immediately — no waiting.

## Transport

The phone link is **Bluetooth Classic SPP** (Serial Port Profile over RFCOMM). The protected machine is the SPP **server** (a BlueZ `org.bluez.Profile1` profile advertised on RFCOMM channel 22); the phone is the client. Bluetooth pairing **bonds** the two devices and encrypts the RFCOMM link — there is no TLS, no certificate and no application-layer PIN; the link's confidentiality comes from BT bonding.

Frames are length-prefixed JSON (4-byte big-endian length + payload):

- `{"type":"pending",...}` — daemon → phone, one per new session
- `{"type":"decision",...}` — phone → daemon, signed approve/deny
- `{"type":"decision-result",...}` — daemon → phone, verdict on the decision

## Components

| Path | What it is |
| --- | --- |
| `daemon/` | Go single binary `phone-approve-daemon`, run as the `phonefprint` user. Holds pending sessions, issues nonces, verifies signed decisions. Two surfaces: the root-only unix socket `/run/phone-fprint-auth/daemon.sock` (`POST /v1/session`, `GET /v1/session/{id}`, used by the PAM module) and the phone link (BlueZ SPP server). Flags: `-adapter` (HCI adapter), `-socket`, `-keys-dir`, `-phone-sim-socket` — the last listens on a unix socket that accepts plain framed streams exactly like an SPP connection, a test transport for `phone-sim` and the local E2E. |
| `pam/pam_phone_approve.c` | Native C PAM module. `pam_sm_authenticate` creates a session and polls up to 60s, returns `PAM_SUCCESS` on approve, `PAM_AUTH_ERR` otherwise. A non-2xx session creation (daemon down, no paired keys, no phone connected) fails fast instead of hanging the 60s. The `socket=<path>` argument overrides the daemon socket (used by tests and throwaway PAM services). |
| `pam/phone-approve-t0.sh` | Legacy T0 pam_exec helper. De-risk only; not wired into the final system. |
| `scripts/install.sh` | Root install: builds and installs daemon, helper, module, pair CLI and systemd unit; creates the `phonefprint` user and key store; installs the D-Bus policy letting the daemon own `com.phonefprint.auth` (the SPP profile name); wires the module into `/etc/pam.d/sudo` and `/etc/pam.d/polkit-1`. |
| `scripts/rollback.sh` | Reverses the install and restores the original PAM files. |
| `scripts/phone-approve` | Pair CLI (root): `bt-pair`, `pair <name> <pubkey_b64>`, `list`, `remove <name>`. |
| `scripts/phone-sim` | Simulator for testing. Dials the daemon's `-phone-sim-socket` and speaks the same framed protocol as a real phone: `-socket <path> -key <priv_b64> [-decision approve|deny] [-once]`. |
| `app/` | Flutter Android app (package `com.phonefprint.auth`). Pairing screen scans for the computer, bonds over Bluetooth and shows the device public key; approval screen receives pending frames and signs with BiometricPrompt. |

## Prerequisites

Target OS is Ubuntu/Debian. On the machine being protected:

- Go (the daemon is built from source by `install.sh`)
- `gcc`, `make` (PAM module build)
- `curl`, `jq` (manual daemon checks)
- `pamtester`, `libpam0g-dev` (PAM testing and headers)
- `shellcheck` (script linting)
- BlueZ (`bluetooth.service`) with a Bluetooth adapter

To build the Android app:

- Flutter with the Android SDK toolchain (`flutter analyze`, `flutter test`, `flutter build apk --release`)

You also need an Android phone with Bluetooth, bonded to the protected machine.

## Build and install

From a checkout of this repo:

```sh
sudo ./scripts/install.sh
```

Run as root (the script refuses otherwise; `sudo` is fine). The script is **idempotent**, so re-running is safe. What it does:

1. Builds the daemon and the PAM module.
2. Installs `phone-approve-daemon` to `/usr/local/libexec/`, `phone-approve` to `/usr/local/bin/`, the PAM module to `/usr/lib/x86_64-linux-gnu/security/`, the systemd unit to `/etc/systemd/system/`, and the D-Bus policy to `/etc/dbus-1/system.d/phone-fprint-auth.conf`.
3. Creates the system user `phonefprint` and `/var/lib/phone-fprint-auth/keys/` (owned by `phonefprint`, mode 0700).
4. Enables and starts `phone-approve-daemon` (unix socket + BlueZ SPP server, run as `phonefprint`).
5. Inserts `auth sufficient pam_phone_approve.so` as the first auth line in both `/etc/pam.d/sudo` and `/etc/pam.d/polkit-1`.

Before touching a PAM file, the script copies it to `<file>.orig-<timestamp>`. The module line sits above `@include common-auth`, so an approve skips the password prompt and anything else falls through to normal password auth.

If Go module downloads are blocked from your network, build the daemon and tools with the China proxy:

```sh
GOPROXY=https://goproxy.cn,direct GOSUMDB=off go build ./...
```

## Pair your phone

1. Make the machine discoverable and pairable over Bluetooth:

```sh
sudo phone-approve bt-pair
```

2. On the phone, open the app and start pairing. The app scans for the computer; tap it and bond (confirm the same pairing code on both devices if asked). Bonding is what encrypts the SPP link.
3. The app generates its Ed25519 keypair on first launch and shows the public key. On the machine, register that key under a name you choose:

```sh
sudo phone-approve pair my-phone <pubkey_b64>
```

For example, `sudo phone-approve pair pixel-8 AAAA...base64...`.

The daemon loads paired keys only at startup, so restart it after pairing:

```sh
sudo systemctl restart phone-approve-daemon
```

`sudo phone-approve list` shows paired keys; `sudo phone-approve remove <name>` removes one. The `pair`, `remove` and `bt-pair` commands require root because the key store is owned by `phonefprint`.

## Usage

1. Keep the app open, Bluetooth on, and the phone bonded to the machine. (The daemon only pushes pending requests over an active SPP connection; the app cannot see them while closed or disconnected.)
2. Run `sudo` or any pkexec action (for example `pkexec ...` or a GUI policy dialog).
3. The app shows the request with the user, service and tty context. Approve with your fingerprint.
4. The command proceeds. If you deny, or nothing happens within 60 seconds, the normal password prompt appears.
5. If the app is closed or no phone is connected, the daemon answers session creation with 503 and PAM falls back to the password prompt immediately — no waiting.

To test without a phone, use the simulator over the `-phone-sim-socket` test transport:

```sh
go run ./scripts/phone-sim -socket /tmp/e2e-sim.sock -key <priv_b64> -decision approve
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

- **Bluetooth only.** The phone link is Bluetooth Classic SPP over RFCOMM; it is not reachable from the LAN or the internet. Bluetooth pairing bonds the devices and encrypts the link: only a bonded device can connect to the SPP server, and frames are protected in transit by BT link encryption. There is no TLS layer, no certificate to pin, and no application PIN.
- **Signed challenge, not a static token.** The device signs a message that binds the fresh per-session nonce and the context (`user`, `service`, `tty`). The nonce is one-time, the session expires after 60 seconds, and the context is part of the signed payload, so a captured decision cannot be replayed against a different request.
- **Approval authority is granted solely by explicit pubkey registration.** Only Ed25519 public keys added by `sudo phone-approve pair` can produce an accepted decision; anything else is rejected as `unpaired-key`. Bonding at the Bluetooth level alone is not enough to approve.
- **Decisions are Ed25519-signed and nonce-bound.** The phone signs the pinned byte format below with its private key; the daemon re-derives the same bytes and verifies against registered public keys.
- **No password is ever transmitted.** Not by the PAM module, not by the daemon, not by the phone.
- **Only the public key lives on the daemon.** The phone keeps its private key. Compromising the daemon does not leak anything that can sign an approval.
- **The signed byte format** is `"phone-fprint-auth/v1" || 0x00 || action || 0x00 || u8len(user) || user || u8len(service) || service || u8len(tty) || tty || nonce`, Ed25519, with single-byte length prefixes.

Residual risks:

- **Session creation is root-only.** `POST /v1/session` and `GET /v1/session/{id}` live on the unix socket `/run/phone-fprint-auth/daemon.sock` (socket `0700`, parent dir `0700`). Only root — or a setuid-root process such as the PAM module — can create or poll a session, so nobody else can forge prompt spam or decoy requests.
- **The phone link trusts Bluetooth pairing.** Classic BT SSP encryption is strong against casual attackers but has known protocol weaknesses; an attacker who can defeat BT link encryption on the air interface could read frames. Authenticity of decisions still comes from the Ed25519 signature, so a passive reader cannot forge an approval. Keep the phone within Bluetooth range and be aware of nearby devices during pairing.
- **Fast fallback without a phone.** With the app closed, no phone connected, or no keys paired, the daemon answers session creation with 503 and PAM falls back to the password prompt immediately — there is no 60s wait and no lockout risk. `pam_phone_approve.so` is `sufficient`, not `required`, so the password path always remains.

## Project layout

| Path | Contents |
| --- | --- |
| `app/` | Flutter Android app. Release APK at `app/build/app/outputs/flutter-apk/app-release.apk`. |
| `daemon/` | Go approval daemon: unix-socket surface, BlueZ SPP server, session store, key loading, Ed25519 verification, unit tests. |
| `etc/` | Systemd unit and D-Bus policy. |
| `pam/` | PAM module C source, legacy T0 helper, build Makefile. |
| `scripts/` | `install.sh`, `rollback.sh`, `phone-approve` pair CLI, `phone-sim` simulator. |
