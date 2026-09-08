// Command phone-approve manages the paired phone public keys that the
// phone-fprint-auth daemon verifies decisions against. Each paired key is a
// file /var/lib/phone-fprint-auth/keys/<name>.pub containing the standard,
// padded base64 encoding of a 32-byte Ed25519 public key, mode 0600, owned by
// the phonefprint user (so the daemon can read it and nobody else can write
// it).
//
// Usage:
//
//	phone-approve pair <name> <pubkey_b64>
//	phone-approve list
//	phone-approve remove <name>
//	phone-approve bt-pair
//
// pair and remove require root (the keys directory is root/phonefprint-owned);
// list and bt-pair do not.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// keysDir is where the daemon loads <name>.pub files from (daemon default
// -keys-dir). It must match the daemon's configuration.
const keysDir = "/var/lib/phone-fprint-auth/keys"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "pair":
		if len(os.Args) != 4 {
			usage()
			os.Exit(1)
		}
		err = pair(os.Args[2], os.Args[3])
	case "list":
		err = list()
	case "remove":
		if len(os.Args) != 3 {
			usage()
			os.Exit(1)
		}
		err = remove(os.Args[2])
	case "bt-pair":
		err = btPair()
	default:
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "phone-approve:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: phone-approve <command>
  pair <name> <pubkey_b64>   pair a phone: store its Ed25519 public key
  list                       list paired key names
  remove <name>              unpair a phone
  bt-pair                    make this machine discoverable so the phone app can bond (Bluetooth)`)
}

// pair validates the public key and stores it under keysDir as <name>.pub,
// mode 0600, owned by the phonefprint user (falling back to the current
// euid when no phonefprint user exists).
func pair(name, pubkeyB64 string) error {
	if err := requireRoot("pair"); err != nil {
		return err
	}
	if err := validateName(name); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubkeyB64))
	if err != nil {
		return fmt.Errorf("invalid public key: not standard padded base64: %v", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key: decoded %d bytes, want %d (Ed25519)", len(raw), ed25519.PublicKeySize)
	}

	uid, gid, ok := lookupPhonefprint()
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return err
	}
	// MkdirAll also creates missing parents with the same 0700 mode; the
	// parent /var/lib/phone-fprint-auth must be world-traversable (0755) so
	// the daemon, running as phonefprint, can reach the keys dir. The keys
	// dir itself stays 0700.
	_ = os.Chmod(filepath.Dir(keysDir), 0755)
	if ok {
		if err := os.Chown(keysDir, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %v", keysDir, err)
		}
	}
	path := filepath.Join(keysDir, name+".pub")
	if err := os.WriteFile(path, []byte(pubkeyB64), 0600); err != nil {
		return err
	}
	if ok {
		if err := os.Chown(path, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %v", path, err)
		}
	}
	fmt.Printf("paired %q: %s\n", name, path)
	return nil
}

// list prints the name (without .pub) of every paired key, one per line.
// A missing keys directory is not an error — nothing is paired yet.
func list() error {
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		names = append(names, strings.TrimSuffix(e.Name(), ".pub"))
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Println(n)
	}
	return nil
}

// remove deletes the paired key <name>.pub.
func remove(name string) error {
	if err := requireRoot("remove"); err != nil {
		return err
	}
	if err := validateName(name); err != nil {
		return err
	}
	path := filepath.Join(keysDir, name+".pub")
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no paired key named %q", name)
		}
		return err
	}
	fmt.Printf("unpaired %q\n", name)
	return nil
}

// btPair makes this machine Bluetooth-discoverable so the phone app can find
// and bond to it, prints the adapter MAC and hostname for the operator, and
// turns discoverability back off after ~60 seconds. Pairing stays on (the
// BlueZ default), so re-pairing later does not need this command again.
func btPair() error {
	run := func(args ...string) error {
		cmd := exec.Command("bluetoothctl", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	if err := run("discoverable", "on"); err != nil {
		return fmt.Errorf("bluetoothctl discoverable on: %v", err)
	}
	if err := run("pairable", "on"); err != nil {
		return fmt.Errorf("bluetoothctl pairable on: %v", err)
	}

	out, err := exec.Command("bluetoothctl", "show").Output()
	if err != nil {
		return fmt.Errorf("bluetoothctl show: %v", err)
	}
	mac := ""
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "Controller" {
			mac = f[1]
			break
		}
	}
	if mac == "" {
		return fmt.Errorf("no controller address in bluetoothctl show output")
	}
	host, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("hostname: %v", err)
	}

	fmt.Printf("Bluetooth adapter: %s\n", mac)
	fmt.Printf("Hostname: %s\n", host)
	fmt.Println("Now bond from the phone (app → discover → tap the computer), then run 'sudo phone-approve pair <name> <pubkey>'")

	// ~60s to complete bonding on the phone, then stop advertising.
	// Best-effort: pairable stays on, which is the BlueZ default.
	time.Sleep(60 * time.Second)
	if err := run("discoverable", "off"); err != nil {
		fmt.Fprintf(os.Stderr, "phone-approve: warning: bluetoothctl discoverable off: %v\n", err)
	}
	return nil
}

// requireRoot rejects operations that write into the root/phonefprint-owned
// keys directory when not running as root.
func requireRoot(op string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%s requires root (run with sudo): %s is root/phonefprint-owned", op, keysDir)
	}
	return nil
}

// validateName rejects names that could escape keysDir or name the file
// itself (this tool runs as root — a traversal would be an arbitrary write).
func validateName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("invalid key name %q: must be non-empty and contain no path separators", name)
	}
	return nil
}

// lookupPhonefprint resolves the phonefprint user's uid/gid. ok is false when
// no such user exists, in which case files fall back to the current euid.
func lookupPhonefprint() (uid, gid int, ok bool) {
	u, err := user.Lookup("phonefprint")
	if err != nil {
		return 0, 0, false
	}
	uid, errU := strconv.Atoi(u.Uid)
	gid, errG := strconv.Atoi(u.Gid)
	if errU != nil || errG != nil {
		return 0, 0, false
	}
	return uid, gid, true
}
