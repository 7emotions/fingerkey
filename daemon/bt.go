package main

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/godbus/dbus/v5"
)

const (
	// sppProfilePath is the D-Bus object path the profile is exported on.
	sppProfilePath = dbus.ObjectPath("/com/phonefprint/auth")
	// sppProfileName is the well-known bus name the profile is owned under.
	sppProfileName = "com.phonefprint.auth"
	// sppUUID is the RFCOMM Serial Port Profile service UUID.
	sppUUID = "00001101-0000-1000-8000-00805F9B34FB"
	// sppChannel is the RFCOMM channel advertised in the SDP record.
	sppChannel = uint16(22)
	// sppAgentPath is the D-Bus object path the pairing agent is exported on.
	sppAgentPath = dbus.ObjectPath("/com/phonefprint/agent")
)

// sppConn and sppProfile hold the live D-Bus state past startSppServer's
// return: the connection's inWorker goroutine keeps serving incoming
// Profile1 method calls as long as the conn is referenced and open.
var (
	sppConn    *dbus.Conn
	sppProfile *sppProfileState
)

// startSppServer registers an org.bluez.Profile1 (RFCOMM SPP server) on the
// system bus and hands every accepted RFCOMM socket to startPhoneLink, so the
// connected phone flows through the same framed approval protocol as the
// sim-socket. Any failure is returned to the caller (which logs it as
// non-fatal): the daemon keeps serving the unix-socket surface without
// Bluetooth.
func startSppServer(adapter string, store *Store, keys map[string]ed25519.PublicKey) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("connect to system bus: %w", err)
	}

	// Resolve the -adapter flag to the Adapter1 object path and its MAC.
	managed, err := getManagedObjects(conn)
	if err != nil {
		conn.Close()
		return err
	}
	path, mac, err := selectAdapterPath(managed, adapter)
	if err != nil {
		conn.Close()
		return err
	}
	log.Printf("bluetooth: adapter %s resolved to %s (MAC %s)", adapter, path, mac)

	// Own the well-known name the profile lives under. DoNotQueue: a second
	// daemon instance (or a stale one) must not silently shadow this one.
	reply, err := conn.RequestName(sppProfileName, dbus.NameFlagDoNotQueue)
	if err != nil {
		conn.Close()
		return fmt.Errorf("request name %s: %w", sppProfileName, err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner && reply != dbus.RequestNameReplyAlreadyOwner {
		conn.Close()
		return fmt.Errorf("request name %s: not primary owner (reply=%d)", sppProfileName, reply)
	}

	profile := &sppProfileState{store: store, keys: keys}
	if err := conn.Export(profile, sppProfilePath, "org.bluez.Profile1"); err != nil {
		conn.Close()
		return fmt.Errorf("export profile: %w", err)
	}

	options := map[string]dbus.Variant{
		"Role":                  dbus.MakeVariant("server"),
		"Channel":               dbus.MakeVariant(sppChannel),
		"RequireAuthentication": dbus.MakeVariant(true),
		"Name":                  dbus.MakeVariant("phone-fprint-auth"),
	}
	call := conn.Object("org.bluez", "/org/bluez").Call(
		"org.bluez.ProfileManager1.RegisterProfile", 0, sppProfilePath, sppUUID, options)
	if call.Err != nil {
		conn.Export(nil, sppProfilePath, "org.bluez.Profile1") // undo the export
		conn.Close()
		return fmt.Errorf("register profile: %w", call.Err)
	}

	// Export and register the NoInputNoOutput pairing agent: without it
	// bluetoothd rejects pairing with "Authentication attempt without agent".
	// Every agent callback auto-accepts, so the phone can bond inside the
	// 60s bt-pair window; approval authority still comes from pubkey
	// registration, never from bonding.
	agent := &sppAgent{}
	if err := conn.Export(agent, sppAgentPath, "org.bluez.Agent1"); err != nil {
		conn.Export(nil, sppProfilePath, "org.bluez.Profile1")
		conn.Close()
		return fmt.Errorf("export pairing agent: %w", err)
	}
	agentManager := conn.Object("org.bluez", "/org/bluez")
	if call := agentManager.Call(
		"org.bluez.AgentManager1.RegisterAgent", 0, sppAgentPath, "NoInputNoOutput"); call.Err != nil {
		conn.Export(nil, sppAgentPath, "org.bluez.Agent1")
		conn.Export(nil, sppProfilePath, "org.bluez.Profile1")
		conn.Close()
		return fmt.Errorf("register pairing agent: %w", call.Err)
	}
	if call := agentManager.Call(
		"org.bluez.AgentManager1.RequestDefaultAgent", 0, sppAgentPath); call.Err != nil {
		conn.Export(nil, sppAgentPath, "org.bluez.Agent1")
		conn.Export(nil, sppProfilePath, "org.bluez.Profile1")
		conn.Close()
		return fmt.Errorf("request default pairing agent: %w", call.Err)
	}

	// Keep the live D-Bus state referenced and unregister best-effort on
	// shutdown, then exit so SIGINT/SIGTERM still terminate the process.
	sppConn = conn
	sppProfile = profile
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		if err := conn.Object("org.bluez", "/org/bluez").Call(
			"org.bluez.ProfileManager1.UnregisterProfile", 0, sppProfilePath).Err; err != nil {
			log.Printf("bluetooth: unregister profile: %v", err)
		}
		if err := conn.Object("org.bluez", "/org/bluez").Call(
			"org.bluez.AgentManager1.UnregisterAgent", 0, sppAgentPath).Err; err != nil {
			log.Printf("bluetooth: unregister pairing agent: %v", err)
		}
		conn.Close()
		os.Exit(0)
	}()

	log.Printf("spp profile registered (uuid=%s, channel=%d, adapter=%s)", sppUUID, sppChannel, path)
	log.Printf("pairing agent registered (path=%s, capability=NoInputNoOutput)", sppAgentPath)
	return nil
}

// getManagedObjects fetches the BlueZ object tree from the system bus.
func getManagedObjects(conn *dbus.Conn) (map[dbus.ObjectPath]map[string]map[string]dbus.Variant, error) {
	var managed map[dbus.ObjectPath]map[string]map[string]dbus.Variant
	err := conn.Object("org.bluez", "/").Call(
		"org.freedesktop.DBus.ObjectManager.GetManagedObjects", 0).Store(&managed)
	if err != nil {
		return nil, fmt.Errorf("get managed objects: %w", err)
	}
	return managed, nil
}

// selectAdapterPath picks the org.bluez.Adapter1 object matching adapter from
// the managed-objects tree. adapter is either an HCI name like "hci0"
// (matched against the "/org/bluez/<name>" path suffix) or a MAC address
// (matched, case-insensitively, against the adapter's Address property).
// It returns the object path and the adapter's MAC.
func selectAdapterPath(managed map[dbus.ObjectPath]map[string]map[string]dbus.Variant, adapter string) (dbus.ObjectPath, string, error) {
	isMAC := strings.Count(adapter, ":") == 5
	for path, ifaces := range managed {
		iface, ok := ifaces["org.bluez.Adapter1"]
		if !ok {
			continue
		}
		mac, _ := iface["Address"].Value().(string)
		if isMAC {
			if strings.EqualFold(mac, adapter) {
				return path, mac, nil
			}
		} else if strings.HasSuffix(string(path), "/"+adapter) {
			return path, mac, nil
		}
	}
	return "", "", fmt.Errorf("no org.bluez.Adapter1 matching %q", adapter)
}

// sppProfileState implements org.bluez.Profile1. NewConnection receives the
// RFCOMM socket as a dbus.UnixFD and hands it to startPhoneLink; at most one
// phone link is active — a new connection replaces the previous one.
type sppProfileState struct {
	mu     sync.Mutex
	active *os.File // the connected RFCOMM socket, one phone at a time
	store  *Store
	keys   map[string]ed25519.PublicKey
}

// Release is called by BlueZ when the profile is released (service stop or
// profile removal): drop the active link.
func (p *sppProfileState) Release() *dbus.Error {
	log.Printf("bluetooth: profile released, closing active link")
	p.closeActive()
	return nil
}

// NewConnection is called by BlueZ when a phone connects the SPP profile.
// The fd is the connected RFCOMM socket; ownership passes to us. If a
// previous link is still active it is closed first (one phone at a time).
func (p *sppProfileState) NewConnection(device dbus.ObjectPath, fd dbus.UnixFD, fdProps map[string]dbus.Variant) *dbus.Error {
	f := wrapUnixFD(fd)
	if f == nil {
		log.Printf("bluetooth: rejecting connection from %s: invalid RFCOMM fd", device)
		return dbus.NewError("org.bluez.Error.Rejected", []interface{}{"invalid file descriptor"})
	}

	p.mu.Lock()
	prev := p.active
	p.active = f
	p.mu.Unlock()
	if prev != nil {
		log.Printf("bluetooth: closing previous phone link for new connection from %s", device)
		_ = prev.Close()
	}

	log.Printf("bluetooth: SPP connection from %s", device)
	startPhoneLink(f, p.store, p.keys)
	return nil
}

// RequestDisconnection is called by BlueZ when a disconnect is requested
// (e.g. the phone disconnects): drop the active link.
func (p *sppProfileState) RequestDisconnection(device dbus.ObjectPath) *dbus.Error {
	log.Printf("bluetooth: disconnection requested for %s", device)
	p.closeActive()
	return nil
}

// closeActive closes the active RFCOMM socket, if any. phoneLink.run closes
// the same file when its loop finishes; the extra close here is harmless and
// clears the reference so a new connection starts clean.
func (p *sppProfileState) closeActive() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active != nil {
		_ = p.active.Close()
		p.active = nil
	}
}

// sppAgent implements org.bluez.Agent1 with the NoInputNoOutput capability.
// Returning nil from RequestConfirmation/RequestAuthorization/AuthorizeService
// means accept, so pairing always succeeds while this agent is the default.
type sppAgent struct{}

func (a *sppAgent) Release() *dbus.Error { return nil }

func (a *sppAgent) RequestPinCode(device dbus.ObjectPath) (string, *dbus.Error) {
	return "", nil
}

func (a *sppAgent) DisplayPinCode(device dbus.ObjectPath, pincode string) *dbus.Error {
	return nil
}

func (a *sppAgent) RequestPasskey(device dbus.ObjectPath) (uint32, *dbus.Error) {
	return 0, nil
}

func (a *sppAgent) DisplayPasskey(device dbus.ObjectPath, passkey uint32, entered uint16) *dbus.Error {
	return nil
}

func (a *sppAgent) RequestConfirmation(device dbus.ObjectPath, passkey uint32) *dbus.Error {
	return nil
}

func (a *sppAgent) RequestAuthorization(device dbus.ObjectPath) *dbus.Error {
	return nil
}

func (a *sppAgent) AuthorizeService(device dbus.ObjectPath, uuid string) *dbus.Error {
	return nil
}

func (a *sppAgent) Cancel() *dbus.Error { return nil }

// wrapUnixFD turns a dbus.UnixFD received on the wire (the actual process fd
// number, extracted from the SCM_RIGHTS payload by godbus) into an *os.File,
// which satisfies io.ReadWriteCloser for startPhoneLink. Returns nil when the
// fd is not a valid open descriptor.
func wrapUnixFD(fd dbus.UnixFD) *os.File {
	return os.NewFile(uintptr(fd), "rfcomm")
}
