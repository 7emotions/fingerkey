package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
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

// sppConn holds the live D-Bus connection past startSppServer's return: its
// inWorker goroutine keeps serving incoming method calls as long as the conn
// is referenced and open.
var sppConn *dbus.Conn

// startSppServer registers an org.bluez.Profile1 (RFCOMM SPP server) on the
// system bus and hands every accepted RFCOMM socket to startPhoneLink, so the
// connected phone flows through the same framed approval protocol as the
// sim-socket. Any failure is returned to the caller (which logs it as
// non-fatal): the daemon keeps serving the unix-socket surface without
// Bluetooth.
//
// TODO(todo 9): delete this whole file. The single-link sppProfileState was
// removed in todo 5 (multi-link); profile registration is disabled below.
func startSppServer(adapter string, store *Store, keys *keyProvider) error {
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

	// Profile registration removed with sppProfileState (todo 5): the SPP
	// profile has no single-link state to export anymore and the LAN/TLS
	// listener replaces the phone transport. Nothing here registers a
	// profile; the code stays in place until todo 9 deletes it.

	// Export and register the NoInputNoOutput pairing agent: without it
	// bluetoothd rejects pairing with "Authentication attempt without agent".
	// Every agent callback auto-accepts, so the phone can bond inside the
	// 60s bt-pair window; approval authority still comes from pubkey
	// registration, never from bonding.
	agent := &sppAgent{}
	if err := conn.Export(agent, sppAgentPath, "org.bluez.Agent1"); err != nil {
		conn.Close()
		return fmt.Errorf("export pairing agent: %w", err)
	}
	agentManager := conn.Object("org.bluez", "/org/bluez")
	if call := agentManager.Call(
		"org.bluez.AgentManager1.RegisterAgent", 0, sppAgentPath, "NoInputNoOutput"); call.Err != nil {
		conn.Export(nil, sppAgentPath, "org.bluez.Agent1")
		conn.Close()
		return fmt.Errorf("register pairing agent: %w", call.Err)
	}
	if call := agentManager.Call(
		"org.bluez.AgentManager1.RequestDefaultAgent", 0, sppAgentPath); call.Err != nil {
		conn.Export(nil, sppAgentPath, "org.bluez.Agent1")
		conn.Close()
		return fmt.Errorf("request default pairing agent: %w", call.Err)
	}

	// Keep the live D-Bus state referenced and unregister best-effort on
	// shutdown, then exit so SIGINT/SIGTERM still terminate the process.
	sppConn = conn
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		if err := conn.Object("org.bluez", "/org/bluez").Call(
			"org.bluez.AgentManager1.UnregisterAgent", 0, sppAgentPath).Err; err != nil {
			log.Printf("bluetooth: unregister pairing agent: %v", err)
		}
		conn.Close()
		os.Exit(0)
	}()

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
