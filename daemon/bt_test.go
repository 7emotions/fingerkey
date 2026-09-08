package main

import (
	"io"
	"os"
	"syscall"
	"testing"

	"github.com/godbus/dbus/v5"
)

func managedWithAdapters(adapters map[dbus.ObjectPath]string) map[dbus.ObjectPath]map[string]map[string]dbus.Variant {
	managed := make(map[dbus.ObjectPath]map[string]map[string]dbus.Variant)
	for path, mac := range adapters {
		managed[path] = map[string]map[string]dbus.Variant{
			"org.bluez.Adapter1": {"Address": dbus.MakeVariant(mac)},
		}
	}
	// A non-adapter object with the same MAC must never match.
	managed["/org/bluez/hci0/dev_11_22_33_44_55_66"] = map[string]map[string]dbus.Variant{
		"org.bluez.Device1": {"Address": dbus.MakeVariant("D0:57:7E:C8:12:B5")},
	}
	return managed
}

func TestSelectAdapterPathByName(t *testing.T) {
	managed := managedWithAdapters(map[dbus.ObjectPath]string{
		"/org/bluez/hci0": "D0:57:7E:C8:12:B5",
		"/org/bluez/hci1": "AA:BB:CC:DD:EE:FF",
	})

	path, mac, err := selectAdapterPath(managed, "hci1")
	if err != nil {
		t.Fatalf("selectAdapterPath(hci1): %v", err)
	}
	if path != "/org/bluez/hci1" || mac != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("selectAdapterPath(hci1) = %q, %q; want /org/bluez/hci1, AA:BB:CC:DD:EE:FF", path, mac)
	}
}

func TestSelectAdapterPathByMAC(t *testing.T) {
	managed := managedWithAdapters(map[dbus.ObjectPath]string{
		"/org/bluez/hci0": "D0:57:7E:C8:12:B5",
	})

	path, mac, err := selectAdapterPath(managed, "d0:57:7e:c8:12:b5")
	if err != nil {
		t.Fatalf("selectAdapterPath(mac): %v", err)
	}
	if path != "/org/bluez/hci0" || mac != "D0:57:7E:C8:12:B5" {
		t.Fatalf("selectAdapterPath(mac) = %q, %q; want /org/bluez/hci0, D0:57:7E:C8:12:B5", path, mac)
	}
}

func TestSelectAdapterPathNotFound(t *testing.T) {
	managed := managedWithAdapters(map[dbus.ObjectPath]string{
		"/org/bluez/hci0": "D0:57:7E:C8:12:B5",
	})

	if _, _, err := selectAdapterPath(managed, "hci2"); err == nil {
		t.Fatal("selectAdapterPath(hci2): expected error for unknown adapter name")
	}
	if _, _, err := selectAdapterPath(managed, "00:00:00:00:00:00"); err == nil {
		t.Fatal("selectAdapterPath(mac): expected error for unknown MAC")
	}
}

func TestWrapUnixFDRoundTrip(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// The wrapped file owns the same fd as w: close only f, never w.
	f := wrapUnixFD(dbus.UnixFD(w.Fd()))
	if f == nil {
		t.Fatal("wrapUnixFD returned nil for a valid fd")
	}
	defer f.Close()

	payload := []byte("framed-approval")
	go func() {
		if _, err := f.Write(payload); err != nil {
			t.Errorf("wrapped file write: %v", err)
		}
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
}

func TestWrapUnixFDInvalid(t *testing.T) {
	// os.NewFile returns nil for a negative fd (Linux Go 1.18: fdi < 0).
	if f := wrapUnixFD(dbus.UnixFD(-1)); f != nil {
		f.Close()
		t.Fatal("wrapUnixFD(-1) returned non-nil")
	}
}

// newSocketPairFiles returns a connected SOCK_STREAM pair wrapped as
// *os.File: link is the daemon side (handed to NewConnection), phone is the
// remote side the test writes to. Each fd is wrapped exactly once, so no
// double-close hazard exists.
func newSocketPairFiles(t *testing.T) (link, phone *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	link = os.NewFile(uintptr(fds[0]), "link")
	phone = os.NewFile(uintptr(fds[1]), "phone")
	t.Cleanup(func() {
		link.Close()
		phone.Close()
	})
	return link, phone
}

func TestSppProfileReplacesActiveLink(t *testing.T) {
	p := &sppProfileState{store: NewStore(), keys: nil}

	firstLink, firstPhone := newSocketPairFiles(t)
	p.NewConnection("/org/bluez/hci0/dev_11_22_33_44_55_66", dbus.UnixFD(firstLink.Fd()), nil)

	secondLink, secondPhone := newSocketPairFiles(t)
	p.NewConnection("/org/bluez/hci0/dev_77_88_99_AA_BB_CC", dbus.UnixFD(secondLink.Fd()), nil)

	// The first link must have been closed by the replacement: writing from
	// the phone side fails with EPIPE once the daemon side is closed.
	if _, err := firstPhone.Write([]byte("x")); err == nil {
		t.Error("first link still writable after replacement; expected closed")
	}

	// The second link stays usable until a disconnect is requested.
	if _, err := secondPhone.Write([]byte("y")); err != nil {
		t.Errorf("second link write: %v", err)
	}
	p.RequestDisconnection("/org/bluez/hci0/dev_77_88_99_AA_BB_CC")
	if _, err := secondPhone.Write([]byte("z")); err == nil {
		t.Error("second link still writable after RequestDisconnection; expected closed")
	}

	p.Release()
}
