package main

import (
	"io"
	"os"
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

func TestSppAgentAutoAccepts(t *testing.T) {
	a := &sppAgent{}
	device := dbus.ObjectPath("/org/bluez/hci0/dev_68_85_A4_4A_56_10")

	if pin, err := a.RequestPinCode(device); err != nil || pin != "" {
		t.Errorf("RequestPinCode() = %q, %v; want \"\", nil", pin, err)
	}
	if passkey, err := a.RequestPasskey(device); err != nil || passkey != 0 {
		t.Errorf("RequestPasskey() = %d, %v; want 0, nil", passkey, err)
	}

	// All NoInputNoOutput auto-accept callbacks must return nil so pairing
	// succeeds: nil means accept/authorize for this agent.
	callbacks := map[string]*dbus.Error{
		"DisplayPinCode":       a.DisplayPinCode(device, "1234"),
		"DisplayPasskey":       a.DisplayPasskey(device, 1234, 0),
		"RequestConfirmation":  a.RequestConfirmation(device, 1234),
		"RequestAuthorization": a.RequestAuthorization(device),
		"AuthorizeService":     a.AuthorizeService(device, sppUUID),
		"Cancel":               a.Cancel(),
	}
	for name, err := range callbacks {
		if err != nil {
			t.Errorf("%s() = %v; want nil (auto-accept)", name, err)
		}
	}
	if err := a.Release(); err != nil {
		t.Errorf("Release() = %v; want nil", err)
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
