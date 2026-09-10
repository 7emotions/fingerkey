package main

import (
	"os"
	"testing"
)

// TestMDNSServiceAdvertisement: the built announcement carries the
// _phonefprint._tcp service type, the machine hostname as instance, the TLS
// port, and TXT records with the fingerprint and protocol version — what a
// phone's NSD browse parses to find and pin this daemon.
func TestMDNSServiceAdvertisement(t *testing.T) {
	svc, err := newMDNSService(4443, "abcd1234abcd1234abcd1234abcd1234")
	if err != nil {
		t.Fatalf("newMDNSService: %v", err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("os.Hostname: %v", err)
	}
	if svc.Instance != hostname || svc.HostName != hostname+"." {
		t.Errorf("instance/host = %q/%q, want %q/%q", svc.Instance, svc.HostName, hostname, hostname+".")
	}
	if svc.Service != mdnsServiceType {
		t.Errorf("service = %q, want %q", svc.Service, mdnsServiceType)
	}
	if svc.Port != 4443 {
		t.Errorf("port = %d, want 4443", svc.Port)
	}
	txt := make(map[string]bool, len(svc.TXT))
	for _, kv := range svc.TXT {
		txt[kv] = true
	}
	if !txt["fp=abcd1234abcd1234abcd1234abcd1234"] {
		t.Errorf("TXT missing fp record: %v", svc.TXT)
	}
	if !txt["v=1"] {
		t.Errorf("TXT missing v=1 record: %v", svc.TXT)
	}
}
