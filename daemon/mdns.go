package main

import (
	"net"
	"os"

	"github.com/hashicorp/mdns"
)

// mdnsServiceType is the LAN service type phones browse for via NSD.
const mdnsServiceType = "_phonefprint._tcp"

// mdnsServer keeps the mDNS responder alive: the server runs its own
// goroutines, but the reference guarantees it is never collected while the
// daemon runs.
var mdnsServer *mdns.Server

// newMDNSService builds the _phonefprint._tcp announcement: the instance is
// the machine hostname, the TXT records carry the TLS fingerprint (fp=) and
// the protocol version (v=1), and the port is the TLS listener's port. The
// host record's IP is passed explicitly (the numeric default-route address)
// so publication never depends on DNS resolution of the hostname.
func newMDNSService(port int, fp string) (*mdns.MDNSService, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(localIPv4())
	return mdns.NewMDNSService(
		hostname, mdnsServiceType, "", hostname+".", port, []net.IP{ip}, []string{"fp=" + fp, "v=1"},
	)
}

// publishMDNS starts the in-process mDNS responder advertising this daemon.
// Any error is returned to the caller, which logs it non-fatally: the daemon
// keeps serving TLS and the unix-socket surface without mDNS.
func publishMDNS(port int, fp string) error {
	service, err := newMDNSService(port, fp)
	if err != nil {
		return err
	}
	server, err := mdns.NewServer(&mdns.Config{Zone: service})
	if err != nil {
		return err
	}
	mdnsServer = server
	return nil
}
