package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/mdp/qrterminal/v3"
)

// daemonSocket is the root-only unix socket the daemon serves its local HTTP
// surface (POST /v1/pair) on. It is a var so tests can point it at a fake
// daemon.
var daemonSocket = "/run/phone-fprint-auth/daemon.sock"

// pairReply is the daemon's POST /v1/pair response: the one-time token plus
// the LAN address and TLS fingerprint the phone must dial.
type pairReply struct {
	Token string `json:"token"`
	FP    string `json:"fp"`
	Host  string `json:"host"`
	Port  int    `json:"port"`
}

// pairQR fetches a one-time pairing token from the daemon and renders a
// scannable terminal QR code encoding the phonefprint:// connect string. The
// app scans it, dials <host>:<port> with the pinned <fp> and completes
// registration with <token>; the daemon names the new key after <name>.
func pairQR(name string, w io.Writer) error {
	if err := validateName(name); err != nil {
		return err
	}
	reply, err := requestPairToken(daemonSocket, name)
	if err != nil {
		return err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("hostname: %v", err)
	}
	fmt.Fprintf(w, "Scan with the app, then it auto-registers as %q\n", name)
	qrEncode(pairPayload(reply, hostname), w)
	return nil
}

// qrEncode renders payload as a scannable terminal QR code. It is a var so
// tests can capture the exact payload handed to the encoder.
//
// Half-block mode packs two QR rows into one terminal cell, halving the width
// while keeping the code square. The mapping below uses the standard "dark
// module = block, light module = space" convention (scannable on light
// backgrounds); qrterminal's GenerateHalfBlock uses the inverted dark-terminal
// mapping, so we build the config by hand instead.
var qrEncode = func(payload string, w io.Writer) {
	qrterminal.GenerateWithConfig(payload, qrterminal.Config{
		Level:          qrterminal.M,
		Writer:         w,
		HalfBlocks:     true,
		BlackChar:      "█",
		WhiteChar:      " ",
		BlackWhiteChar: "▀",
		WhiteBlackChar: "▄",
		QuietZone:      4,
	})
}

// pairPayload builds the phonefprint:// connect string the app decodes.
func pairPayload(reply pairReply, hostname string) string {
	return fmt.Sprintf("phonefprint://%s:%d?fp=%s&t=%s&n=%s",
		reply.Host, reply.Port,
		url.QueryEscape(reply.FP), url.QueryEscape(reply.Token), url.QueryEscape(hostname))
}

// requestPairToken POSTs {name} to the daemon's POST /v1/pair over the unix
// socket socketPath and returns the pairing reply. Every field of the reply
// is required; anything missing or a non-200 response is an error.
func requestPairToken(socketPath, name string) (pairReply, error) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 5 * time.Second,
	}
	body, err := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: name})
	if err != nil {
		return pairReply{}, err
	}
	resp, err := client.Post("http://unix/v1/pair", "application/json", bytes.NewReader(body))
	if err != nil {
		return pairReply{}, fmt.Errorf("cannot reach daemon at %s: %v (is fingerkeyd running?)", socketPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error != "" {
			return pairReply{}, fmt.Errorf("daemon refused pairing: %s", e.Error)
		}
		return pairReply{}, fmt.Errorf("daemon refused pairing: HTTP %d", resp.StatusCode)
	}
	var reply pairReply
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return pairReply{}, fmt.Errorf("malformed daemon reply: %v", err)
	}
	if reply.Token == "" || reply.FP == "" || reply.Host == "" || reply.Port == 0 {
		return pairReply{}, fmt.Errorf("malformed daemon reply: token, fp, host and port are all required")
	}
	return reply, nil
}
