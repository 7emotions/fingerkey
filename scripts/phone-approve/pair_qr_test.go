package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// startPairServer serves a fake daemon POST /v1/pair on a unix socket in a
// temp dir, points daemonSocket at it and restores it on cleanup. Every
// request body is delivered on the returned channel; requests are answered
// with the given status and body.
func startPairServer(t *testing.T, status int, reply string) chan []byte {
	t.Helper()
	reqCh := make(chan []byte, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/pair" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		reqCh <- body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	})
	srv := httptest.NewUnstartedServer(handler)
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "daemon.sock"))
	if err != nil {
		t.Fatal(err)
	}
	srv.Listener = ln
	srv.Start()
	prev := daemonSocket
	daemonSocket = ln.Addr().String()
	t.Cleanup(func() {
		daemonSocket = prev
		srv.Close()
	})
	return reqCh
}

func TestPairPayload(t *testing.T) {
	got := pairPayload(pairReply{Token: "t0ken", FP: "deadbeef", Host: "192.0.2.1", Port: 4443}, "desk")
	want := "phonefprint://192.0.2.1:4443?fp=deadbeef&t=t0ken&n=desk"
	if got != want {
		t.Fatalf("payload = %q, want %q", got, want)
	}
}

func TestPairQR_when_daemonResponds(t *testing.T) {
	reqCh := startPairServer(t, http.StatusOK, `{"token":"abc123","fp":"beef","host":"10.0.0.7","port":4443}`)

	var payload string
	prev := qrEncode
	qrEncode = func(p string, w io.Writer) { payload = p }
	t.Cleanup(func() { qrEncode = prev })

	var stdout, stderr bytes.Buffer
	code := run([]string{"pair-qr", "pixel-8"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(<-reqCh, &req); err != nil {
		t.Fatal(err)
	}
	if req.Name != "pixel-8" {
		t.Errorf("request name = %q, want %q", req.Name, "pixel-8")
	}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	want := "phonefprint://10.0.0.7:4443?fp=beef&t=abc123&n=" + hostname
	if payload != want {
		t.Errorf("QR payload = %q, want %q", payload, want)
	}
	if !strings.Contains(stdout.String(), `Scan with the app, then it auto-registers as "pixel-8"`) {
		t.Errorf("stdout = %q, want the scan hint", stdout.String())
	}
}

func TestPairQR_renders_QR_blocks(t *testing.T) {
	startPairServer(t, http.StatusOK, `{"token":"abc123","fp":"beef","host":"10.0.0.7","port":4443}`)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"pair-qr", "pixel-8"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	// qrterminal paints white modules with this ANSI escape.
	if !strings.Contains(stdout.String(), "\x1b[47m") {
		t.Errorf("stdout does not contain QR blocks:\n%s", stdout.String())
	}
}

func TestPairQR_when_daemonDown(t *testing.T) {
	prev := daemonSocket
	daemonSocket = filepath.Join(t.TempDir(), "daemon.sock")
	t.Cleanup(func() { daemonSocket = prev })

	var stdout, stderr bytes.Buffer
	code := run([]string{"pair-qr", "pixel-8"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (stdout = %q)", code, stdout.String())
	}
	msg := stderr.String()
	if !strings.Contains(msg, "cannot reach daemon") || !strings.Contains(msg, daemonSocket) {
		t.Errorf("stderr = %q, want a clear unreachable message naming the socket", msg)
	}
}

func TestPairQR_when_daemonRejects(t *testing.T) {
	startPairServer(t, http.StatusServiceUnavailable, `{"error":"pairing unavailable"}`)
	var stdout, stderr bytes.Buffer
	code := run([]string{"pair-qr", "pixel-8"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "pairing unavailable") {
		t.Errorf("stderr = %q, want the daemon error surfaced", stderr.String())
	}
}

func TestPairQR_when_malformedReply(t *testing.T) {
	startPairServer(t, http.StatusOK, `{"token":"abc123"}`) // fp/host/port missing
	var stdout, stderr bytes.Buffer
	code := run([]string{"pair-qr", "pixel-8"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "all required") {
		t.Errorf("stderr = %q, want the missing-field error", stderr.String())
	}
}

func TestPairQR_when_invalidName(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"pair-qr", "../evil"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "invalid key name") {
		t.Errorf("stderr = %q, want the name validation error", stderr.String())
	}
}
