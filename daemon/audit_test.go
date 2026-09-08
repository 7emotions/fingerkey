package main

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

// swapAudit redirects the package audit writer to a fresh buffer and
// restores the previous writer when the test ends. Call it before any
// request is made so the writer is swapped before a handler runs.
func swapAudit(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := auditWriter
	auditWriter = &buf
	t.Cleanup(func() { auditWriter = old })
	return &buf
}

// assertCleanAuditLine fails if the captured audit output is not exactly one
// newline-terminated line, or if it leaks secret material: no "nonce"
// anywhere, and no "sig" outside the prescribed reason literal
// invalid-signature (which names a failure category, not signature bytes).
func assertCleanAuditLine(t *testing.T, got string) {
	t.Helper()
	line := strings.TrimSuffix(got, "\n")
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("audit output must be newline-terminated: %q", got)
	}
	if strings.Contains(line, "\n") {
		t.Errorf("audit output must be a single line: %q", got)
	}
	if strings.Contains(line, "nonce") {
		t.Errorf("audit line leaks nonce: %q", got)
	}
	sigFree := strings.ReplaceAll(line, "reason=invalid-signature", "")
	if strings.Contains(sigFree, "sig") {
		t.Errorf("audit line leaks sig: %q", got)
	}
}

func TestAuditSessionCreated(t *testing.T) {
	buf := swapAudit(t)
	ts, _, _ := newTestServer(t)
	resp := postJSON(t, ts.URL+"/v1/session", `{"user":"alice","service":"sudo","tty":"/dev/pts/0"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got := buf.String()
	if !strings.Contains(got, "event=session-created") {
		t.Fatalf("missing session-created audit line: %q", got)
	}
	for _, want := range []string{"id=", "user=alice", "service=sudo", "tty=/dev/pts/0"} {
		if !strings.Contains(got, want) {
			t.Errorf("session-created line missing %q: %q", want, got)
		}
	}
	assertCleanAuditLine(t, got)
}

func TestAuditDecisionApprove(t *testing.T) {
	buf := swapAudit(t)
	ts, st, priv := newTestServer(t)
	s, err := st.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sig := signDecision(priv, "approve", s)
	resp := postJSON(t, ts.URL+"/v1/session/"+s.ID+"/decision",
		`{"decision":"approve","sig":"`+sig+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got := buf.String()
	// "event=decision " (trailing space) distinguishes it from
	// "event=decision-failed".
	if !strings.Contains(got, "event=decision ") {
		t.Fatalf("missing decision audit line: %q", got)
	}
	if !strings.Contains(got, "decision=approve") || !strings.Contains(got, "key=alice") {
		t.Fatalf("decision line missing decision/key fields: %q", got)
	}
	if strings.Contains(got, sig) {
		t.Errorf("audit line leaks the signature value: %q", got)
	}
	assertCleanAuditLine(t, got)
}

func TestAuditDecisionFailed(t *testing.T) {
	buf := swapAudit(t)
	ts, st, _ := newTestServer(t)
	s, err := st.Create("alice", "sudo", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	resp := postJSON(t, ts.URL+"/v1/session/"+s.ID+"/decision",
		`{"decision":"approve","sig":"!!!not-base64!!!"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	got := buf.String()
	if !strings.Contains(got, "event=decision-failed") {
		t.Fatalf("missing decision-failed audit line: %q", got)
	}
	if !strings.Contains(got, "reason=invalid-signature") {
		t.Errorf("decision-failed line missing reason=invalid-signature: %q", got)
	}
	if !strings.Contains(got, "id="+s.ID) {
		t.Errorf("decision-failed line missing session id: %q", got)
	}
	if strings.Contains(got, base64.StdEncoding.EncodeToString(s.Nonce)) {
		t.Errorf("audit line leaks the nonce value: %q", got)
	}
	assertCleanAuditLine(t, got)
}
