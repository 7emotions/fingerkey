package main

import (
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// maxAuditFieldLen caps how many bytes one audit field value may occupy, so
// a hostile multi-megabyte decision frame cannot flood the journal with a
// single line.
const maxAuditFieldLen = 256

// sanitizeField makes a value safe for a single-line, bounded audit field:
// control characters (including \r and \n) become spaces, and the value is
// truncated to maxAuditFieldLen bytes on a UTF-8 boundary.
func sanitizeField(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7F {
			return ' '
		}
		return r
	}, v)
	if len(v) <= maxAuditFieldLen {
		return v
	}
	cut := v[:maxAuditFieldLen]
	for !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}

// auditWriter is where audit lines are written. It is package-level and
// swap-able so tests can capture output with a buffer, and it is guarded by
// auditMu so concurrent handlers never interleave lines.
var (
	auditMu     sync.Mutex
	auditWriter io.Writer = os.Stderr
)

// audit emits one grep-able, newline-terminated line:
//
//	ts=<RFC3339> event=<event> k1=v1 k2=v2 …
//
// fields is an even-length sequence of key, value pairs. Each call writes
// exactly one line under the mutex, so lines from concurrent requests cannot
// interleave. journald captures stderr as a single MESSAGE; these key=value
// lines are meant to be grep-ed, not field-parsed.
func audit(event string, fields ...string) {
	var b strings.Builder
	b.WriteString("ts=")
	b.WriteString(time.Now().UTC().Format(time.RFC3339))
	b.WriteString(" event=")
	b.WriteString(event)
	for i := 0; i+1 < len(fields); i += 2 {
		b.WriteString(" ")
		b.WriteString(fields[i])
		b.WriteString("=")
		b.WriteString(sanitizeField(fields[i+1]))
	}
	b.WriteString("\n")
	auditMu.Lock()
	defer auditMu.Unlock()
	io.WriteString(auditWriter, b.String())
}
