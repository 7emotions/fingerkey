package main

import (
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

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
		b.WriteString(fields[i+1])
	}
	b.WriteString("\n")
	auditMu.Lock()
	defer auditMu.Unlock()
	io.WriteString(auditWriter, b.String())
}
