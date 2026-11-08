package resolver

import (
	"crypto/rand"
	"encoding/hex"
	"sync/atomic"
	"time"
)

// FIRESTACK PATCH (P5): upstream used github.com/google/uuid only to label
// traces. Replaced with 16 random bytes to drop a dependency (smaller supply
// chain, NIST SSDF PW.4). Trace IDs are log labels, never security tokens.

type Trace struct {
	Id    string
	Start time.Time

	Iterations atomic.Uint32
}

func NewTrace() *Trace {
	return newTraceWithStart(time.Now())
}

func newTraceWithStart(start time.Time) *Trace {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return &Trace{
		Id:    hex.EncodeToString(b[:]),
		Start: start,
	}
}

func (t *Trace) ID() string {
	return t.Id
}

func (t *Trace) ShortID() string {
	// Last 7 characters; unique enough to correlate log lines.
	if len(t.Id) < 7 {
		return t.Id
	}
	return t.Id[len(t.Id)-7:]
}

func (t *Trace) Iteration() uint32 {
	return t.Iterations.Load()
}
