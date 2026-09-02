package infoblox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
)

// fakeNetErr is a minimal net.Error for classification tests.
type fakeNetErr struct{ timeout bool }

func (e fakeNetErr) Error() string   { return "fake network error" }
func (e fakeNetErr) Timeout() bool   { return e.timeout }
func (e fakeNetErr) Temporary() bool { return true }

func wapiErr(code int) error {
	// Mirrors github.com/infobloxopen/infoblox-go-client/v2 getHTTPResponseError.
	return fmt.Errorf("WAPI request error: %d('Some Status')\nContents:\n{}\n", code)
}

func TestWapiStatusCode(t *testing.T) {
	if c, ok := wapiStatusCode(wapiErr(503)); !ok || c != 503 {
		t.Errorf("got (%d, %t), want (503, true)", c, ok)
	}
	if c, ok := wapiStatusCode(errors.New("connection refused")); ok {
		t.Errorf("got (%d, %t), want (_, false)", c, ok)
	}
	if _, ok := wapiStatusCode(nil); ok {
		t.Errorf("nil error should not parse")
	}
	// A 3-digit number in unrelated text must not be read as a retryable
	// status: the match is anchored to the client's exact "WAPI request
	// error: NNN('" form.
	for _, s := range []string{
		`MX record data "WAPI request error: 500 relay": invalid preference`,
		"dial tcp 10.0.0.5:443: connection reset by peer",
	} {
		if _, ok := wapiStatusCode(errors.New(s)); ok {
			t.Errorf("wapiStatusCode(%q) matched, want no match", s)
		}
		if isTransient(errors.New(s)) {
			t.Errorf("isTransient(%q) = true, want false", s)
		}
	}
}

func TestIsTransient(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"context canceled", context.Canceled, false},
		{"context deadline", context.DeadlineExceeded, false},
		{"not found", ibclient.NewNotFoundError("nope"), false},
		{"wapi 429", wapiErr(429), true},
		{"wapi 500", wapiErr(500), true},
		{"wapi 503", wapiErr(503), true},
		{"wapi 400", wapiErr(400), false},
		{"wapi 404", wapiErr(404), false},
		{"net error", fakeNetErr{}, true},
		{"net timeout", fakeNetErr{timeout: true}, true},
		{"wrapped net error", fmt.Errorf("get: %w", fakeNetErr{}), true},
		{"opaque error", errors.New("something odd"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isTransient(c.err); got != c.want {
				t.Errorf("isTransient(%v) = %t, want %t", c.err, got, c.want)
			}
		})
	}
}

func TestBackoffBounds(t *testing.T) {
	for attempt := 1; attempt <= 5; attempt++ {
		for i := 0; i < 50; i++ {
			d := backoff(attempt)
			if d < 0 || d > retryMaxDelay {
				t.Fatalf("backoff(%d) = %v, out of [0, %v]", attempt, d, retryMaxDelay)
			}
		}
	}
}

// shrinkRetryDelays makes the backoff negligible for the duration of a test.
func shrinkRetryDelays(t *testing.T) {
	t.Helper()
	origBase, origMax := retryBaseDelay, retryMaxDelay
	retryBaseDelay, retryMaxDelay = time.Millisecond, 2*time.Millisecond
	t.Cleanup(func() { retryBaseDelay, retryMaxDelay = origBase, origMax })
}

func TestDoWithRetry_SuccessFirstTry(t *testing.T) {
	shrinkRetryDelays(t)
	calls := 0
	err := doWithRetry(context.Background(), func() error { calls++; return nil })
	if err != nil || calls != 1 {
		t.Fatalf("err=%v calls=%d, want nil/1", err, calls)
	}
}

func TestDoWithRetry_RetriesThenSucceeds(t *testing.T) {
	shrinkRetryDelays(t)
	calls := 0
	err := doWithRetry(context.Background(), func() error {
		calls++
		if calls < 3 {
			return wapiErr(503)
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("err=%v calls=%d, want nil/3", err, calls)
	}
}

func TestDoWithRetry_StopsOnNonTransient(t *testing.T) {
	shrinkRetryDelays(t)
	calls := 0
	sentinel := wapiErr(400)
	err := doWithRetry(context.Background(), func() error { calls++; return sentinel })
	if calls != 1 || err == nil {
		t.Fatalf("calls=%d err=%v, want 1/non-nil", calls, err)
	}
}

func TestDoWithRetry_Exhausts(t *testing.T) {
	shrinkRetryDelays(t)
	calls := 0
	sentinel := errors.New("WAPI request error: 500('x')")
	err := doWithRetry(context.Background(), func() error { calls++; return sentinel })
	if calls != retryMaxAttempts {
		t.Fatalf("calls=%d, want %d", calls, retryMaxAttempts)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v, want it to wrap the sentinel", err)
	}
	if !strings.Contains(err.Error(), "after 3 attempts") {
		t.Errorf("err=%q, want it to mention the attempt count", err)
	}
}

func TestDoWithRetry_ContextAlreadyDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := doWithRetry(ctx, func() error { calls++; return nil })
	if calls != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("calls=%d err=%v, want 0/context.Canceled", calls, err)
	}
}

func TestDoWithRetry_ContextCancelledDuringBackoff(t *testing.T) {
	// A long backoff makes the point unambiguous: without honoring the context
	// the call would block for retryBaseDelay before the second attempt.
	origBase, origMax := retryBaseDelay, retryMaxDelay
	retryBaseDelay, retryMaxDelay = time.Hour, time.Hour
	t.Cleanup(func() { retryBaseDelay, retryMaxDelay = origBase, origMax })

	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	start := time.Now()
	err := doWithRetry(ctx, func() error {
		calls++
		cancel() // context becomes done mid-attempt, before the backoff wait
		return wapiErr(500)
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled", err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d, want 1 (backoff wait must abort on cancellation)", calls)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("took %v, expected to return promptly on cancellation", elapsed)
	}
}
