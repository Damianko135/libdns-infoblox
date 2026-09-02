package infoblox

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"

	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
)

// libdns asks provider packages to retry transient failures (connection errors,
// HTTP 5xx, HTTP 429) a few times with backoff so that a passing hiccup on the
// grid does not fail an ACME issuance or renewal. The retry here is deliberately
// small: a handful of attempts, bounded backoff, and every wait is abandoned the
// moment the caller's context is done.
//
// These are vars rather than consts only so tests can shorten the delays.
var (
	retryMaxAttempts = 3
	retryBaseDelay   = 400 * time.Millisecond
	retryMaxDelay    = 3 * time.Second
)

// doWithRetry runs op until it succeeds, returns a non-transient error, the
// attempt budget is spent, or ctx is done. It is only ever handed operations
// that are safe to repeat: reads, updates and deletes by object reference (all
// idempotent), and creates that the caller re-checks for a duplicate afterwards.
func doWithRetry(ctx context.Context, op func() error) error {
	var lastErr error
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return contextErr(err, lastErr)
		}

		lastErr = op()
		if lastErr == nil {
			return nil
		}
		if !isTransient(lastErr) {
			return lastErr
		}
		if attempt >= retryMaxAttempts {
			// Distinguish "tried hard and still failing" from a fast failure,
			// without a logging dependency: the wrapped error is enough for a
			// caller (Caddy) to see retries were spent.
			return fmt.Errorf("after %d attempts: %w", attempt, lastErr)
		}

		timer := time.NewTimer(backoff(attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return contextErr(ctx.Err(), lastErr)
		case <-timer.C:
		}
	}
}

// contextErr wraps a context error so errors.Is(err, context.Canceled) still
// works, while keeping the last transient failure visible for diagnostics.
func contextErr(ctxErr, lastErr error) error {
	if lastErr != nil {
		return fmt.Errorf("%w; last error before cancellation: %v", ctxErr, lastErr)
	}
	return ctxErr
}

// backoff returns the wait before retry number attempt+1: an exponential step
// from retryBaseDelay, capped at retryMaxDelay, with full jitter.
func backoff(attempt int) time.Duration {
	d := retryBaseDelay << (attempt - 1)
	if d <= 0 || d > retryMaxDelay {
		d = retryMaxDelay
	}
	return time.Duration(rand.Int64N(int64(d)))
}

// isTransient reports whether err is worth retrying.
func isTransient(err error) bool {
	if err == nil {
		return false
	}
	// The caller's own cancellation/deadline is never "transient": surface it.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	// A genuine "no such object" from the grid is a definitive answer.
	var notFound *ibclient.NotFoundError
	if errors.As(err, &notFound) {
		return false
	}
	// The infoblox-go-client flattens non-404 HTTP failures into a plain error
	// whose text carries the status code (see wapiStatusCode). 429 and 5xx are
	// the recoverable ones.
	if code, ok := wapiStatusCode(err); ok {
		return code == http.StatusTooManyRequests || (code >= 500 && code <= 599)
	}
	// No HTTP response at all: dial failure, reset, TLS handshake, read timeout.
	var netErr net.Error
	return errors.As(err, &netErr)
}

// wapiErrStatusRe matches the status code in the error string produced by
// github.com/infobloxopen/infoblox-go-client/v2 connector.go getHTTPResponseError:
//
//	"WAPI request error: %d('%s')\nContents:\n%s\n"
//
// The client exposes no typed error for non-404 responses, so matching the
// message is the only way to tell 429/5xx from 4xx. The dependency is pinned and
// its bumps are reviewed (Dependabot auto-merge is disabled for it), so the
// coupling is acceptable and contained here. The trailing "('" anchors the match
// to that exact format so an unrelated error that merely contains a 3-digit
// number is not mistaken for a retryable status.
var wapiErrStatusRe = regexp.MustCompile(`WAPI request error: (\d{3})\('`)

func wapiStatusCode(err error) (int, bool) {
	if err == nil {
		return 0, false
	}
	m := wapiErrStatusRe.FindStringSubmatch(err.Error())
	if m == nil {
		return 0, false
	}
	code, convErr := strconv.Atoi(m[1])
	if convErr != nil {
		return 0, false
	}
	return code, true
}
