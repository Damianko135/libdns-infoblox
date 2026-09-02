package infoblox

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

const testZone = "example.com."

func txtFields(name, text string) map[string]any {
	return map[string]any{
		"name": name + ".example.com", "text": text,
		"ttl": 0, "use_ttl": false, "view": "default",
	}
}

// txtValues returns the sorted TXT rdata currently held for name.
func txtValues(t *testing.T, p *Provider, name string) []string {
	t.Helper()
	recs, err := p.GetRecords(context.Background(), testZone)
	if err != nil {
		t.Fatalf("GetRecords: %v", err)
	}
	var out []string
	for _, r := range recs {
		rr := r.RR()
		if rr.Type == "TXT" && rr.Name == name {
			out = append(out, rr.Data)
		}
	}
	sort.Strings(out)
	return out
}

func TestWAPI_GetRecords_EmptyTypesAreNotErrors(t *testing.T) {
	f := newFakeWAPI()
	p := f.start(t)
	f.seed("record:txt", txtFields("_acme-challenge", "only-a-txt"))

	recs, err := p.GetRecords(context.Background(), testZone)
	if err != nil {
		t.Fatalf("GetRecords returned an error for a zone with only TXT records: %v", err)
	}
	if len(recs) != 1 || recs[0].RR().Type != "TXT" {
		t.Fatalf("got %d records %+v, want exactly one TXT", len(recs), recs)
	}
}

func TestWAPI_Append_PreservesExistingTXT(t *testing.T) {
	f := newFakeWAPI()
	p := f.start(t)
	f.seed("record:txt", txtFields("_acme-challenge", "existing"))

	added, err := p.AppendRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "challenge"},
	})
	if err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}
	if len(added) != 1 || added[0].RR().Data != "challenge" {
		t.Fatalf("added = %+v, want [challenge]", added)
	}
	if got := txtValues(t, p, "_acme-challenge"); strings.Join(got, ",") != "challenge,existing" {
		t.Fatalf("TXT rdata after append = %v, want [challenge existing]", got)
	}
}

func TestWAPI_Append_MultipleChallengesCoexist(t *testing.T) {
	f := newFakeWAPI()
	p := f.start(t)
	f.seed("record:txt", txtFields("_acme-challenge", "challenge-a"))

	if _, err := p.AppendRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "challenge-b"},
	}); err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}
	if got := txtValues(t, p, "_acme-challenge"); strings.Join(got, ",") != "challenge-a,challenge-b" {
		t.Fatalf("got %v, want both challenge-a and challenge-b", got)
	}
}

func TestWAPI_Append_Idempotent(t *testing.T) {
	f := newFakeWAPI()
	p := f.start(t)
	rec := []libdns.Record{libdns.TXT{Name: "_acme-challenge", Text: "challenge"}}

	for i := 0; i < 2; i++ {
		added, err := p.AppendRecords(context.Background(), testZone, rec)
		if err != nil {
			t.Fatalf("AppendRecords #%d: %v", i+1, err)
		}
		if len(added) != 1 || added[0].RR().Data != "challenge" {
			t.Fatalf("AppendRecords #%d added = %+v, want [challenge]", i+1, added)
		}
	}
	if n := f.count("record:txt"); n != 1 {
		t.Fatalf("store holds %d TXT records after two identical appends, want 1", n)
	}
}

func TestWAPI_Delete_RemovesOnlyTarget(t *testing.T) {
	f := newFakeWAPI()
	p := f.start(t)
	f.seed("record:txt", txtFields("_acme-challenge", "challenge-a"))
	f.seed("record:txt", txtFields("_acme-challenge", "challenge-b"))

	deleted, err := p.DeleteRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "challenge-a"},
	})
	if err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}
	if len(deleted) != 1 || deleted[0].RR().Data != "challenge-a" {
		t.Fatalf("deleted = %+v, want [challenge-a]", deleted)
	}
	if got := txtValues(t, p, "_acme-challenge"); strings.Join(got, ",") != "challenge-b" {
		t.Fatalf("remaining TXT rdata = %v, want [challenge-b]", got)
	}
}

func TestWAPI_Delete_AbsentIsNoError(t *testing.T) {
	f := newFakeWAPI()
	p := f.start(t)
	f.seed("record:txt", txtFields("_acme-challenge", "challenge-b"))

	deleted, err := p.DeleteRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "never-existed"},
	})
	if err != nil {
		t.Fatalf("DeleteRecords of an absent record must not error, got: %v", err)
	}
	if len(deleted) != 0 {
		t.Fatalf("deleted = %+v, want empty", deleted)
	}
	if got := txtValues(t, p, "_acme-challenge"); strings.Join(got, ",") != "challenge-b" {
		t.Fatalf("unrelated record was touched: %v", got)
	}
}

func TestWAPI_Delete_ValueWildcardRemovesWholeName(t *testing.T) {
	f := newFakeWAPI()
	p := f.start(t)
	f.seed("record:txt", txtFields("_acme-challenge", "challenge-a"))
	f.seed("record:txt", txtFields("_acme-challenge", "challenge-b"))

	deleted, err := p.DeleteRecords(context.Background(), testZone, []libdns.Record{
		libdns.RR{Type: "TXT", Name: "_acme-challenge"}, // empty Data == wildcard
	})
	if err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}
	if len(deleted) != 2 {
		t.Fatalf("deleted %d records, want 2", len(deleted))
	}
	if n := f.count("record:txt"); n != 0 {
		t.Fatalf("store still holds %d TXT records, want 0", n)
	}
}

func TestWAPI_SetRecords_ReplacesRRset(t *testing.T) {
	f := newFakeWAPI()
	p := f.start(t)
	f.seed("record:txt", txtFields("_acme-challenge", "old-a"))
	f.seed("record:txt", txtFields("_acme-challenge", "old-b"))
	f.seed("record:txt", txtFields("other", "untouched"))

	set, err := p.SetRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "new-only"},
	})
	if err != nil {
		t.Fatalf("SetRecords: %v", err)
	}
	if len(set) != 1 || set[0].RR().Data != "new-only" {
		t.Fatalf("set = %+v, want [new-only]", set)
	}
	if got := txtValues(t, p, "_acme-challenge"); strings.Join(got, ",") != "new-only" {
		t.Fatalf("RRset after SetRecords = %v, want [new-only]", got)
	}
	if got := txtValues(t, p, "other"); strings.Join(got, ",") != "untouched" {
		t.Fatalf("unrelated name changed: %v", got)
	}
}

func TestWAPI_SetRecords_TTLOnlyChangeUpdatesInPlace(t *testing.T) {
	f := newFakeWAPI()
	p := f.start(t)
	ref := f.seed("record:txt", txtFields("_acme-challenge", "same-value"))

	set, err := p.SetRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "same-value", TTL: 300 * time.Second},
	})
	if err != nil {
		t.Fatalf("SetRecords: %v", err)
	}
	if len(set) != 1 || set[0].RR().Data != "same-value" || set[0].RR().TTL != 300*time.Second {
		t.Fatalf("set = %+v, want same-value @ 300s", set)
	}
	if n := f.count("record:txt"); n != 1 {
		t.Fatalf("store holds %d records, want 1 (updated in place, not recreated)", n)
	}
	f.mu.Lock()
	obj := f.objects[ref]
	f.mu.Unlock()
	if obj == nil {
		t.Fatal("original object ref disappeared: record was recreated, not updated")
	}
}

func TestWAPI_Retry_TransientThenSuccess(t *testing.T) {
	f := newFakeWAPI()
	shrinkRetryDelays(t)
	p := f.start(t)
	// Fail both HTTP hits of the first doWithRetry attempt (normal + the
	// client's own forceProxy fallback), then let it through.
	f.failFirst["POST record:txt"] = 2

	added, err := p.AppendRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "challenge"},
	})
	if err != nil {
		t.Fatalf("AppendRecords should have recovered after a transient failure, got: %v", err)
	}
	if len(added) != 1 || f.count("record:txt") != 1 {
		t.Fatalf("added=%+v store=%d, want one record created exactly once", added, f.count("record:txt"))
	}
}

func TestWAPI_Retry_PermanentFailureIsNotRetried(t *testing.T) {
	f := newFakeWAPI()
	shrinkRetryDelays(t)
	p := f.start(t)
	f.failStatus = http.StatusBadRequest
	f.failFirst["POST record:txt"] = 99 // effectively always

	_, err := p.AppendRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "challenge"},
	})
	if err == nil {
		t.Fatal("expected AppendRecords to fail on a permanent 400")
	}
	// The provider looks up (GET, 2 hits: normal + forceProxy) then creates
	// (POST, 2 hits). It must NOT spin doWithRetry on the 400: no more than a
	// handful of POSTs.
	posts := 0
	for _, h := range f.hits {
		if strings.HasPrefix(h, "POST record:txt") {
			posts++
		}
	}
	if posts > 2 {
		t.Fatalf("permanent 400 was retried: %d POST hits, want <= 2", posts)
	}
}

func TestWAPI_SetRecords_PartialFailureIsReported(t *testing.T) {
	f := newFakeWAPI()
	shrinkRetryDelays(t)
	p := f.start(t)
	f.failStatus = http.StatusBadRequest
	f.failFirst["POST record:txt"] = 2 // kills exactly the first create (2 hits)

	set, err := p.SetRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "value-1"},
		libdns.TXT{Name: "_acme-challenge", Text: "value-2"},
	})
	if err == nil {
		t.Fatal("expected a partial-failure error")
	}
	// Exactly one of the two values should have made it in, and the returned
	// slice must reflect only what actually succeeded.
	if n := f.count("record:txt"); n != 1 {
		t.Fatalf("store holds %d records, want 1 (one create failed)", n)
	}
	if len(set) != 1 {
		t.Fatalf("returned %d set records, want 1", len(set))
	}
}

func TestWAPI_ContextCancelled_DoesNoWork(t *testing.T) {
	f := newFakeWAPI()
	p := f.start(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := p.GetRecords(ctx, testZone); err == nil {
		t.Fatal("GetRecords with a cancelled context should error")
	}
	if _, err := p.AppendRecords(ctx, testZone, []libdns.Record{libdns.TXT{Name: "x", Text: "y"}}); err == nil {
		t.Fatal("AppendRecords with a cancelled context should error")
	}
	if n := f.hitCount(); n != 0 {
		t.Fatalf("cancelled context still made %d WAPI calls", n)
	}
}

func TestWAPI_ConcurrentAppendsToSameName(t *testing.T) {
	f := newFakeWAPI()
	p := f.start(t)

	const n = 6
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = p.AppendRecords(context.Background(), testZone, []libdns.Record{
				libdns.TXT{Name: "_acme-challenge", Text: fmt.Sprintf("token-%d", i)},
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent AppendRecords #%d: %v", i, err)
		}
	}
	if got := len(txtValues(t, p, "_acme-challenge")); got != n {
		t.Fatalf("after %d concurrent appends the name holds %d TXT records", n, got)
	}
}

func TestWAPI_ConcurrentIdenticalAppends_ResolveToOneRecord(t *testing.T) {
	f := newFakeWAPI()
	shrinkRetryDelays(t)
	p := f.start(t)

	const n = 5
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = p.AppendRecords(context.Background(), testZone, []libdns.Record{
				libdns.TXT{Name: "_acme-challenge", Text: "same-token"},
			})
		}(i)
	}
	wg.Wait()

	// Every caller must see success (losers of the create race fall back to
	// the post-create re-check and find the record), and NIOS's duplicate
	// rejection must leave exactly one record.
	for i, err := range errs {
		if err != nil {
			t.Errorf("append #%d: %v", i, err)
		}
	}
	if got := f.count("record:txt"); got != 1 {
		t.Fatalf("store holds %d records after %d identical concurrent appends, want 1", got, n)
	}
}

func TestWAPI_ListZones(t *testing.T) {
	f := newFakeWAPI()
	p := f.start(t)
	f.seed("zone_auth", map[string]any{"fqdn": "example.com", "view": "default"})
	f.seed("zone_auth", map[string]any{"fqdn": "example.net", "view": "default"})
	f.seed("zone_auth", map[string]any{"fqdn": "internal.example", "view": "internal"})

	zones, err := p.ListZones(context.Background())
	if err != nil {
		t.Fatalf("ListZones: %v", err)
	}
	var names []string
	for _, z := range zones {
		names = append(names, z.Name)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "example.com.,example.net." {
		t.Fatalf("zones = %v, want the two default-view zones with trailing dots", names)
	}
}

func TestWAPI_TXT_RoundTripsTTLAndValue(t *testing.T) {
	f := newFakeWAPI()
	p := f.start(t)

	// A realistic ACME DNS-01 token: base64url, 43 chars, no spaces or quotes.
	const token = "3Zx1cJ8-7pQ2rL5wY0nD4kF6hB9sT1uV_aXeM8oGqIw"
	added, err := p.AppendRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: token, TTL: 120 * time.Second},
	})
	if err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}
	rr := added[0].RR()
	if rr.Data != token {
		t.Errorf("value round-trip: got %q", rr.Data)
	}
	if rr.TTL != 120*time.Second {
		t.Errorf("ttl round-trip: got %v, want 120s", rr.TTL)
	}

	// And it comes back the same way through GetRecords.
	recs, _ := p.GetRecords(context.Background(), testZone)
	if len(recs) != 1 || recs[0].RR().Data != token || recs[0].RR().TTL != 120*time.Second {
		t.Fatalf("GetRecords round-trip mismatch: %+v", recs)
	}

	// The provider passes TXT text through untouched; RFC 1035 quoting of
	// spaced/quoted values is a documented NIOS-side limitation, not something
	// this test asserts either way.
}
