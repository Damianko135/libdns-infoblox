package infoblox

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
	"github.com/libdns/libdns"
)

// ptr returns a pointer to v, for building the pointer-heavy Infoblox structs
// inline in tests.
func ptr[T any](v T) *T {
	return &v
}

func TestRelativeName(t *testing.T) {
	cases := []struct{ fqdn, zone, want string }{
		{"www.example.com", "example.com", "www"},
		{"sub.host.example.com", "example.com", "sub.host"},
		{"example.com", "example.com", "@"},       // zone apex, per libdns's RR.Name convention
		{"other.org", "example.com", "other.org"}, // no matching suffix: left untouched
	}
	for _, c := range cases {
		if got := relativeName(c.fqdn, c.zone); got != c.want {
			t.Errorf("relativeName(%q, %q) = %q, want %q", c.fqdn, c.zone, got, c.want)
		}
	}
}

func TestAbsoluteName(t *testing.T) {
	cases := []struct{ name, zone, want string }{
		{"www", "example.com", "www.example.com"},
		{"sub.host", "example.com", "sub.host.example.com"},
		{"@", "example.com", "example.com"},
		{"", "example.com", "example.com"},
	}
	for _, c := range cases {
		if got := absoluteName(c.name, c.zone); got != c.want {
			t.Errorf("absoluteName(%q, %q) = %q, want %q", c.name, c.zone, got, c.want)
		}
	}
}

func TestTTLDuration(t *testing.T) {
	if got := ttlDuration(nil); got != 0 {
		t.Errorf("ttlDuration(nil) = %v, want 0", got)
	}
	if got := ttlDuration(ptr(uint32(300))); got != 300*time.Second {
		t.Errorf("ttlDuration(300) = %v, want 300s", got)
	}
}

func TestStrValUint32Val(t *testing.T) {
	if got := strVal(nil); got != "" {
		t.Errorf("strVal(nil) = %q, want empty", got)
	}
	if got := strVal(ptr("x")); got != "x" {
		t.Errorf("strVal(&\"x\") = %q, want \"x\"", got)
	}
	if got := uint32Val(nil); got != 0 {
		t.Errorf("uint32Val(nil) = %d, want 0", got)
	}
	if got := uint32Val(ptr(uint32(42))); got != 42 {
		t.Errorf("uint32Val(&42) = %d, want 42", got)
	}
}

func TestParseMXData(t *testing.T) {
	pref, exch, err := parseMXData("10 mail.example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pref != 10 || exch != "mail.example.com." {
		t.Errorf("got (%d, %q), want (10, \"mail.example.com.\")", pref, exch)
	}

	for _, bad := range []string{"", "10", "10 mail.example.com. extra", "notanumber mail.example.com."} {
		if _, _, err := parseMXData(bad); err == nil {
			t.Errorf("parseMXData(%q): expected error, got nil", bad)
		}
	}
}

func TestFormatMXData(t *testing.T) {
	if got := formatMXData(10, "mail.example.com."); got != "10 mail.example.com." {
		t.Errorf("formatMXData(10, ...) = %q", got)
	}
	// Round-trip through libdns's own MX.RR() format.
	rr := libdns.MX{Preference: 10, Target: "mail.example.com."}.RR()
	pref, exch, err := parseMXData(rr.Data)
	if err != nil {
		t.Fatalf("parseMXData(%q): %v", rr.Data, err)
	}
	if pref != 10 || exch != "mail.example.com." {
		t.Errorf("round-trip mismatch: got (%d, %q)", pref, exch)
	}
}

func TestParseSRVData(t *testing.T) {
	priority, weight, port, target, err := parseSRVData("10 20 5060 sip.example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if priority != 10 || weight != 20 || port != 5060 || target != "sip.example.com." {
		t.Errorf("got (%d, %d, %d, %q)", priority, weight, port, target)
	}

	for _, bad := range []string{"", "10 20 5060", "10 20 5060 sip.example.com. extra", "x 20 5060 sip.example.com."} {
		if _, _, _, _, err := parseSRVData(bad); err == nil {
			t.Errorf("parseSRVData(%q): expected error, got nil", bad)
		}
	}
}

func TestFormatSRVData(t *testing.T) {
	// Round-trip through libdns's own SRV.RR() format.
	rr := libdns.SRV{Priority: 10, Weight: 20, Port: 5060, Target: "sip.example.com."}.RR()
	priority, weight, port, target, err := parseSRVData(rr.Data)
	if err != nil {
		t.Fatalf("parseSRVData(%q): %v", rr.Data, err)
	}
	if priority != 10 || weight != 20 || port != 5060 || target != "sip.example.com." {
		t.Errorf("round-trip mismatch: got (%d, %d, %d, %q)", priority, weight, port, target)
	}
}

func TestToAddress(t *testing.T) {
	v4, err := toAddress("www", "192.0.2.1", 300*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := libdns.Address{Name: "www", TTL: 300 * time.Second, IP: netip.MustParseAddr("192.0.2.1")}
	if !reflect.DeepEqual(v4, want) {
		t.Errorf("toAddress(v4) = %#v, want %#v", v4, want)
	}

	v6, err := toAddress("www", "2001:db8::1", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantV6 := libdns.Address{Name: "www", IP: netip.MustParseAddr("2001:db8::1")}
	if !reflect.DeepEqual(v6, wantV6) {
		t.Errorf("toAddress(v6) = %#v, want %#v", v6, wantV6)
	}

	if _, err := toAddress("www", "not-an-ip", 0); err == nil {
		t.Error("toAddress(garbage): expected error, got nil")
	}
}

func TestCNAMEKindToRecord(t *testing.T) {
	rec := &ibclient.RecordCNAME{
		Name:      ptr("www.example.com"),
		Canonical: ptr("target.example.com"),
		Ttl:       ptr(uint32(300)),
		UseTtl:    ptr(true),
	}
	got, err := cnameKind.toRecord(rec, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := libdns.CNAME{Name: "www", TTL: 300 * time.Second, Target: "target.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestTXTKindToRecord(t *testing.T) {
	rec := &ibclient.RecordTXT{
		Name:   ptr("_acme-challenge.example.com"),
		Text:   ptr("some-token"),
		Ttl:    ptr(uint32(60)),
		UseTtl: ptr(true),
	}
	got, err := txtKind.toRecord(rec, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := libdns.TXT{Name: "_acme-challenge", TTL: 60 * time.Second, Text: "some-token"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestAKindToRecord(t *testing.T) {
	rec := &ibclient.RecordA{
		Name:     ptr("www.example.com"),
		Ipv4Addr: ptr("192.0.2.1"),
		Ttl:      ptr(uint32(120)),
		UseTtl:   ptr(true),
	}
	got, err := aKind.toRecord(rec, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := libdns.Address{Name: "www", TTL: 120 * time.Second, IP: netip.MustParseAddr("192.0.2.1")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestAAAAKindToRecord(t *testing.T) {
	rec := &ibclient.RecordAAAA{
		Name:     ptr("www.example.com"),
		Ipv6Addr: ptr("2001:db8::1"),
		Ttl:      ptr(uint32(120)),
		UseTtl:   ptr(true),
	}
	got, err := aaaaKind.toRecord(rec, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := libdns.Address{Name: "www", TTL: 120 * time.Second, IP: netip.MustParseAddr("2001:db8::1")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestMXKindToRecord(t *testing.T) {
	// MX records commonly sit at the zone apex; the relative name must come
	// back as "@" (libdns's convention), not "" or the untouched FQDN.
	rec := &ibclient.RecordMX{
		Name:          ptr("example.com"),
		MailExchanger: ptr("mail.example.com"),
		Preference:    ptr(uint32(10)),
		Ttl:           ptr(uint32(3600)),
		UseTtl:        ptr(true),
	}
	got, err := mxKind.toRecord(rec, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := libdns.MX{Name: "@", TTL: 3600 * time.Second, Preference: 10, Target: "mail.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestSRVKindToRecord(t *testing.T) {
	rec := &ibclient.RecordSRV{
		Name:     ptr("_sip._tcp.host.example.com"),
		Priority: ptr(uint32(10)),
		Weight:   ptr(uint32(20)),
		Port:     ptr(uint32(5060)),
		Target:   ptr("sip.example.com"),
		Ttl:      ptr(uint32(300)),
		UseTtl:   ptr(true),
	}
	got, err := srvKind.toRecord(rec, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := libdns.SRV{
		Service:   "sip",
		Transport: "tcp",
		Name:      "host",
		TTL:       300 * time.Second,
		Priority:  10,
		Weight:    20,
		Port:      5060,
		Target:    "sip.example.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestToRecordHonorsUseTtl(t *testing.T) {
	// use_ttl unset or false => the record inherits the zone default, which
	// libdns represents as TTL 0, regardless of any stale ttl field value.
	for _, useTtl := range []*bool{nil, ptr(false)} {
		rec := &ibclient.RecordTXT{
			Name:   ptr("_acme-challenge.example.com"),
			Text:   ptr("tok"),
			Ttl:    ptr(uint32(3600)),
			UseTtl: useTtl,
		}
		got, err := txtKind.toRecord(rec, "example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.RR().TTL != 0 {
			t.Errorf("UseTtl=%v: TTL = %v, want 0", useTtl, got.RR().TTL)
		}
	}
}

func TestEffTTL(t *testing.T) {
	cases := []struct {
		ttl    *uint32
		useTtl *bool
		want   time.Duration
	}{
		{nil, nil, 0},
		{ptr(uint32(300)), nil, 0},
		{ptr(uint32(300)), ptr(false), 0},
		{ptr(uint32(300)), ptr(true), 300 * time.Second},
		{nil, ptr(true), 0},
	}
	for _, c := range cases {
		if got := effTTL(c.ttl, c.useTtl); got != c.want {
			t.Errorf("effTTL(%v, %v) = %v, want %v", c.ttl, c.useTtl, got, c.want)
		}
	}
}

func TestTTLArgs(t *testing.T) {
	cases := []struct {
		in      time.Duration
		wantTTL uint32
		wantUse bool
	}{
		{0, 0, false},
		{-5 * time.Second, 0, false},
		{300 * time.Second, 300, true},
		{500 * time.Millisecond, 0, true}, // sub-second: "really 0, don't cache"
		{1500 * time.Millisecond, 1, true},
	}
	for _, c := range cases {
		gotTTL, gotUse := ttlArgs(c.in)
		if gotTTL != c.wantTTL || gotUse != c.wantUse {
			t.Errorf("ttlArgs(%v) = (%d, %t), want (%d, %t)", c.in, gotTTL, gotUse, c.wantTTL, c.wantUse)
		}
	}
}

func TestCanonFQDNAndIP(t *testing.T) {
	if got := canonFQDN("Mail.Example.COM."); got != "mail.example.com" {
		t.Errorf("canonFQDN = %q", got)
	}
	if got := canonIP(" 2001:0DB8::0001 "); got != "2001:db8::1" {
		t.Errorf("canonIP = %q", got)
	}
	if got := canonIP("not-an-ip"); got != "not-an-ip" {
		t.Errorf("canonIP passthrough = %q", got)
	}
}

// TestCanonicalValueRoundTrip checks that an existing Infoblox record and the
// libdns RR that should match it reduce to the same canonical string — the
// invariant every RRset comparison in Set/Delete depends on.
func TestCanonicalValueRoundTrip(t *testing.T) {
	txtRec := &ibclient.RecordTXT{Text: ptr("token-xyz")}
	if got, _ := txtKind.canonicalRRValue(libdns.TXT{Text: "token-xyz"}.RR()); got != txtKind.canonicalValue(txtRec) {
		t.Errorf("TXT canonical mismatch: %q vs %q", got, txtKind.canonicalValue(txtRec))
	}

	aRec := &ibclient.RecordA{Ipv4Addr: ptr("192.0.2.5")}
	if got, _ := aKind.canonicalRRValue(libdns.Address{IP: netip.MustParseAddr("192.0.2.5")}.RR()); got != aKind.canonicalValue(aRec) {
		t.Errorf("A canonical mismatch: %q vs %q", got, aKind.canonicalValue(aRec))
	}

	aaaaRec := &ibclient.RecordAAAA{Ipv6Addr: ptr("2001:db8::1")}
	if got, _ := aaaaKind.canonicalRRValue(libdns.Address{IP: netip.MustParseAddr("2001:0db8::1")}.RR()); got != aaaaKind.canonicalValue(aaaaRec) {
		t.Errorf("AAAA canonical mismatch: %q vs %q", got, aaaaKind.canonicalValue(aaaaRec))
	}

	cnameRec := &ibclient.RecordCNAME{Canonical: ptr("target.example.com")}
	if got, _ := cnameKind.canonicalRRValue(libdns.CNAME{Target: "target.example.com."}.RR()); got != cnameKind.canonicalValue(cnameRec) {
		t.Errorf("CNAME canonical mismatch: %q vs %q", got, cnameKind.canonicalValue(cnameRec))
	}

	mxRec := &ibclient.RecordMX{Preference: ptr(uint32(10)), MailExchanger: ptr("mail.example.com")}
	if got, _ := mxKind.canonicalRRValue(libdns.MX{Preference: 10, Target: "mail.example.com."}.RR()); got != mxKind.canonicalValue(mxRec) {
		t.Errorf("MX canonical mismatch: %q vs %q", got, mxKind.canonicalValue(mxRec))
	}

	srvRec := &ibclient.RecordSRV{Priority: ptr(uint32(1)), Weight: ptr(uint32(2)), Port: ptr(uint32(443)), Target: ptr("svc.example.com")}
	if got, _ := srvKind.canonicalRRValue(libdns.SRV{Priority: 1, Weight: 2, Port: 443, Target: "svc.example.com."}.RR()); got != srvKind.canonicalValue(srvRec) {
		t.Errorf("SRV canonical mismatch: %q vs %q", got, srvKind.canonicalValue(srvRec))
	}
}

func txt(name, text string, ttlSecs uint32) ibclient.RecordTXT {
	useTtl := ttlSecs != 0
	return ibclient.RecordTXT{
		Ref:    "record:txt/" + name + ":" + text,
		Name:   ptr(name + ".example.com"),
		Text:   ptr(text),
		Ttl:    ptr(ttlSecs),
		UseTtl: ptr(useTtl),
	}
}

// TestPlanRRSet_MultiTXT is the core regression: two challenge tokens live at the
// same name and SetRecords with one of them must remove only the other, not
// mutate an arbitrary first match.
func TestPlanRRSet_MultiTXT(t *testing.T) {
	existing := []ibclient.RecordTXT{
		txt("_acme-challenge", "token-A", 0),
		txt("_acme-challenge", "token-B", 0),
	}
	desired := []libdns.RR{libdns.TXT{Name: "_acme-challenge", Text: "token-A"}.RR()}

	plan, err := planRRSet(existing, desired, txtKind)
	if err != nil {
		t.Fatalf("planRRSet: %v", err)
	}
	if len(plan.create) != 0 || len(plan.update) != 0 {
		t.Fatalf("expected no create/update, got %+v", plan)
	}
	if len(plan.keep) != 1 || strVal(plan.keep[0].Text) != "token-A" {
		t.Fatalf("expected to keep token-A, got %+v", plan.keep)
	}
	if len(plan.delete) != 1 || strVal(plan.delete[0].Text) != "token-B" {
		t.Fatalf("expected to delete token-B only, got %+v", plan.delete)
	}
}

func TestPlanRRSet_AddUpdateNoop(t *testing.T) {
	// Add a second value alongside an existing one.
	plan, _ := planRRSet(
		[]ibclient.RecordTXT{txt("x", "one", 0)},
		[]libdns.RR{
			libdns.TXT{Name: "x", Text: "one"}.RR(),
			libdns.TXT{Name: "x", Text: "two"}.RR(),
		},
		txtKind,
	)
	if len(plan.create) != 1 || plan.create[0].Data != "two" {
		t.Errorf("expected create [two], got %+v", plan.create)
	}
	if len(plan.delete) != 0 {
		t.Errorf("expected no deletes, got %+v", plan.delete)
	}

	// Same value, different TTL => update, not create+delete.
	plan, _ = planRRSet(
		[]ibclient.RecordTXT{txt("x", "one", 300)},
		[]libdns.RR{libdns.TXT{Name: "x", Text: "one", TTL: 60 * time.Second}.RR()},
		txtKind,
	)
	if len(plan.update) != 1 || len(plan.create) != 0 || len(plan.delete) != 0 {
		t.Errorf("expected a single update, got %+v", plan)
	}

	// Same value, same TTL => nothing to do, still reported via keep.
	plan, _ = planRRSet(
		[]ibclient.RecordTXT{txt("x", "one", 300)},
		[]libdns.RR{libdns.TXT{Name: "x", Text: "one", TTL: 300 * time.Second}.RR()},
		txtKind,
	)
	if len(plan.update) != 0 || len(plan.create) != 0 || len(plan.delete) != 0 || len(plan.keep) != 1 {
		t.Errorf("expected pure keep, got %+v", plan)
	}
}

func TestMatchesDelete(t *testing.T) {
	recA := txt("_acme-challenge", "token-A", 300)

	cases := []struct {
		name string
		rr   libdns.RR
		want bool
	}{
		{"exact value", libdns.TXT{Name: "_acme-challenge", Text: "token-A", TTL: 300 * time.Second}.RR(), true},
		{"other value is not matched", libdns.TXT{Name: "_acme-challenge", Text: "token-B"}.RR(), false},
		{"empty value is a wildcard", libdns.RR{Type: "TXT", Name: "_acme-challenge"}, true},
		{"value wildcard, ttl wildcard", libdns.RR{Type: "TXT", Name: "_acme-challenge", TTL: 0}, true},
		{"value match, ttl wildcard", libdns.TXT{Name: "_acme-challenge", Text: "token-A"}.RR(), true},
		{"value match, ttl mismatch", libdns.TXT{Name: "_acme-challenge", Text: "token-A", TTL: 60 * time.Second}.RR(), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := matchesDelete(&recA, c.rr, txtKind)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("matchesDelete = %t, want %t", got, c.want)
			}
		})
	}
}

func TestOrderedNamesAndGrouping(t *testing.T) {
	rrs := []libdns.RR{
		{Type: "TXT", Name: "b"},
		{Type: "TXT", Name: "a"},
		{Type: "TXT", Name: "b"},
	}
	names := orderedNames(rrs)
	if len(names) != 2 || names[0] != "b" || names[1] != "a" {
		t.Fatalf("orderedNames = %v", names)
	}
	if got := rrsForName(rrs, "b"); len(got) != 2 {
		t.Errorf("rrsForName(b) = %d records, want 2", len(got))
	}
}

func TestSRVKindToRecord_NoHostPart(t *testing.T) {
	// "_sip._tcp" with nothing after it means the SRV lives at the zone apex.
	rec := &ibclient.RecordSRV{
		Name:     ptr("_sip._tcp.example.com"),
		Priority: ptr(uint32(1)),
		Weight:   ptr(uint32(1)),
		Port:     ptr(uint32(1)),
		Target:   ptr("sip.example.com"),
	}
	got, err := srvKind.toRecord(rec, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	srv, ok := got.(libdns.SRV)
	if !ok {
		t.Fatalf("got %T, want libdns.SRV", got)
	}
	if srv.Name != "@" {
		t.Errorf("Name = %q, want \"@\"", srv.Name)
	}
}
