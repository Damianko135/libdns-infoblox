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
		Name: ptr("_acme-challenge.example.com"),
		Text: ptr("some-token"),
		Ttl:  ptr(uint32(60)),
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
