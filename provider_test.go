package infoblox

import (
	"strings"
	"testing"

	"github.com/libdns/libdns"
)

func TestGroupByType(t *testing.T) {
	records := []libdns.Record{
		libdns.CNAME{Name: "www", Target: "target.example.com"},
		libdns.TXT{Name: "_acme-challenge", Text: "token-1"},
		libdns.TXT{Name: "_acme-challenge", Text: "token-2"},
		libdns.Address{Name: "api"},
	}

	groups := groupByType(records)

	if got := len(groups["CNAME"]); got != 1 {
		t.Errorf("CNAME group has %d records, want 1", got)
	}
	if got := len(groups["TXT"]); got != 2 {
		t.Errorf("TXT group has %d records, want 2", got)
	}
	if got := len(groups["A"]); got != 1 {
		t.Errorf("A group has %d records, want 1", got)
	}
	if got := len(groups["AAAA"]); got != 0 {
		t.Errorf("AAAA group has %d records, want 0", got)
	}
}

func TestUnsupportedTypeErrors(t *testing.T) {
	groups := map[string][]libdns.RR{
		"CNAME": {{Type: "CNAME", Name: "www"}},
		"NS":    {{Type: "NS", Name: "@"}},
		"CAA":   {{Type: "CAA", Name: "@"}, {Type: "CAA", Name: "www"}},
	}

	errs := unsupportedTypeErrors(groups)
	if len(errs) != 3 {
		t.Fatalf("got %d errors, want 3 (one per unsupported record, none for CNAME)", len(errs))
	}
	for _, err := range errs {
		if strings.Contains(err.Error(), "CNAME") {
			t.Errorf("supported type CNAME should not produce an error, got: %v", err)
		}
	}
}

func TestProviderPort(t *testing.T) {
	if got := (&Provider{}).port(); got != defaultPort {
		t.Errorf("empty Port = %q, want %q", got, defaultPort)
	}
	if got := (&Provider{Port: "8443"}).port(); got != "8443" {
		t.Errorf("custom Port = %q, want \"8443\"", got)
	}
}

func TestProviderView(t *testing.T) {
	if got := (&Provider{}).view(); got != defaultView {
		t.Errorf("empty View = %q, want %q", got, defaultView)
	}
	if got := (&Provider{View: "internal"}).view(); got != "internal" {
		t.Errorf("custom View = %q, want \"internal\"", got)
	}
}

// newValidProvider returns a fresh, fully-populated Provider. It's a function
// rather than a shared value because Provider embeds a sync.Mutex, which must
// never be copied after first use.
func newValidProvider() *Provider {
	return &Provider{Host: "gm.example.com", Username: "admin", Password: "secret", Version: "2.12"}
}

func TestProviderValidate(t *testing.T) {
	if err := newValidProvider().validate(); err != nil {
		t.Errorf("fully populated Provider should validate, got: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(p *Provider)
		wantSub string
	}{
		{"missing Host", func(p *Provider) { p.Host = "" }, "Host"},
		{"missing Username", func(p *Provider) { p.Username = "" }, "Username"},
		{"missing Password", func(p *Provider) { p.Password = "" }, "Password"},
		{"missing Version", func(p *Provider) { p.Version = "" }, "Version"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newValidProvider()
			c.mutate(p)
			err := p.validate()
			if err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Errorf("error %q does not mention %q", err.Error(), c.wantSub)
			}
		})
	}
}

func TestGetConnectorFailsFastOnInvalidConfig(t *testing.T) {
	// No network call should be attempted: validation happens before any
	// connection is established.
	_, err := (&Provider{}).getConnector()
	if err == nil {
		t.Fatal("expected a validation error for an empty Provider, got nil")
	}
	if !strings.Contains(err.Error(), "Host") {
		t.Errorf("error %q does not mention the missing Host field", err.Error())
	}
}

func TestProviderCloseWithoutConnection(t *testing.T) {
	p := &Provider{}
	if err := p.Close(); err != nil {
		t.Errorf("Close() on a never-connected Provider should be a no-op, got: %v", err)
	}
}
