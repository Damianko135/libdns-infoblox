package infoblox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
	"github.com/libdns/libdns"
)

// Provider manages DNS records on an Infoblox NIOS grid through its WAPI.
//
// The package is built for one job: letting Caddy (via libdns / certmagic)
// solve ACME DNS-01 challenges against Infoblox, which means creating,
// reading and removing TXT records reliably. A, AAAA, CNAME, MX and SRV
// records are handled too, as ordinary zone-file record types with a clean
// libdns representation, but they are not the focus and no Infoblox-specific
// modelling (host records, IPAM, DTC, DNSSEC administration, delegation) is
// exposed.
//
// NS records are intentionally not supported: Infoblox models them as
// zone-delegation metadata (name-server glue addresses, MS delegation names)
// rather than a simple name/target pair, and delegation management is out of
// scope for a DNS-01 provider. Records of any other type are reported as an
// error rather than silently ignored.
type Provider struct {
	Host     string `json:"host,omitempty"`
	Port     string `json:"port,omitempty"`
	Version  string `json:"version,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// View is the Infoblox DNS view to operate in. Defaults to "default".
	View string `json:"view,omitempty"`
	// Insecure disables TLS certificate verification. Leave false in production;
	// only set true against a trusted lab/test grid with a self-signed certificate.
	Insecure bool `json:"insecure,omitempty"`

	mu   sync.Mutex
	conn *ibclient.Connector
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	conn, err := p.getConnector()
	if err != nil {
		return nil, fmt.Errorf("failed to get connector: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	view := p.view()
	legitzone := strings.TrimSuffix(zone, ".")

	var list []libdns.Record
	var errs []error
	collect := func(recs []libdns.Record, err error) {
		if err != nil {
			errs = append(errs, err)
			return
		}
		list = append(list, recs...)
	}

	collect(listRecordsOfKind(ctx, conn, view, legitzone, cnameKind))
	collect(listRecordsOfKind(ctx, conn, view, legitzone, txtKind))
	collect(listRecordsOfKind(ctx, conn, view, legitzone, aKind))
	collect(listRecordsOfKind(ctx, conn, view, legitzone, aaaaKind))
	collect(listRecordsOfKind(ctx, conn, view, legitzone, mxKind))
	collect(listRecordsOfKind(ctx, conn, view, legitzone, srvKind))

	return list, errors.Join(errs...)
}

// AppendRecords adds records to the zone. It returns the records that were added.
// Records that fail to be created are reported via the returned error but do not
// stop the remaining records from being processed. If an identical record already
// exists it is treated as already added, so a retried call is idempotent.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	conn, err := p.getConnector()
	if err != nil {
		return nil, fmt.Errorf("failed to get connector: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	objMgr := ibclient.NewObjectManager(conn, "", "")

	view := p.view()
	legitzone := strings.TrimSuffix(zone, ".")
	groups := groupByType(records)

	var added []libdns.Record
	var errs []error
	collect := func(recs []libdns.Record, errList []error) {
		added = append(added, recs...)
		errs = append(errs, errList...)
	}

	collect(appendRecordsOfKind(ctx, conn, objMgr, view, legitzone, groups["CNAME"], cnameKind))
	collect(appendRecordsOfKind(ctx, conn, objMgr, view, legitzone, groups["TXT"], txtKind))
	collect(appendRecordsOfKind(ctx, conn, objMgr, view, legitzone, groups["A"], aKind))
	collect(appendRecordsOfKind(ctx, conn, objMgr, view, legitzone, groups["AAAA"], aaaaKind))
	collect(appendRecordsOfKind(ctx, conn, objMgr, view, legitzone, groups["MX"], mxKind))
	collect(appendRecordsOfKind(ctx, conn, objMgr, view, legitzone, groups["SRV"], srvKind))
	errs = append(errs, unsupportedTypeErrors(groups)...)

	return added, errors.Join(errs...)
}

// SetRecords sets the records in the zone so that, for each (name, type) pair in
// the input, the given records are the only members of that RRset — the
// libdns.RecordSetter contract. It returns the records that were set. Records
// that fail are reported via the returned error but do not stop the remaining
// records from being processed. SetRecords is not atomic: on a partial failure
// the zone may be left partway between the old and new state.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	conn, err := p.getConnector()
	if err != nil {
		return nil, fmt.Errorf("failed to get connector: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	objMgr := ibclient.NewObjectManager(conn, "", "")

	view := p.view()
	legitzone := strings.TrimSuffix(zone, ".")
	groups := groupByType(records)

	var updated []libdns.Record
	var errs []error
	collect := func(recs []libdns.Record, errList []error) {
		updated = append(updated, recs...)
		errs = append(errs, errList...)
	}

	collect(setRecordsOfKind(ctx, conn, objMgr, view, legitzone, groups["CNAME"], cnameKind))
	collect(setRecordsOfKind(ctx, conn, objMgr, view, legitzone, groups["TXT"], txtKind))
	collect(setRecordsOfKind(ctx, conn, objMgr, view, legitzone, groups["A"], aKind))
	collect(setRecordsOfKind(ctx, conn, objMgr, view, legitzone, groups["AAAA"], aaaaKind))
	collect(setRecordsOfKind(ctx, conn, objMgr, view, legitzone, groups["MX"], mxKind))
	collect(setRecordsOfKind(ctx, conn, objMgr, view, legitzone, groups["SRV"], srvKind))
	errs = append(errs, unsupportedTypeErrors(groups)...)

	return updated, errors.Join(errs...)
}

// DeleteRecords deletes the records from the zone. It returns the records that
// were deleted. Following libdns.RecordDeleter semantics, an input record's
// value and TTL must match exactly unless left empty (a wildcard), and records
// that do not exist are silently ignored — so a repeated cleanup is safe.
// Failures are reported via the returned error but do not stop the remaining
// records from being processed.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	conn, err := p.getConnector()
	if err != nil {
		return nil, fmt.Errorf("failed to get connector: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	view := p.view()
	legitzone := strings.TrimSuffix(zone, ".")
	groups := groupByType(records)

	var deleted []libdns.Record
	var errs []error
	collect := func(recs []libdns.Record, errList []error) {
		deleted = append(deleted, recs...)
		errs = append(errs, errList...)
	}

	collect(deleteRecordsOfKind(ctx, conn, view, legitzone, groups["CNAME"], cnameKind))
	collect(deleteRecordsOfKind(ctx, conn, view, legitzone, groups["TXT"], txtKind))
	collect(deleteRecordsOfKind(ctx, conn, view, legitzone, groups["A"], aKind))
	collect(deleteRecordsOfKind(ctx, conn, view, legitzone, groups["AAAA"], aaaaKind))
	collect(deleteRecordsOfKind(ctx, conn, view, legitzone, groups["MX"], mxKind))
	collect(deleteRecordsOfKind(ctx, conn, view, legitzone, groups["SRV"], srvKind))
	errs = append(errs, unsupportedTypeErrors(groups)...)

	return deleted, errors.Join(errs...)
}

// supportedRecordTypes lists the libdns.RR.Type values this Provider knows how to handle.
var supportedRecordTypes = map[string]bool{
	"CNAME": true,
	"TXT":   true,
	"A":     true,
	"AAAA":  true,
	"MX":    true,
	"SRV":   true,
}

// groupByType buckets records by their RR type so each kind can be processed together.
func groupByType(records []libdns.Record) map[string][]libdns.RR {
	groups := make(map[string][]libdns.RR)
	for _, r := range records {
		rr := r.RR()
		groups[rr.Type] = append(groups[rr.Type], rr)
	}
	return groups
}

// unsupportedTypeErrors reports one error per record of a type this Provider doesn't handle.
func unsupportedTypeErrors(groups map[string][]libdns.RR) []error {
	var errs []error
	for t, rrs := range groups {
		if supportedRecordTypes[t] {
			continue
		}
		for _, rr := range rrs {
			errs = append(errs, fmt.Errorf("unsupported record type %q for %q", t, rr.Name))
		}
	}
	return errs
}

// relativeName strips the trailing zone (and separating dot) from a fully-qualified
// record name, leaving it relative the way libdns expects. A record sitting at the
// zone apex is reported as "@", per libdns's documented convention for RR.Name.
func relativeName(fqdn, legitzone string) string {
	if fqdn == legitzone {
		return "@"
	}
	return strings.TrimSuffix(fqdn, "."+legitzone)
}

// absoluteName is the inverse of relativeName: it qualifies a libdns record name
// (which may be "@" or "" for the zone apex, per libdns's RR.Name convention)
// into the fully-qualified name Infoblox expects.
func absoluteName(name, legitzone string) string {
	if name == "" || name == "@" {
		return legitzone
	}
	return name + "." + legitzone
}

func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func uint32Val(v *uint32) uint32 {
	if v == nil {
		return 0
	}
	return *v
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ libdns.ZoneLister     = (*Provider)(nil)
)
