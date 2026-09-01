package infoblox

import (
	"context"
	"errors"
	"fmt"
	"strings"

	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with Infoblox.
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
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(_ context.Context, zone string) ([]libdns.Record, error) {
	conn, err := p.getConnector()
	if err != nil {
		return nil, fmt.Errorf("failed to get connector: %w", err)
	}

	legitzone := strings.TrimSuffix(zone, ".")
	qp := ibclient.NewQueryParams(false, map[string]string{"zone": legitzone, "view": p.view()})

	var cnameRecords []ibclient.RecordCNAME
	if err := conn.GetObject(&ibclient.RecordCNAME{}, "", qp, &cnameRecords); err != nil {
		return nil, fmt.Errorf("failed to get CNAME records: %w", err)
	}

	var txtRecords []ibclient.RecordTXT
	if err := conn.GetObject(&ibclient.RecordTXT{}, "", qp, &txtRecords); err != nil {
		return nil, fmt.Errorf("failed to get TXT records: %w", err)
	}

	var list []libdns.Record
	for i := range cnameRecords {
		list = append(list, libdns.RR{
			Type: "CNAME",
			Name: relativeName(strVal(cnameRecords[i].Name), legitzone),
			Data: strVal(cnameRecords[i].Canonical),
		})
	}

	for i := range txtRecords {
		list = append(list, libdns.RR{
			Type: "TXT",
			Name: relativeName(strVal(txtRecords[i].Name), legitzone),
			Data: strVal(txtRecords[i].Text),
		})
	}

	return list, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
// Records that fail to be created are reported via the returned error but do not
// stop the remaining records from being processed.
func (p *Provider) AppendRecords(_ context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var added []libdns.Record
	var errs []error

	objMgr, err := p.getObjectManager()
	if err != nil {
		return nil, fmt.Errorf("failed to get object manager: %w", err)
	}

	view := p.view()
	legitzone := strings.TrimSuffix(zone, ".")

	for _, rec := range records {
		recRR := rec.RR()
		fqdn := recRR.Name + "." + legitzone
		switch recRR.Type {
		case "CNAME":
			record, err := objMgr.CreateCNAMERecord(view, recRR.Data, fqdn, true, uint32(recRR.TTL.Seconds()), "", nil)
			if err != nil {
				errs = append(errs, fmt.Errorf("create CNAME %q: %w", fqdn, err))
				continue
			}
			added = append(added, libdns.RR{
				Type: "CNAME",
				Name: relativeName(strVal(record.Name), legitzone),
				Data: strVal(record.Canonical),
			})
		case "TXT":
			record, err := objMgr.CreateTXTRecord(view, fqdn, recRR.Data, uint32(recRR.TTL.Seconds()), true, "", nil)
			if err != nil {
				errs = append(errs, fmt.Errorf("create TXT %q: %w", fqdn, err))
				continue
			}
			added = append(added, libdns.RR{
				Type: "TXT",
				Name: relativeName(strVal(record.Name), legitzone),
				Data: strVal(record.Text),
			})
		default:
			errs = append(errs, fmt.Errorf("unsupported record type %q for %q", recRR.Type, recRR.Name))
		}
	}

	return added, errors.Join(errs...)
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records. Records that fail are reported via the returned error but do not
// stop the remaining records from being processed.
func (p *Provider) SetRecords(_ context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var updated []libdns.Record
	var errs []error

	conn, err := p.getConnector()
	if err != nil {
		return nil, fmt.Errorf("failed to get connector: %w", err)
	}
	objMgr := ibclient.NewObjectManager(conn, "", "")

	view := p.view()
	legitzone := strings.TrimSuffix(zone, ".")

	for _, rec := range records {
		recRR := rec.RR()
		fqdn := recRR.Name + "." + legitzone
		switch recRR.Type {
		case "CNAME":
			existing, found, err := findCNAMERecord(conn, view, fqdn)
			if err != nil {
				errs = append(errs, fmt.Errorf("looking up CNAME %q: %w", fqdn, err))
				continue
			}

			var record *ibclient.RecordCNAME
			if found {
				record, err = objMgr.UpdateCNAMERecord(existing.Ref, recRR.Data, strVal(existing.Name), boolVal(existing.UseTtl), uint32Val(existing.Ttl), strVal(existing.Comment), existing.Ea)
			} else {
				record, err = objMgr.CreateCNAMERecord(view, recRR.Data, fqdn, true, uint32(recRR.TTL.Seconds()), "", nil)
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("set CNAME %q: %w", fqdn, err))
				continue
			}
			updated = append(updated, libdns.RR{
				Type: "CNAME",
				Name: relativeName(strVal(record.Name), legitzone),
				Data: strVal(record.Canonical),
			})
		case "TXT":
			existing, found, err := findTXTRecord(conn, view, fqdn)
			if err != nil {
				errs = append(errs, fmt.Errorf("looking up TXT %q: %w", fqdn, err))
				continue
			}

			var record *ibclient.RecordTXT
			if found {
				record, err = objMgr.UpdateTXTRecord(existing.Ref, strVal(existing.Name), recRR.Data, uint32Val(existing.Ttl), boolVal(existing.UseTtl), strVal(existing.Comment), existing.Ea)
			} else {
				record, err = objMgr.CreateTXTRecord(view, fqdn, recRR.Data, uint32(recRR.TTL.Seconds()), true, "", nil)
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("set TXT %q: %w", fqdn, err))
				continue
			}
			updated = append(updated, libdns.RR{
				Type: "TXT",
				Name: relativeName(strVal(record.Name), legitzone),
				Data: strVal(record.Text),
			})
		default:
			errs = append(errs, fmt.Errorf("unsupported record type %q for %q", recRR.Type, recRR.Name))
		}
	}

	return updated, errors.Join(errs...)
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
// Records that fail to be deleted (including ones that no longer exist) are reported via the
// returned error but do not stop the remaining records from being processed.
func (p *Provider) DeleteRecords(_ context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var deleted []libdns.Record
	var errs []error

	conn, err := p.getConnector()
	if err != nil {
		return nil, fmt.Errorf("failed to get connector: %w", err)
	}
	objMgr := ibclient.NewObjectManager(conn, "", "")

	view := p.view()
	legitzone := strings.TrimSuffix(zone, ".")

	for _, rec := range records {
		recRR := rec.RR()
		fqdn := recRR.Name + "." + legitzone
		switch recRR.Type {
		case "CNAME":
			existing, found, err := findCNAMERecord(conn, view, fqdn)
			if err != nil {
				errs = append(errs, fmt.Errorf("looking up CNAME %q: %w", fqdn, err))
				continue
			}
			if !found {
				errs = append(errs, fmt.Errorf("delete CNAME %q: not found", fqdn))
				continue
			}
			if _, err := objMgr.DeleteCNAMERecord(existing.Ref); err != nil {
				errs = append(errs, fmt.Errorf("delete CNAME %q: %w", fqdn, err))
				continue
			}
			deleted = append(deleted, libdns.RR{
				Type: "CNAME",
				Name: relativeName(strVal(existing.Name), legitzone),
				Data: strVal(existing.Canonical),
			})
		case "TXT":
			existing, found, err := findTXTRecord(conn, view, fqdn)
			if err != nil {
				errs = append(errs, fmt.Errorf("looking up TXT %q: %w", fqdn, err))
				continue
			}
			if !found {
				errs = append(errs, fmt.Errorf("delete TXT %q: not found", fqdn))
				continue
			}
			if _, err := objMgr.DeleteTXTRecord(existing.Ref); err != nil {
				errs = append(errs, fmt.Errorf("delete TXT %q: %w", fqdn, err))
				continue
			}
			deleted = append(deleted, libdns.RR{
				Type: "TXT",
				Name: relativeName(strVal(existing.Name), legitzone),
				Data: strVal(existing.Text),
			})
		default:
			errs = append(errs, fmt.Errorf("unsupported record type %q for %q", recRR.Type, recRR.Name))
		}
	}

	return deleted, errors.Join(errs...)
}

// findCNAMERecord looks up a CNAME record by its fully-qualified name within a view.
// It is used instead of objMgr.GetCNAMERecord, which also requires the record's
// current canonical target to be known up front — unworkable for a name-based upsert.
func findCNAMERecord(conn *ibclient.Connector, view, fqdn string) (record *ibclient.RecordCNAME, found bool, err error) {
	var results []ibclient.RecordCNAME
	qp := ibclient.NewQueryParams(false, map[string]string{"view": view, "name": fqdn})
	if err := conn.GetObject(&ibclient.RecordCNAME{}, "", qp, &results); err != nil {
		return nil, false, err
	}
	if len(results) == 0 {
		return nil, false, nil
	}
	return &results[0], true, nil
}

// findTXTRecord looks up a TXT record by its fully-qualified name within a view.
func findTXTRecord(conn *ibclient.Connector, view, fqdn string) (record *ibclient.RecordTXT, found bool, err error) {
	var results []ibclient.RecordTXT
	qp := ibclient.NewQueryParams(false, map[string]string{"view": view, "name": fqdn})
	if err := conn.GetObject(&ibclient.RecordTXT{}, "", qp, &results); err != nil {
		return nil, false, err
	}
	if len(results) == 0 {
		return nil, false, nil
	}
	return &results[0], true, nil
}

// relativeName strips the trailing zone (and separating dot) from a fully-qualified
// record name, leaving it relative the way libdns expects.
func relativeName(fqdn, legitzone string) string {
	return strings.TrimSuffix(fqdn, "."+legitzone)
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

func boolVal(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
