package infoblox

import (
	"context"
	"fmt"
	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
	"github.com/libdns/libdns"
	"strings"
)

// Provider facilitates DNS record manipulation with Infoblox
type Provider struct {
	Host     string `json:"host,omitempty"`
	Version  string `json:"version,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(_ context.Context, zone string) ([]libdns.Record, error) {
	conn, err := p.getConnector()
	if err != nil {
		return nil, fmt.Errorf("failed to get connector: %w", err)
	}
	qp := ibclient.NewQueryParams(false, map[string]string{"name": zone})

	var cnameRecords []ibclient.RecordCNAME
	err = conn.GetObject(&ibclient.RecordCNAME{}, "", qp, &cnameRecords)
	if err != nil {
		return nil, fmt.Errorf("failed to get CNAME records: %w", err)
	}

	var txtRecords []ibclient.RecordTXT
	err = conn.GetObject(&ibclient.RecordTXT{}, "", qp, &txtRecords)
	if err != nil {
		return nil, fmt.Errorf("failed to get TXT records: %w", err)
	}

	var legitzone = strings.TrimSuffix(zone, ".")

	var list []libdns.Record
	for i := range cnameRecords {
		list = append(list, libdns.RR{
			Type: "CNAME",
			Name: strings.TrimSuffix(*cnameRecords[i].Name, "."+legitzone),
			Data: *cnameRecords[i].Canonical,
		})
	}

	for i := range txtRecords {
		list = append(list, libdns.RR{
			Type: "TXT",
			Name: strings.TrimSuffix(*txtRecords[i].Name, "."+legitzone),
			Data: *txtRecords[i].Text,
		})
	}

	return list, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(_ context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var added []libdns.Record

	objMgr, err := p.getObjectManager()
	if err != nil {
		return nil, fmt.Errorf("failed to get object manager: %w", err)
	}

	var legitzone = strings.TrimSuffix(zone, ".")

	for i := range records {
		var rec = records[i]
		var recRR = rec.RR()
		switch recRR.Type {
		case "CNAME":
			record, err := objMgr.CreateCNAMERecord("default", recRR.Data, recRR.Name+"."+legitzone, true, uint32(recRR.TTL.Seconds()), "", nil)
			if err != nil {
				continue
			}
			added = append(added, libdns.RR{
				Type: "CNAME",
				Name: strings.TrimSuffix(*record.Name, "."+legitzone),
				Data: *record.Canonical,
			})
		case "TXT":
			record, err := objMgr.CreateTXTRecord("default", recRR.Name+"."+legitzone, recRR.Data, uint32(recRR.TTL.Seconds()), true, "", nil)
			if err != nil {
				continue
			}
			added = append(added, libdns.RR{
				Type: "TXT",
				Name: strings.TrimSuffix(*record.Name, "."+legitzone),
				Data: *record.Text,
			})
		}
	}

	return added, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(_ context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var updated []libdns.Record

	objMgr, err := p.getObjectManager()
	if err != nil {
		return nil, fmt.Errorf("failed to get object manager: %w", err)
	}

	var legitzone = strings.TrimSuffix(zone, ".")

	for i := range records {
		var rec = records[i]
		var recRR = rec.RR()
		switch recRR.Type {
		case "CNAME":
			record, err := objMgr.GetCNAMERecord("default", "", recRR.Name)
			if err != nil {
				record, err = objMgr.CreateCNAMERecord("default", recRR.Data, recRR.Name+"."+legitzone, true, uint32(recRR.TTL.Seconds()), "", nil)
				if err != nil {
					continue
				}
			} else {
				_, err := objMgr.UpdateCNAMERecord(record.Ref, recRR.Data, *record.Name, *record.UseTtl, *record.Ttl, *record.Comment, record.Ea)
				if err != nil {
					continue
				}
			}
			updated = append(updated, libdns.RR{
				Type: "CNAME",
				Name: strings.TrimSuffix(*record.Name, "."+legitzone),
				Data: *record.Canonical,
			})
		case "TXT":
			record, err := objMgr.GetTXTRecord("default", recRR.Name)
			if err != nil {
				record, err = objMgr.CreateTXTRecord("default", recRR.Name+"."+legitzone, recRR.Data, uint32(recRR.TTL.Seconds()), true, "", nil)
				if err != nil {
					continue
				}
			} else {
				record, err = objMgr.UpdateTXTRecord(record.Ref, *record.Name, recRR.Data, *record.Ttl, *record.UseTtl, *record.Comment, record.Ea)
				if err != nil {
					continue
				}
			}
			updated = append(updated, libdns.RR{
				Type: "TXT",
				Name: strings.TrimSuffix(*record.Name, "."+legitzone),
				Data: *record.Text,
			})
		}
	}

	return updated, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(_ context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var deleted []libdns.Record

	objMgr, err := p.getObjectManager()
	if err != nil {
		return nil, fmt.Errorf("failed to get object manager: %w", err)
	}

	var legitzone = strings.TrimSuffix(zone, ".")

	for i := range records {
		var rec = records[i]
		var recRR = rec.RR()
		switch recRR.Type {
		case "CNAME":
			record, err := objMgr.GetCNAMERecord("default", "", recRR.Name+"."+legitzone)
			if err != nil {
				continue
			}
			_, err = objMgr.DeleteCNAMERecord(record.Ref)
			if err != nil {
				continue
			}
			deleted = append(deleted, libdns.RR{
				Type: "CNAME",
				Name: strings.TrimSuffix(*record.Name, "."+legitzone),
				Data: *record.Canonical,
			})
		case "TXT":
			record, err := objMgr.GetTXTRecord("default", recRR.Name+"."+legitzone)
			if err != nil {
				continue
			}
			_, err = objMgr.DeleteTXTRecord(record.Ref)
			if err != nil {
				continue
			}
			deleted = append(deleted, libdns.RR{
				Type: "TXT",
				Name: strings.TrimSuffix(*record.Name, "."+legitzone),
				Data: *record.Text,
			})
		}
	}

	return deleted, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)