package infoblox

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
	"github.com/libdns/libdns"
)

// recordKind bundles the operations needed to drive one Infoblox record type
// (CNAME, TXT, A, AAAA, MX or SRV) through libdns's Get/Append/Set/Delete
// verbs, so those four methods can share one implementation instead of
// repeating a near-identical block per type.
type recordKind[T any] struct {
	typeName string

	// list returns every record of this kind within the zone.
	list func(conn *ibclient.Connector, view, legitzone string) ([]T, error)
	// find looks up a single record of this kind by its fully-qualified name.
	// It is used instead of the client library's GetXRecord helpers, which
	// require the record's current value to already be known — unworkable
	// for a name-based upsert.
	find func(conn *ibclient.Connector, view, fqdn string) (*T, bool, error)
	// create makes a new record from a libdns.RR.
	create func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, fqdn string, rr libdns.RR) (*T, error)
	// update applies a libdns.RR's value and TTL onto an existing record,
	// preserving that record's comment and extensible attributes.
	update func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, existing *T, fqdn string, rr libdns.RR) (*T, error)
	// deleteRecord removes an existing record.
	deleteRecord func(conn *ibclient.Connector, existing *T) error
	// toRR converts a fetched record into a libdns.RR relative to the zone.
	toRR func(rec *T, legitzone string) libdns.RR
}

func listRecordsOfKind[T any](conn *ibclient.Connector, view, legitzone string, k recordKind[T]) ([]libdns.Record, error) {
	recs, err := k.list(conn, view, legitzone)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s records: %w", k.typeName, err)
	}
	list := make([]libdns.Record, 0, len(recs))
	for i := range recs {
		list = append(list, k.toRR(&recs[i], legitzone))
	}
	return list, nil
}

func appendRecordsOfKind[T any](conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, legitzone string, rrs []libdns.RR, k recordKind[T]) ([]libdns.Record, []error) {
	var added []libdns.Record
	var errs []error

	for _, rr := range rrs {
		fqdn := rr.Name + "." + legitzone
		rec, err := k.create(conn, objMgr, view, fqdn, rr)
		if err != nil {
			errs = append(errs, fmt.Errorf("create %s %q: %w", k.typeName, fqdn, err))
			continue
		}
		added = append(added, k.toRR(rec, legitzone))
	}

	return added, errs
}

func setRecordsOfKind[T any](conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, legitzone string, rrs []libdns.RR, k recordKind[T]) ([]libdns.Record, []error) {
	var updated []libdns.Record
	var errs []error

	for _, rr := range rrs {
		fqdn := rr.Name + "." + legitzone
		existing, found, err := k.find(conn, view, fqdn)
		if err != nil {
			errs = append(errs, fmt.Errorf("looking up %s %q: %w", k.typeName, fqdn, err))
			continue
		}

		var rec *T
		if found {
			rec, err = k.update(conn, objMgr, existing, fqdn, rr)
		} else {
			rec, err = k.create(conn, objMgr, view, fqdn, rr)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("set %s %q: %w", k.typeName, fqdn, err))
			continue
		}
		updated = append(updated, k.toRR(rec, legitzone))
	}

	return updated, errs
}

func deleteRecordsOfKind[T any](conn *ibclient.Connector, view, legitzone string, rrs []libdns.RR, k recordKind[T]) ([]libdns.Record, []error) {
	var deleted []libdns.Record
	var errs []error

	for _, rr := range rrs {
		fqdn := rr.Name + "." + legitzone
		existing, found, err := k.find(conn, view, fqdn)
		if err != nil {
			errs = append(errs, fmt.Errorf("looking up %s %q: %w", k.typeName, fqdn, err))
			continue
		}
		if !found {
			errs = append(errs, fmt.Errorf("delete %s %q: not found", k.typeName, fqdn))
			continue
		}
		if err := k.deleteRecord(conn, existing); err != nil {
			errs = append(errs, fmt.Errorf("delete %s %q: %w", k.typeName, fqdn, err))
			continue
		}
		deleted = append(deleted, k.toRR(existing, legitzone))
	}

	return deleted, errs
}

// ibObjectPtr constrains PT to be a pointer to T that also implements ibclient.IBObject,
// which is how every generated Infoblox record type satisfies the connector's generic
// Create/Get/Update/Delete methods.
type ibObjectPtr[T any] interface {
	*T
	ibclient.IBObject
}

// listRecordsByZone fetches every record of a given kind within a zone/view.
func listRecordsByZone[T any, PT ibObjectPtr[T]](conn *ibclient.Connector, empty PT, view, legitzone string) ([]T, error) {
	var results []T
	qp := ibclient.NewQueryParams(false, map[string]string{"zone": legitzone, "view": view})
	err := conn.GetObject(empty, "", qp, &results)
	return results, err
}

// findRecordByName looks up a single record of a given kind by its fully-qualified name.
func findRecordByName[T any, PT ibObjectPtr[T]](conn *ibclient.Connector, empty PT, view, fqdn string) (*T, bool, error) {
	var results []T
	qp := ibclient.NewQueryParams(false, map[string]string{"view": view, "name": fqdn})
	if err := conn.GetObject(empty, "", qp, &results); err != nil {
		return nil, false, err
	}
	if len(results) == 0 {
		return nil, false, nil
	}
	return &results[0], true, nil
}

// fetchByRef re-fetches a record by its WAPI object reference, e.g. right after a
// create or update that only returned the new/changed reference string.
func fetchByRef[T any, PT ibObjectPtr[T]](conn *ibclient.Connector, empty PT, ref string) (*T, error) {
	err := conn.GetObject(empty, ref, ibclient.NewQueryParams(false, nil), &empty)
	if err != nil {
		return nil, err
	}
	return (*T)(empty), nil
}

// ttlDuration converts an Infoblox TTL field into the time.Duration libdns expects.
func ttlDuration(ttl *uint32) time.Duration {
	return time.Duration(uint32Val(ttl)) * time.Second
}

// --- CNAME -------------------------------------------------------------

var cnameKind = recordKind[ibclient.RecordCNAME]{
	typeName: "CNAME",
	list: func(conn *ibclient.Connector, view, legitzone string) ([]ibclient.RecordCNAME, error) {
		return listRecordsByZone[ibclient.RecordCNAME](conn, ibclient.NewEmptyRecordCNAME(), view, legitzone)
	},
	find: func(conn *ibclient.Connector, view, fqdn string) (*ibclient.RecordCNAME, bool, error) {
		return findRecordByName[ibclient.RecordCNAME](conn, ibclient.NewEmptyRecordCNAME(), view, fqdn)
	},
	create: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, fqdn string, rr libdns.RR) (*ibclient.RecordCNAME, error) {
		return objMgr.CreateCNAMERecord(view, rr.Data, fqdn, true, uint32(rr.TTL.Seconds()), "", nil)
	},
	update: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, existing *ibclient.RecordCNAME, fqdn string, rr libdns.RR) (*ibclient.RecordCNAME, error) {
		return objMgr.UpdateCNAMERecord(existing.Ref, rr.Data, fqdn, true, uint32(rr.TTL.Seconds()), strVal(existing.Comment), existing.Ea)
	},
	deleteRecord: func(conn *ibclient.Connector, existing *ibclient.RecordCNAME) error {
		_, err := conn.DeleteObject(existing.Ref)
		return err
	},
	toRR: func(rec *ibclient.RecordCNAME, legitzone string) libdns.RR {
		return libdns.RR{
			Type: "CNAME",
			Name: relativeName(strVal(rec.Name), legitzone),
			Data: strVal(rec.Canonical),
			TTL:  ttlDuration(rec.Ttl),
		}
	},
}

// --- TXT -----------------------------------------------------------------

var txtKind = recordKind[ibclient.RecordTXT]{
	typeName: "TXT",
	list: func(conn *ibclient.Connector, view, legitzone string) ([]ibclient.RecordTXT, error) {
		return listRecordsByZone[ibclient.RecordTXT](conn, ibclient.NewEmptyRecordTXT(), view, legitzone)
	},
	find: func(conn *ibclient.Connector, view, fqdn string) (*ibclient.RecordTXT, bool, error) {
		return findRecordByName[ibclient.RecordTXT](conn, ibclient.NewEmptyRecordTXT(), view, fqdn)
	},
	create: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, fqdn string, rr libdns.RR) (*ibclient.RecordTXT, error) {
		return objMgr.CreateTXTRecord(view, fqdn, rr.Data, uint32(rr.TTL.Seconds()), true, "", nil)
	},
	update: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, existing *ibclient.RecordTXT, fqdn string, rr libdns.RR) (*ibclient.RecordTXT, error) {
		return objMgr.UpdateTXTRecord(existing.Ref, fqdn, rr.Data, uint32(rr.TTL.Seconds()), true, strVal(existing.Comment), existing.Ea)
	},
	deleteRecord: func(conn *ibclient.Connector, existing *ibclient.RecordTXT) error {
		_, err := conn.DeleteObject(existing.Ref)
		return err
	},
	toRR: func(rec *ibclient.RecordTXT, legitzone string) libdns.RR {
		return libdns.RR{
			Type: "TXT",
			Name: relativeName(strVal(rec.Name), legitzone),
			Data: strVal(rec.Text),
			TTL:  ttlDuration(rec.Ttl),
		}
	},
}

// --- A ---------------------------------------------------------------------

var aKind = recordKind[ibclient.RecordA]{
	typeName: "A",
	list: func(conn *ibclient.Connector, view, legitzone string) ([]ibclient.RecordA, error) {
		return listRecordsByZone[ibclient.RecordA](conn, ibclient.NewEmptyRecordA(), view, legitzone)
	},
	find: func(conn *ibclient.Connector, view, fqdn string) (*ibclient.RecordA, bool, error) {
		return findRecordByName[ibclient.RecordA](conn, ibclient.NewEmptyRecordA(), view, fqdn)
	},
	create: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, fqdn string, rr libdns.RR) (*ibclient.RecordA, error) {
		return objMgr.CreateARecord("", view, fqdn, "", rr.Data, uint32(rr.TTL.Seconds()), true, "", nil)
	},
	update: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, existing *ibclient.RecordA, fqdn string, rr libdns.RR) (*ibclient.RecordA, error) {
		return objMgr.UpdateARecord(existing.Ref, fqdn, rr.Data, "", "", uint32(rr.TTL.Seconds()), true, strVal(existing.Comment), existing.Ea)
	},
	deleteRecord: func(conn *ibclient.Connector, existing *ibclient.RecordA) error {
		_, err := conn.DeleteObject(existing.Ref)
		return err
	},
	toRR: func(rec *ibclient.RecordA, legitzone string) libdns.RR {
		return libdns.RR{
			Type: "A",
			Name: relativeName(strVal(rec.Name), legitzone),
			Data: strVal(rec.Ipv4Addr),
			TTL:  ttlDuration(rec.Ttl),
		}
	},
}

// --- AAAA --------------------------------------------------------------

var aaaaKind = recordKind[ibclient.RecordAAAA]{
	typeName: "AAAA",
	list: func(conn *ibclient.Connector, view, legitzone string) ([]ibclient.RecordAAAA, error) {
		return listRecordsByZone[ibclient.RecordAAAA](conn, ibclient.NewEmptyRecordAAAA(), view, legitzone)
	},
	find: func(conn *ibclient.Connector, view, fqdn string) (*ibclient.RecordAAAA, bool, error) {
		return findRecordByName[ibclient.RecordAAAA](conn, ibclient.NewEmptyRecordAAAA(), view, fqdn)
	},
	create: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, fqdn string, rr libdns.RR) (*ibclient.RecordAAAA, error) {
		return objMgr.CreateAAAARecord("", view, fqdn, "", rr.Data, true, uint32(rr.TTL.Seconds()), "", nil)
	},
	update: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, existing *ibclient.RecordAAAA, fqdn string, rr libdns.RR) (*ibclient.RecordAAAA, error) {
		return objMgr.UpdateAAAARecord(existing.Ref, "", fqdn, rr.Data, "", true, uint32(rr.TTL.Seconds()), strVal(existing.Comment), existing.Ea)
	},
	deleteRecord: func(conn *ibclient.Connector, existing *ibclient.RecordAAAA) error {
		_, err := conn.DeleteObject(existing.Ref)
		return err
	},
	toRR: func(rec *ibclient.RecordAAAA, legitzone string) libdns.RR {
		return libdns.RR{
			Type: "AAAA",
			Name: relativeName(strVal(rec.Name), legitzone),
			Data: strVal(rec.Ipv6Addr),
			TTL:  ttlDuration(rec.Ttl),
		}
	},
}

// --- MX ----------------------------------------------------------------

// parseMXData splits a libdns MX RR's Data field ("<preference> <exchange>") into
// its two parts. See github.com/libdns/libdns MX.RR().
func parseMXData(data string) (preference uint32, exchanger string, err error) {
	fields := strings.Fields(data)
	if len(fields) != 2 {
		return 0, "", fmt.Errorf("MX record data %q: expected \"<preference> <exchange>\"", data)
	}
	pref, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil {
		return 0, "", fmt.Errorf("MX record data %q: invalid preference: %w", data, err)
	}
	return uint32(pref), fields[1], nil
}

func formatMXData(preference uint32, exchanger string) string {
	return fmt.Sprintf("%d %s", preference, exchanger)
}

// The infoblox-go-client ObjectManager has no MX-record helpers, so MX records
// are built and sent through the connector directly.

func getMXByRef(conn *ibclient.Connector, ref string) (*ibclient.RecordMX, error) {
	return fetchByRef[ibclient.RecordMX](conn, ibclient.NewEmptyRecordMX(), ref)
}

var mxKind = recordKind[ibclient.RecordMX]{
	typeName: "MX",
	list: func(conn *ibclient.Connector, view, legitzone string) ([]ibclient.RecordMX, error) {
		return listRecordsByZone[ibclient.RecordMX](conn, ibclient.NewEmptyRecordMX(), view, legitzone)
	},
	find: func(conn *ibclient.Connector, view, fqdn string) (*ibclient.RecordMX, bool, error) {
		return findRecordByName[ibclient.RecordMX](conn, ibclient.NewEmptyRecordMX(), view, fqdn)
	},
	create: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, fqdn string, rr libdns.RR) (*ibclient.RecordMX, error) {
		preference, exchanger, err := parseMXData(rr.Data)
		if err != nil {
			return nil, err
		}
		ttl := uint32(rr.TTL.Seconds())
		useTtl := true
		rec := ibclient.NewRecordMX(ibclient.RecordMX{
			View:          &view,
			Name:          &fqdn,
			MailExchanger: &exchanger,
			Preference:    &preference,
			Ttl:           &ttl,
			UseTtl:        &useTtl,
		})
		ref, err := conn.CreateObject(rec)
		if err != nil {
			return nil, err
		}
		return getMXByRef(conn, ref)
	},
	update: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, existing *ibclient.RecordMX, fqdn string, rr libdns.RR) (*ibclient.RecordMX, error) {
		preference, exchanger, err := parseMXData(rr.Data)
		if err != nil {
			return nil, err
		}
		ttl := uint32(rr.TTL.Seconds())
		useTtl := true
		rec := ibclient.NewRecordMX(ibclient.RecordMX{
			Ref:           existing.Ref,
			Name:          &fqdn,
			MailExchanger: &exchanger,
			Preference:    &preference,
			Ttl:           &ttl,
			UseTtl:        &useTtl,
			Comment:       existing.Comment,
			Ea:            existing.Ea,
		})
		ref, err := conn.UpdateObject(rec, existing.Ref)
		if err != nil {
			return nil, err
		}
		return getMXByRef(conn, ref)
	},
	deleteRecord: func(conn *ibclient.Connector, existing *ibclient.RecordMX) error {
		_, err := conn.DeleteObject(existing.Ref)
		return err
	},
	toRR: func(rec *ibclient.RecordMX, legitzone string) libdns.RR {
		return libdns.RR{
			Type: "MX",
			Name: relativeName(strVal(rec.Name), legitzone),
			Data: formatMXData(uint32Val(rec.Preference), strVal(rec.MailExchanger)),
			TTL:  ttlDuration(rec.Ttl),
		}
	},
}

// --- SRV -----------------------------------------------------------------

// parseSRVData splits a libdns SRV RR's Data field ("<priority> <weight> <port>
// <target>") into its four parts. Note that the leading "_service._proto" label
// is already folded into the record Name by libdns's SRV.RR(), not into Data.
// See github.com/libdns/libdns SRV.RR().
func parseSRVData(data string) (priority, weight, port uint32, target string, err error) {
	fields := strings.Fields(data)
	if len(fields) != 4 {
		return 0, 0, 0, "", fmt.Errorf("SRV record data %q: expected \"<priority> <weight> <port> <target>\"", data)
	}
	nums := make([]uint32, 3)
	for i := 0; i < 3; i++ {
		v, err := strconv.ParseUint(fields[i], 10, 32)
		if err != nil {
			return 0, 0, 0, "", fmt.Errorf("SRV record data %q: invalid value %q: %w", data, fields[i], err)
		}
		nums[i] = uint32(v)
	}
	return nums[0], nums[1], nums[2], fields[3], nil
}

func formatSRVData(priority, weight, port uint32, target string) string {
	return fmt.Sprintf("%d %d %d %s", priority, weight, port, target)
}

var srvKind = recordKind[ibclient.RecordSRV]{
	typeName: "SRV",
	list: func(conn *ibclient.Connector, view, legitzone string) ([]ibclient.RecordSRV, error) {
		return listRecordsByZone[ibclient.RecordSRV](conn, ibclient.NewEmptyRecordSRV(), view, legitzone)
	},
	find: func(conn *ibclient.Connector, view, fqdn string) (*ibclient.RecordSRV, bool, error) {
		return findRecordByName[ibclient.RecordSRV](conn, ibclient.NewEmptyRecordSRV(), view, fqdn)
	},
	create: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, fqdn string, rr libdns.RR) (*ibclient.RecordSRV, error) {
		priority, weight, port, target, err := parseSRVData(rr.Data)
		if err != nil {
			return nil, err
		}
		return objMgr.CreateSRVRecord(view, fqdn, priority, weight, port, target, uint32(rr.TTL.Seconds()), true, "", nil)
	},
	update: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, existing *ibclient.RecordSRV, fqdn string, rr libdns.RR) (*ibclient.RecordSRV, error) {
		priority, weight, port, target, err := parseSRVData(rr.Data)
		if err != nil {
			return nil, err
		}
		return objMgr.UpdateSRVRecord(existing.Ref, fqdn, priority, weight, port, target, uint32(rr.TTL.Seconds()), true, strVal(existing.Comment), existing.Ea)
	},
	deleteRecord: func(conn *ibclient.Connector, existing *ibclient.RecordSRV) error {
		_, err := conn.DeleteObject(existing.Ref)
		return err
	},
	toRR: func(rec *ibclient.RecordSRV, legitzone string) libdns.RR {
		return libdns.RR{
			Type: "SRV",
			Name: relativeName(strVal(rec.Name), legitzone),
			Data: formatSRVData(uint32Val(rec.Priority), uint32Val(rec.Weight), uint32Val(rec.Port), strVal(rec.Target)),
			TTL:  ttlDuration(rec.Ttl),
		}
	},
}
