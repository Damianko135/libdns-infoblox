package infoblox

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
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
	// findAll returns every record of this kind at one fully-qualified name,
	// i.e. the whole RRset. It is used instead of the client library's
	// GetXRecord helpers, which need the record's current value to be known
	// already — unworkable for a name-based upsert — and which only ever
	// return the first match.
	findAll func(conn *ibclient.Connector, view, fqdn string) ([]T, error)
	// create makes a new record from a libdns.RR.
	create func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, fqdn string, rr libdns.RR) (*T, error)
	// update applies a libdns.RR's value and TTL onto an existing record,
	// preserving that record's comment and extensible attributes.
	update func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, existing *T, fqdn string, rr libdns.RR) (*T, error)
	// deleteRecord removes an existing record.
	deleteRecord func(conn *ibclient.Connector, existing *T) error
	// toRecord converts a fetched record into the concrete libdns record type
	// (e.g. libdns.CNAME, libdns.Address) relative to the zone. libdns docs
	// ask providers to return these typed structs rather than a bare
	// libdns.RR, so callers can type-switch on the result reliably.
	toRecord func(rec *T, legitzone string) (libdns.Record, error)

	// canonicalValue renders an existing record's rdata as a canonical string,
	// and canonicalRRValue renders the same string from a libdns input RR
	// (erroring if the RR's Data is malformed). Two records are the same member
	// of an RRset exactly when these strings are equal; this is what makes
	// Set/Delete operate on the right record when several share a name.
	canonicalValue   func(rec *T) string
	canonicalRRValue func(rr libdns.RR) (string, error)

	// ttl returns the record's effective TTL: 0 when it inherits the zone
	// default (Infoblox use_ttl is false/unset), otherwise the stored value.
	ttl func(rec *T) time.Duration
}

// --- generic plumbing --------------------------------------------------

// ibObjectPtr constrains PT to be a pointer to T that also implements ibclient.IBObject,
// which is how every generated Infoblox record type satisfies the connector's generic
// Create/Get/Update/Delete methods.
type ibObjectPtr[T any] interface {
	*T
	ibclient.IBObject
}

// searchRecords runs a WAPI search and returns the matches.
//
// The infoblox-go-client connector reports an empty result set as
// *ibclient.NotFoundError rather than an empty slice (see connector.go
// GetObject: `if string(resp) == "[]" { return NewNotFoundError(...) }`). Every
// caller here wants "no matches" to mean an empty slice and no error — a zone
// legitimately has no records of some type, and an upsert's lookup legitimately
// finds nothing — so that translation happens in one place, here.
func searchRecords[T any, PT ibObjectPtr[T]](conn *ibclient.Connector, empty PT, fields map[string]string) ([]T, error) {
	var results []T
	qp := ibclient.NewQueryParams(false, fields)
	if err := conn.GetObject(empty, "", qp, &results); err != nil {
		var notFound *ibclient.NotFoundError
		if errors.As(err, &notFound) {
			return nil, nil
		}
		return nil, err
	}
	return results, nil
}

func listByZone[T any, PT ibObjectPtr[T]](conn *ibclient.Connector, empty PT, view, legitzone string) ([]T, error) {
	return searchRecords[T](conn, empty, map[string]string{"zone": legitzone, "view": view})
}

func findByName[T any, PT ibObjectPtr[T]](conn *ibclient.Connector, empty PT, view, fqdn string) ([]T, error) {
	return searchRecords[T](conn, empty, map[string]string{"view": view, "name": fqdn})
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

// effTTL is ttlDuration but honours Infoblox's use_ttl flag: a record with
// use_ttl unset or false inherits the zone default, which libdns represents as
// TTL 0.
func effTTL(ttl *uint32, useTtl *bool) time.Duration {
	if useTtl == nil || !*useTtl {
		return 0
	}
	return ttlDuration(ttl)
}

// ttlArgs maps a libdns TTL onto Infoblox's (ttl, use_ttl) pair. A zero or
// negative duration means "no explicit TTL": use_ttl is false and the record
// inherits the zone default. libdns explicitly permits a provider to treat
// TTL 0 this way (see libdns.RR.TTL docs).
func ttlArgs(d time.Duration) (ttl uint32, useTtl bool) {
	if d <= 0 {
		return 0, false
	}
	return uint32(d / time.Second), true
}

// canonFQDN normalises a hostname for comparison: no trailing dot, lower-case.
func canonFQDN(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// canonIP normalises an IP literal for comparison, leaving it untouched if it
// does not parse.
func canonIP(s string) string {
	if addr, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
		return addr.String()
	}
	return strings.TrimSpace(s)
}

func ipRRValue(data string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(data))
	if err != nil {
		return "", fmt.Errorf("invalid IP address %q: %w", data, err)
	}
	return addr.String(), nil
}

// --- verb drivers ----------------------------------------------------------

// listRecordsOfKind implements GetRecords for one kind.
func listRecordsOfKind[T any](ctx context.Context, conn *ibclient.Connector, view, legitzone string, k recordKind[T]) ([]libdns.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var recs []T
	err := doWithRetry(ctx, func() error {
		var e error
		recs, e = k.list(conn, view, legitzone)
		return e
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get %s records: %w", k.typeName, err)
	}

	var list []libdns.Record
	var errs []error
	for i := range recs {
		rec, err := k.toRecord(&recs[i], legitzone)
		if err != nil {
			errs = append(errs, fmt.Errorf("parsing %s record: %w", k.typeName, err))
			continue
		}
		list = append(list, rec)
	}
	return list, errors.Join(errs...)
}

// findExisting fetches the current RRset for one name, with retry.
func findExisting[T any](ctx context.Context, conn *ibclient.Connector, view, fqdn string, k recordKind[T]) ([]T, error) {
	var recs []T
	err := doWithRetry(ctx, func() error {
		var e error
		recs, e = k.findAll(conn, view, fqdn)
		return e
	})
	return recs, err
}

// firstWithValue returns the first record in recs whose rdata matches want, or nil.
func firstWithValue[T any](recs []T, want string, k recordKind[T]) *T {
	for i := range recs {
		if k.canonicalValue(&recs[i]) == want {
			return &recs[i]
		}
	}
	return nil
}

// deleteOne removes a single record, treating an already-gone record as success
// so that Delete (and Set's stale-value cleanup) is idempotent.
func deleteOne[T any](ctx context.Context, conn *ibclient.Connector, rec *T, k recordKind[T]) error {
	return doWithRetry(ctx, func() error {
		err := k.deleteRecord(conn, rec)
		var notFound *ibclient.NotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return err
	})
}

// appendRecordsOfKind implements AppendRecords for one kind.
//
// AppendRecords is "create, never modify existing". If an identical record is
// already present the zone is already in the desired state, so the append is
// reported as satisfied instead of failing on the duplicate that Infoblox would
// reject — which also makes a retried ACME "present" call idempotent.
func appendRecordsOfKind[T any](ctx context.Context, conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, legitzone string, rrs []libdns.RR, k recordKind[T]) ([]libdns.Record, []error) {
	var added []libdns.Record
	var errs []error

	for _, rr := range rrs {
		if err := ctx.Err(); err != nil {
			return added, append(errs, err)
		}
		fqdn := absoluteName(rr.Name, legitzone)

		want, err := k.canonicalRRValue(rr)
		if err != nil {
			errs = append(errs, fmt.Errorf("append %s %q: %w", k.typeName, fqdn, err))
			continue
		}

		existing, err := findExisting(ctx, conn, view, fqdn, k)
		if err != nil {
			errs = append(errs, fmt.Errorf("append %s %q: %w", k.typeName, fqdn, err))
			continue
		}
		if match := firstWithValue(existing, want, k); match != nil {
			rec, convErr := k.toRecord(match, legitzone)
			if convErr != nil {
				errs = append(errs, fmt.Errorf("append %s %q: identical record exists but could not be parsed: %w", k.typeName, fqdn, convErr))
				continue
			}
			added = append(added, rec)
			continue
		}

		var created *T
		err = doWithRetry(ctx, func() error {
			var e error
			created, e = k.create(conn, objMgr, view, fqdn, rr)
			return e
		})
		if err != nil {
			// A retried create can lose its response after the grid already
			// committed the record; re-check before reporting a failure.
			if again, reErr := findExisting(ctx, conn, view, fqdn, k); reErr == nil {
				if match := firstWithValue(again, want, k); match != nil {
					if rec, convErr := k.toRecord(match, legitzone); convErr == nil {
						added = append(added, rec)
						continue
					}
				}
			}
			errs = append(errs, fmt.Errorf("append %s %q: %w", k.typeName, fqdn, err))
			continue
		}

		rec, err := k.toRecord(created, legitzone)
		if err != nil {
			errs = append(errs, fmt.Errorf("append %s %q: record was created but could not be parsed back: %w", k.typeName, fqdn, err))
			continue
		}
		added = append(added, rec)
	}

	return added, errs
}

// rrUpdate pairs an existing record with the input RR that should overwrite it.
type rrUpdate[T any] struct {
	existing *T
	rr       libdns.RR
}

// rrPlan is the set of changes that reconciles one RRset to the desired input.
type rrPlan[T any] struct {
	keep   []*T // desired and already correct — re-reported unchanged
	create []libdns.RR
	update []rrUpdate[T]
	delete []*T // present but not desired
}

// planRRSet computes, without touching the network, the changes needed so that
// the desired records are exactly the members of their (name, type) RRset — the
// contract of libdns.RecordSetter.SetRecords. Later duplicates in desired win.
func planRRSet[T any](existing []T, desired []libdns.RR, k recordKind[T]) (rrPlan[T], error) {
	var plan rrPlan[T]

	byVal := make(map[string]*T, len(existing))
	for i := range existing {
		byVal[k.canonicalValue(&existing[i])] = &existing[i]
	}

	wanted := make(map[string]bool, len(desired))
	for _, rr := range desired {
		cv, err := k.canonicalRRValue(rr)
		if err != nil {
			return rrPlan[T]{}, err
		}
		if wanted[cv] {
			continue
		}
		wanted[cv] = true

		if ex, ok := byVal[cv]; ok {
			wantTTL, _ := ttlArgs(rr.TTL)
			if uint32(k.ttl(ex)/time.Second) == wantTTL {
				plan.keep = append(plan.keep, ex)
			} else {
				plan.update = append(plan.update, rrUpdate[T]{existing: ex, rr: rr})
			}
			continue
		}
		plan.create = append(plan.create, rr)
	}

	for i := range existing {
		if !wanted[k.canonicalValue(&existing[i])] {
			plan.delete = append(plan.delete, &existing[i])
		}
	}
	return plan, nil
}

// setRecordsOfKind implements SetRecords for one kind.
func setRecordsOfKind[T any](ctx context.Context, conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, legitzone string, rrs []libdns.RR, k recordKind[T]) ([]libdns.Record, []error) {
	var out []libdns.Record
	var errs []error

	for _, name := range orderedNames(rrs) {
		if err := ctx.Err(); err != nil {
			return out, append(errs, err)
		}
		fqdn := absoluteName(name, legitzone)
		group := rrsForName(rrs, name)

		existing, err := findExisting(ctx, conn, view, fqdn, k)
		if err != nil {
			errs = append(errs, fmt.Errorf("set %s %q: %w", k.typeName, fqdn, err))
			continue
		}

		plan, err := planRRSet(existing, group, k)
		if err != nil {
			errs = append(errs, fmt.Errorf("set %s %q: %w", k.typeName, fqdn, err))
			continue
		}

		emit := func(rec *T) {
			r, convErr := k.toRecord(rec, legitzone)
			if convErr != nil {
				errs = append(errs, fmt.Errorf("set %s %q: record was saved but could not be parsed back: %w", k.typeName, fqdn, convErr))
				return
			}
			out = append(out, r)
		}

		for _, ex := range plan.keep {
			emit(ex)
		}

		// Add the new members before removing the old ones, so a value that is
		// being kept or replaced is never briefly absent from the zone.
		for _, rr := range plan.create {
			var rec *T
			if e := doWithRetry(ctx, func() error {
				var er error
				rec, er = k.create(conn, objMgr, view, fqdn, rr)
				return er
			}); e != nil {
				errs = append(errs, fmt.Errorf("set %s %q: %w", k.typeName, fqdn, e))
				continue
			}
			emit(rec)
		}
		for _, u := range plan.update {
			var rec *T
			if e := doWithRetry(ctx, func() error {
				var er error
				rec, er = k.update(conn, objMgr, u.existing, fqdn, u.rr)
				return er
			}); e != nil {
				errs = append(errs, fmt.Errorf("set %s %q: %w", k.typeName, fqdn, e))
				continue
			}
			emit(rec)
		}
		for _, ex := range plan.delete {
			if e := deleteOne(ctx, conn, ex, k); e != nil {
				errs = append(errs, fmt.Errorf("set %s %q: removing stale value: %w", k.typeName, fqdn, e))
			}
		}
	}

	return out, errs
}

// matchesDelete reports whether rec should be removed for input rr, following
// libdns.RecordDeleter semantics: an empty Data is a value wildcard, a zero TTL
// is a TTL wildcard, and anything specified must match exactly.
func matchesDelete[T any](rec *T, rr libdns.RR, k recordKind[T]) (bool, error) {
	if rr.Data != "" {
		want, err := k.canonicalRRValue(rr)
		if err != nil {
			return false, err
		}
		if k.canonicalValue(rec) != want {
			return false, nil
		}
	}
	if rr.TTL != 0 && uint32(k.ttl(rec)/time.Second) != uint32(rr.TTL/time.Second) {
		return false, nil
	}
	return true, nil
}

// deleteRecordsOfKind implements DeleteRecords for one kind. Records that do not
// exist, or that no input matches, are silently ignored.
func deleteRecordsOfKind[T any](ctx context.Context, conn *ibclient.Connector, view, legitzone string, rrs []libdns.RR, k recordKind[T]) ([]libdns.Record, []error) {
	var deleted []libdns.Record
	var errs []error

	for _, name := range orderedNames(rrs) {
		if err := ctx.Err(); err != nil {
			return deleted, append(errs, err)
		}
		fqdn := absoluteName(name, legitzone)

		existing, err := findExisting(ctx, conn, view, fqdn, k)
		if err != nil {
			errs = append(errs, fmt.Errorf("delete %s %q: %w", k.typeName, fqdn, err))
			continue
		}
		consumed := make([]bool, len(existing))

		for _, rr := range rrsForName(rrs, name) {
			for i := range existing {
				if consumed[i] {
					continue
				}
				match, matchErr := matchesDelete(&existing[i], rr, k)
				if matchErr != nil {
					errs = append(errs, fmt.Errorf("delete %s %q: %w", k.typeName, fqdn, matchErr))
					break
				}
				if !match {
					continue
				}
				consumed[i] = true
				if e := deleteOne(ctx, conn, &existing[i], k); e != nil {
					errs = append(errs, fmt.Errorf("delete %s %q: %w", k.typeName, fqdn, e))
					continue
				}
				rec, convErr := k.toRecord(&existing[i], legitzone)
				if convErr != nil {
					errs = append(errs, fmt.Errorf("delete %s %q: record was deleted but could not be parsed back: %w", k.typeName, fqdn, convErr))
					continue
				}
				deleted = append(deleted, rec)
			}
		}
	}

	return deleted, errs
}

// orderedNames returns the distinct RR.Name values in first-seen order.
func orderedNames(rrs []libdns.RR) []string {
	seen := make(map[string]bool, len(rrs))
	var names []string
	for _, rr := range rrs {
		if !seen[rr.Name] {
			seen[rr.Name] = true
			names = append(names, rr.Name)
		}
	}
	return names
}

func rrsForName(rrs []libdns.RR, name string) []libdns.RR {
	var out []libdns.RR
	for _, rr := range rrs {
		if rr.Name == name {
			out = append(out, rr)
		}
	}
	return out
}

// --- CNAME -------------------------------------------------------------

var cnameKind = recordKind[ibclient.RecordCNAME]{
	typeName: "CNAME",
	list: func(conn *ibclient.Connector, view, legitzone string) ([]ibclient.RecordCNAME, error) {
		return listByZone[ibclient.RecordCNAME](conn, ibclient.NewEmptyRecordCNAME(), view, legitzone)
	},
	findAll: func(conn *ibclient.Connector, view, fqdn string) ([]ibclient.RecordCNAME, error) {
		return findByName[ibclient.RecordCNAME](conn, ibclient.NewEmptyRecordCNAME(), view, fqdn)
	},
	create: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, fqdn string, rr libdns.RR) (*ibclient.RecordCNAME, error) {
		ttl, useTtl := ttlArgs(rr.TTL)
		return objMgr.CreateCNAMERecord(view, rr.Data, fqdn, useTtl, ttl, "", nil)
	},
	update: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, existing *ibclient.RecordCNAME, fqdn string, rr libdns.RR) (*ibclient.RecordCNAME, error) {
		ttl, useTtl := ttlArgs(rr.TTL)
		return objMgr.UpdateCNAMERecord(existing.Ref, rr.Data, fqdn, useTtl, ttl, strVal(existing.Comment), existing.Ea)
	},
	deleteRecord: func(conn *ibclient.Connector, existing *ibclient.RecordCNAME) error {
		_, err := conn.DeleteObject(existing.Ref)
		return err
	},
	toRecord: func(rec *ibclient.RecordCNAME, legitzone string) (libdns.Record, error) {
		return libdns.CNAME{
			Name:   relativeName(strVal(rec.Name), legitzone),
			TTL:    effTTL(rec.Ttl, rec.UseTtl),
			Target: strVal(rec.Canonical),
		}, nil
	},
	canonicalValue:   func(rec *ibclient.RecordCNAME) string { return canonFQDN(strVal(rec.Canonical)) },
	canonicalRRValue: func(rr libdns.RR) (string, error) { return canonFQDN(rr.Data), nil },
	ttl:              func(rec *ibclient.RecordCNAME) time.Duration { return effTTL(rec.Ttl, rec.UseTtl) },
}

// --- TXT -----------------------------------------------------------------

var txtKind = recordKind[ibclient.RecordTXT]{
	typeName: "TXT",
	list: func(conn *ibclient.Connector, view, legitzone string) ([]ibclient.RecordTXT, error) {
		return listByZone[ibclient.RecordTXT](conn, ibclient.NewEmptyRecordTXT(), view, legitzone)
	},
	findAll: func(conn *ibclient.Connector, view, fqdn string) ([]ibclient.RecordTXT, error) {
		return findByName[ibclient.RecordTXT](conn, ibclient.NewEmptyRecordTXT(), view, fqdn)
	},
	create: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, fqdn string, rr libdns.RR) (*ibclient.RecordTXT, error) {
		ttl, useTtl := ttlArgs(rr.TTL)
		return objMgr.CreateTXTRecord(view, fqdn, rr.Data, ttl, useTtl, "", nil)
	},
	update: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, existing *ibclient.RecordTXT, fqdn string, rr libdns.RR) (*ibclient.RecordTXT, error) {
		ttl, useTtl := ttlArgs(rr.TTL)
		return objMgr.UpdateTXTRecord(existing.Ref, fqdn, rr.Data, ttl, useTtl, strVal(existing.Comment), existing.Ea)
	},
	deleteRecord: func(conn *ibclient.Connector, existing *ibclient.RecordTXT) error {
		_, err := conn.DeleteObject(existing.Ref)
		return err
	},
	toRecord: func(rec *ibclient.RecordTXT, legitzone string) (libdns.Record, error) {
		return libdns.TXT{
			Name: relativeName(strVal(rec.Name), legitzone),
			TTL:  effTTL(rec.Ttl, rec.UseTtl),
			Text: strVal(rec.Text),
		}, nil
	},
	canonicalValue:   func(rec *ibclient.RecordTXT) string { return strVal(rec.Text) },
	canonicalRRValue: func(rr libdns.RR) (string, error) { return rr.Data, nil },
	ttl:              func(rec *ibclient.RecordTXT) time.Duration { return effTTL(rec.Ttl, rec.UseTtl) },
}

// --- A / AAAA ------------------------------------------------------------

// toAddress builds the shared libdns.Address type used for both A and AAAA records.
func toAddress(name, ip string, ttl time.Duration) (libdns.Record, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address %q: %w", ip, err)
	}
	return libdns.Address{
		Name: name,
		TTL:  ttl,
		IP:   addr,
	}, nil
}

var aKind = recordKind[ibclient.RecordA]{
	typeName: "A",
	list: func(conn *ibclient.Connector, view, legitzone string) ([]ibclient.RecordA, error) {
		return listByZone[ibclient.RecordA](conn, ibclient.NewEmptyRecordA(), view, legitzone)
	},
	findAll: func(conn *ibclient.Connector, view, fqdn string) ([]ibclient.RecordA, error) {
		return findByName[ibclient.RecordA](conn, ibclient.NewEmptyRecordA(), view, fqdn)
	},
	create: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, fqdn string, rr libdns.RR) (*ibclient.RecordA, error) {
		ttl, useTtl := ttlArgs(rr.TTL)
		return objMgr.CreateARecord("", view, fqdn, "", rr.Data, ttl, useTtl, "", nil)
	},
	update: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, existing *ibclient.RecordA, fqdn string, rr libdns.RR) (*ibclient.RecordA, error) {
		ttl, useTtl := ttlArgs(rr.TTL)
		return objMgr.UpdateARecord(existing.Ref, fqdn, rr.Data, "", "", ttl, useTtl, strVal(existing.Comment), existing.Ea)
	},
	deleteRecord: func(conn *ibclient.Connector, existing *ibclient.RecordA) error {
		_, err := conn.DeleteObject(existing.Ref)
		return err
	},
	toRecord: func(rec *ibclient.RecordA, legitzone string) (libdns.Record, error) {
		return toAddress(relativeName(strVal(rec.Name), legitzone), strVal(rec.Ipv4Addr), effTTL(rec.Ttl, rec.UseTtl))
	},
	canonicalValue:   func(rec *ibclient.RecordA) string { return canonIP(strVal(rec.Ipv4Addr)) },
	canonicalRRValue: func(rr libdns.RR) (string, error) { return ipRRValue(rr.Data) },
	ttl:              func(rec *ibclient.RecordA) time.Duration { return effTTL(rec.Ttl, rec.UseTtl) },
}

var aaaaKind = recordKind[ibclient.RecordAAAA]{
	typeName: "AAAA",
	list: func(conn *ibclient.Connector, view, legitzone string) ([]ibclient.RecordAAAA, error) {
		return listByZone[ibclient.RecordAAAA](conn, ibclient.NewEmptyRecordAAAA(), view, legitzone)
	},
	findAll: func(conn *ibclient.Connector, view, fqdn string) ([]ibclient.RecordAAAA, error) {
		return findByName[ibclient.RecordAAAA](conn, ibclient.NewEmptyRecordAAAA(), view, fqdn)
	},
	create: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, fqdn string, rr libdns.RR) (*ibclient.RecordAAAA, error) {
		ttl, useTtl := ttlArgs(rr.TTL)
		return objMgr.CreateAAAARecord("", view, fqdn, "", rr.Data, useTtl, ttl, "", nil)
	},
	update: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, existing *ibclient.RecordAAAA, fqdn string, rr libdns.RR) (*ibclient.RecordAAAA, error) {
		ttl, useTtl := ttlArgs(rr.TTL)
		return objMgr.UpdateAAAARecord(existing.Ref, "", fqdn, rr.Data, "", useTtl, ttl, strVal(existing.Comment), existing.Ea)
	},
	deleteRecord: func(conn *ibclient.Connector, existing *ibclient.RecordAAAA) error {
		_, err := conn.DeleteObject(existing.Ref)
		return err
	},
	toRecord: func(rec *ibclient.RecordAAAA, legitzone string) (libdns.Record, error) {
		return toAddress(relativeName(strVal(rec.Name), legitzone), strVal(rec.Ipv6Addr), effTTL(rec.Ttl, rec.UseTtl))
	},
	canonicalValue:   func(rec *ibclient.RecordAAAA) string { return canonIP(strVal(rec.Ipv6Addr)) },
	canonicalRRValue: func(rr libdns.RR) (string, error) { return ipRRValue(rr.Data) },
	ttl:              func(rec *ibclient.RecordAAAA) time.Duration { return effTTL(rec.Ttl, rec.UseTtl) },
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

// The infoblox-go-client ObjectManager's MX helpers require the record's current
// value up front, so MX records are built and sent through the connector directly.

func getMXByRef(conn *ibclient.Connector, ref string) (*ibclient.RecordMX, error) {
	return fetchByRef[ibclient.RecordMX](conn, ibclient.NewEmptyRecordMX(), ref)
}

var mxKind = recordKind[ibclient.RecordMX]{
	typeName: "MX",
	list: func(conn *ibclient.Connector, view, legitzone string) ([]ibclient.RecordMX, error) {
		return listByZone[ibclient.RecordMX](conn, ibclient.NewEmptyRecordMX(), view, legitzone)
	},
	findAll: func(conn *ibclient.Connector, view, fqdn string) ([]ibclient.RecordMX, error) {
		return findByName[ibclient.RecordMX](conn, ibclient.NewEmptyRecordMX(), view, fqdn)
	},
	create: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, fqdn string, rr libdns.RR) (*ibclient.RecordMX, error) {
		preference, exchanger, err := parseMXData(rr.Data)
		if err != nil {
			return nil, err
		}
		ttl, useTtl := ttlArgs(rr.TTL)
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
		ttl, useTtl := ttlArgs(rr.TTL)
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
	toRecord: func(rec *ibclient.RecordMX, legitzone string) (libdns.Record, error) {
		return libdns.MX{
			Name:       relativeName(strVal(rec.Name), legitzone),
			TTL:        effTTL(rec.Ttl, rec.UseTtl),
			Preference: uint16(uint32Val(rec.Preference)),
			Target:     strVal(rec.MailExchanger),
		}, nil
	},
	canonicalValue: func(rec *ibclient.RecordMX) string {
		return formatMXData(uint32Val(rec.Preference), canonFQDN(strVal(rec.MailExchanger)))
	},
	canonicalRRValue: func(rr libdns.RR) (string, error) {
		pref, exch, err := parseMXData(rr.Data)
		if err != nil {
			return "", err
		}
		return formatMXData(pref, canonFQDN(exch)), nil
	},
	ttl: func(rec *ibclient.RecordMX) time.Duration { return effTTL(rec.Ttl, rec.UseTtl) },
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
		return listByZone[ibclient.RecordSRV](conn, ibclient.NewEmptyRecordSRV(), view, legitzone)
	},
	findAll: func(conn *ibclient.Connector, view, fqdn string) ([]ibclient.RecordSRV, error) {
		return findByName[ibclient.RecordSRV](conn, ibclient.NewEmptyRecordSRV(), view, fqdn)
	},
	create: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, view, fqdn string, rr libdns.RR) (*ibclient.RecordSRV, error) {
		priority, weight, port, target, err := parseSRVData(rr.Data)
		if err != nil {
			return nil, err
		}
		ttl, useTtl := ttlArgs(rr.TTL)
		return objMgr.CreateSRVRecord(view, fqdn, priority, weight, port, target, ttl, useTtl, "", nil)
	},
	update: func(conn *ibclient.Connector, objMgr ibclient.IBObjectManager, existing *ibclient.RecordSRV, fqdn string, rr libdns.RR) (*ibclient.RecordSRV, error) {
		priority, weight, port, target, err := parseSRVData(rr.Data)
		if err != nil {
			return nil, err
		}
		ttl, useTtl := ttlArgs(rr.TTL)
		return objMgr.UpdateSRVRecord(existing.Ref, fqdn, priority, weight, port, target, ttl, useTtl, strVal(existing.Comment), existing.Ea)
	},
	deleteRecord: func(conn *ibclient.Connector, existing *ibclient.RecordSRV) error {
		_, err := conn.DeleteObject(existing.Ref)
		return err
	},
	// toRecord round-trips through libdns.RR.Parse() rather than building a
	// libdns.SRV by hand: splitting the "_service._proto" labels back out of
	// the record name has edge cases (e.g. no host part, root "@" name) that
	// libdns's own parser already implements and tests.
	toRecord: func(rec *ibclient.RecordSRV, legitzone string) (libdns.Record, error) {
		rr := libdns.RR{
			Type: "SRV",
			Name: relativeName(strVal(rec.Name), legitzone),
			TTL:  effTTL(rec.Ttl, rec.UseTtl),
			Data: formatSRVData(uint32Val(rec.Priority), uint32Val(rec.Weight), uint32Val(rec.Port), strVal(rec.Target)),
		}
		parsed, err := rr.Parse()
		if err != nil {
			return nil, fmt.Errorf("parsing SRV name %q: %w", rr.Name, err)
		}
		return parsed, nil
	},
	canonicalValue: func(rec *ibclient.RecordSRV) string {
		return formatSRVData(uint32Val(rec.Priority), uint32Val(rec.Weight), uint32Val(rec.Port), canonFQDN(strVal(rec.Target)))
	},
	canonicalRRValue: func(rr libdns.RR) (string, error) {
		priority, weight, port, target, err := parseSRVData(rr.Data)
		if err != nil {
			return "", err
		}
		return formatSRVData(priority, weight, port, canonFQDN(target)), nil
	},
	ttl: func(rec *ibclient.RecordSRV) time.Duration { return effTTL(rec.Ttl, rec.UseTtl) },
}
