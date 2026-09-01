package infoblox

import (
	"context"
	"errors"
	"fmt"
	"strings"

	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
	"github.com/libdns/libdns"
)

// ListZones returns the authoritative DNS zones visible to the configured
// credentials in the configured view. It is not on the ACME DNS-01 path (Caddy
// already knows the zone for a certificate); it is provided so operators and
// tests can confirm connectivity, permissions and view selection, and because
// it is the one remaining core libdns interface.
//
// Both forward- and reverse-mapping zones are returned. Results are not
// paginated: on a grid with more authoritative zones than its configured
// "Maximum results" limit, the list may be truncated by NIOS. This matters only
// for very large grids and never for challenge solving.
func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	conn, err := p.getConnector()
	if err != nil {
		return nil, fmt.Errorf("failed to get connector: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	view := p.view()
	var zones []ibclient.ZoneAuth
	err = doWithRetry(ctx, func() error {
		zones = nil
		qp := ibclient.NewQueryParams(false, map[string]string{"view": view})
		e := conn.GetObject(ibclient.NewZoneAuth(ibclient.ZoneAuth{}), "", qp, &zones)
		var notFound *ibclient.NotFoundError
		if errors.As(e, &notFound) {
			return nil // no zones in this view
		}
		return e
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list zones: %w", err)
	}

	out := make([]libdns.Zone, 0, len(zones))
	for i := range zones {
		fqdn := strings.TrimSuffix(zones[i].Fqdn, ".")
		if fqdn == "" {
			continue
		}
		out = append(out, libdns.Zone{Name: fqdn + "."})
	}
	return out, nil
}
