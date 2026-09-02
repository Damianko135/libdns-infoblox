# libdns-infoblox

[![CI](https://github.com/Damianko135/libdns-infoblox/actions/workflows/ci.yml/badge.svg)](https://github.com/Damianko135/libdns-infoblox/actions/workflows/ci.yml)

An [Infoblox](https://www.infoblox.com/) NIOS WAPI provider for [libdns](https://github.com/libdns/libdns), letting Go programs (and libdns-based tools such as [Caddy](https://caddyserver.com/) / [certmagic](https://github.com/caddyserver/certmagic)) manage DNS records on an Infoblox grid.

## Status

This project is pre-1.0 and has **not yet been exercised against a live Infoblox grid** by its maintainers — it's verified against the [infoblox-go-client](https://github.com/infobloxopen/infoblox-go-client) source and covered by unit tests, but not by an end-to-end integration run. Test it against a lab/sandbox grid before trusting it in production. See [Known limitations](#known-limitations) below.

## Install

```sh
go get github.com/damianko135/libdns-infoblox
```

## Supported record types

| Type  | Notes |
|-------|-------|
| CNAME | |
| TXT   | |
| A     | |
| AAAA  | |
| MX    | `Data` is `"<preference> <exchange>"`, matching [`libdns.MX.RR()`](https://pkg.go.dev/github.com/libdns/libdns#MX) |
| SRV   | `Data` is `"<priority> <weight> <port> <target>"`; the `_service._proto` labels live in `Name`, matching [`libdns.SRV.RR()`](https://pkg.go.dev/github.com/libdns/libdns#SRV) |

**NS records are not supported.** Infoblox models `record:ns` as zone-delegation metadata (name server addresses, delegation policy) rather than a simple name → target pair, and the client library exposes no create/update/delete operations for it. Records of any other type are reported as an error rather than silently ignored.

Zone-apex records use libdns's `"@"` convention for `Name`.

## Configuration

```go
import infoblox "github.com/damianko135/libdns-infoblox"

p := &infoblox.Provider{
    Host:     "gm.example.com", // Infoblox Grid Master hostname
    Username: "api-user",
    Password: "api-password",
    Version:  "2.12", // WAPI version, e.g. from Grid Manager > Administration > WAPI
}
```

| Field      | Required | Default     | Description |
|------------|----------|-------------|-------------|
| `Host`     | yes      | —           | Grid Master hostname or IP. |
| `Username` | yes      | —           | WAPI username. |
| `Password` | yes      | —           | WAPI password. |
| `Version`  | yes      | —           | WAPI version string (e.g. `"2.12"`). Must match a version your grid supports. |
| `Port`     | no       | `"443"`     | WAPI HTTPS port. |
| `View`     | no       | `"default"` | DNS view to operate in. |
| `Insecure` | no       | `false`     | Skip TLS certificate verification. Leave `false` in production; only set `true` against a trusted lab/test grid with a self-signed certificate. |

A `Provider` establishes its connection to the grid lazily on first use and reuses it (along with its pooled HTTP transport) across calls. Call `Close()` to release it explicitly, e.g. at program shutdown; this is optional and the `Provider` remains usable afterwards.

`Provider.Validate()` reports missing required fields (`Host`, `Username`, `Password`, `Version`) without opening a connection. It runs automatically before the first request; call it yourself if you want to surface configuration errors earlier.

## Usage

```go
package main

import (
    "context"
    "fmt"

    infoblox "github.com/damianko135/libdns-infoblox"
    "github.com/libdns/libdns"
)

func main() {
    p := &infoblox.Provider{
        Host:     "gm.example.com",
        Username: "api-user",
        Password: "api-password",
        Version:  "2.12",
    }
    defer p.Close()

    ctx := context.Background()

    records, err := p.GetRecords(ctx, "example.com.")
    if err != nil {
        panic(err)
    }
    for _, r := range records {
        fmt.Printf("%+v\n", r.RR())
    }

    _, err = p.AppendRecords(ctx, "example.com.", []libdns.Record{
        libdns.TXT{Name: "_acme-challenge", Text: "some-validation-token", TTL: 60 * 1e9},
    })
    if err != nil {
        // Append/Set/Delete process every record even if some fail; a non-nil
        // error here may be wrapping failures for a subset of the batch
        // (via errors.Join) alongside partial success.
        panic(err)
    }
}
```

## Error handling

`AppendRecords`, `SetRecords`, and `DeleteRecords` process every record in the batch even if some fail. Per-record failures are collected and returned together via [`errors.Join`](https://pkg.go.dev/errors#Join) rather than aborting the whole call; use `errors.Is`/`errors.As` or inspect `err.Error()` to see which records failed and why. The returned `[]libdns.Record` always reflects what actually succeeded.

## Known limitations

- **Not yet integration-tested** against a real Infoblox grid (see [Status](#status)).
- **No context cancellation.** All four methods accept a `context.Context`, but neither this provider nor the underlying `infoblox-go-client` attach it to outgoing HTTP requests — a caller's timeout or cancellation currently cannot abort an in-flight WAPI call.
- **No retry/backoff.** A transient network error fails the call; callers that need resilience should retry at their own layer.
- **No pagination handling has been verified** for zones with very large record counts.
- Reads and writes are not transactional: `SetRecords`/`DeleteRecords` look up a record and then act on it in two separate WAPI calls, so concurrent modifications to the same record from elsewhere could race.

## Versioning

This project follows [Semantic Versioning](https://semver.org/). Until `v1.0.0`, breaking changes may ship in minor versions. As a rule of thumb for this repo:

- **Patch** (`0.x.Y`) — dependency bumps (including automated ones from Dependabot) and bug fixes with no API changes.
- **Minor** (`0.X.y`) — new features (e.g. a new supported record type or config option), additive and backwards compatible.
- **Major** (`X.0.0`, once ≥ `1.0.0`) — breaking API changes.

### Dependabot auto-merge

Patch and minor Dependabot PRs (`gomod` and `github-actions` ecosystems) are auto-merged via [`.github/workflows/dependabot-auto-merge.yml`](.github/workflows/dependabot-auto-merge.yml) once CI passes, using a squash merge whose commit message is just the PR title — no changelog dump or bot sign-off lands in history. Major-version bumps are deliberately excluded and are left as ordinary PRs for manual review, since a dependency's major bump can carry breaking changes CI alone might not catch.

Note: GitHub's auto-merge only *guarantees* it waits for checks to finish when the target branch has branch protection requiring them; without that, this repo currently relies on `main`'s CI workflow completing normally before GitHub allows the merge to go through. Add a required-status-check branch protection rule on `main` (for the "Build, vet, and test" check) if you want that guarantee enforced rather than assumed.

## License

[MIT](LICENSE)
