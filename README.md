# libdns-infoblox

[![CI](https://github.com/Damianko135/libdns-infoblox/actions/workflows/ci.yml/badge.svg)](https://github.com/Damianko135/libdns-infoblox/actions/workflows/ci.yml)

An [Infoblox](https://www.infoblox.com/) NIOS WAPI provider for [libdns](https://github.com/libdns/libdns), letting [Caddy](https://caddyserver.com/) / [certmagic](https://github.com/caddyserver/certmagic) (and other libdns consumers) solve **ACME DNS-01 challenges** against an Infoblox grid.

The provider is scoped to that job: create the challenge `TXT` record, read records back, and remove the challenge record afterwards — reliably, and without disturbing unrelated records. `A`, `AAAA`, `CNAME`, `MX` and `SRV` are handled too, as ordinary record types, but they are not the focus. This is **not** a general-purpose Infoblox SDK: host records, IPAM, DTC/GSLB, DNSSEC administration and zone/delegation management are deliberately out of scope.

The primary consumer is [caddydns-infoblox](https://github.com/Damianko135/caddydns-infoblox), built into Caddy with [`xcaddy`](https://github.com/caddyserver/xcaddy).

## Status

This project is pre-1.0 and has **not yet been exercised against a live Infoblox grid** by its maintainers — behaviour is verified against the pinned [infoblox-go-client](https://github.com/infobloxopen/infoblox-go-client) `v2.12.0` source and covered by unit tests, but not by an end-to-end integration run. Test it against a lab/sandbox grid before trusting it in production. See [Known limitations](#known-limitations) below.

## Install

```sh
go get github.com/damianko135/libdns-infoblox
```

## Supported operations

The four record interfaces (`RecordGetter`, `RecordAppender`, `RecordSetter`, `RecordDeleter`) plus `ZoneLister`.

`ListZones` returns the authoritative zones visible to the credentials in the configured view. It is not used for DNS-01 (Caddy already knows the zone) and exists mainly so operators can confirm connectivity, permissions and view selection.

## Supported record types

| Type  | Notes |
|-------|-------|
| **TXT** | The record type ACME DNS-01 needs; the reason this provider exists. Single-string values (challenge tokens) only — values with embedded spaces are not quoted. |
| CNAME | |
| A     | |
| AAAA  | |
| MX    | `Data` is `"<preference> <exchange>"`, matching [`libdns.MX.RR()`](https://pkg.go.dev/github.com/libdns/libdns#MX) |
| SRV   | `Data` is `"<priority> <weight> <port> <target>"`; the `_service._proto` labels live in `Name`, matching [`libdns.SRV.RR()`](https://pkg.go.dev/github.com/libdns/libdns#SRV) |

Records of any other type are reported as an error rather than silently ignored.

**NS and DNSSEC records are not supported**, by design. Infoblox models `record:ns` as zone-delegation metadata (name-server glue addresses, MS delegation names) rather than a simple name → target pair, and delegation management is outside the scope of a DNS-01 provider. DNSSEC-related records are never returned by `GetRecords` and cannot be set.

Zone-apex records use libdns's `"@"` convention for `Name`.

## Behaviour

- **RRsets.** All operations key on the full `(name, type, value)` tuple, not just the name. When several records share a name (e.g. two `_acme-challenge` `TXT` tokens for a wildcard + base-domain issuance), `SetRecords` reconciles the whole RRset to the input and `DeleteRecords` removes only the value it was given.
- **Idempotency.** `AppendRecords` treats an already-present identical record as successfully added. `DeleteRecords` treats an already-absent record as successfully deleted, and (per libdns) an empty `Value`/`TTL` in an input record is a wildcard. Repeated ACME present/cleanup calls are therefore safe.
- **Retries.** Transient failures (HTTP 429, HTTP 5xx, connection errors) are retried up to 3 times with jittered exponential backoff, bounded by `retryMaxDelay`. Every backoff wait is abandoned as soon as the context is done. `NotFoundError` and HTTP 4xx are never retried. Retries only ever repeat idempotent work: reads, updates and deletes by object reference, and creates that are re-checked for a duplicate afterwards.
- **TTL.** A `libdns` TTL of `0` means "no explicit TTL": the record is created with `use_ttl=false` and inherits the zone default. A non-zero TTL sets `use_ttl=true`. On read, a record with `use_ttl=false` reports TTL `0`.

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

## Version compatibility

| Component | Requirement | Notes |
|-----------|-------------|-------|
| `infoblox-go-client` | `v2.12.0` (pinned) | Only this version has been read/verified. The retry classifier depends on the client's error-string format; a bump should be reviewed, not auto-merged blind. |
| `libdns` | `v1.1.1` | RRset semantics for `SetRecords`/`DeleteRecords` follow this version's interface docs. |
| Infoblox NIOS / WAPI | any WAPI version your grid advertises, set via `Version` | The provider uses only long-established objects (`record:{a,aaaa,cname,txt,mx,srv}`, `zone_auth`), present since early WAPI 1.x/2.x. No capability that requires a recent NIOS release is used, so there is no silent-incompatibility surface — but `Version` must match a version the grid actually supports or every call fails fast. |
| Go | `go.mod` declares `go 1.27.0` | Standard library only; no dependencies added by this provider beyond `libdns` and `infoblox-go-client`. Builds cleanly through `xcaddy`. |

None of the above has been confirmed against a live grid; see [Status](#status).

## Known limitations

- **Not yet integration-tested** against a real Infoblox grid (see [Status](#status)).
- **Context cancellation is partial.** Cancellation/deadline is checked before each method and each record, and aborts the wait between retries, but neither this provider nor `infoblox-go-client` attaches the context to the outgoing `http.Request` — so a single in-flight WAPI call cannot be interrupted mid-request. It is bounded instead by the client's HTTP timeout (20s). With no deadline on the context and the grid entirely unreachable, a call can take up to ~1 minute before giving up; pass a context with a deadline for a tighter bound.
- **No pagination.** `GetRecords` and `ListZones` issue a single unpaged WAPI search. RRset lookups return at most a handful of records, but on a grid configured with a "Maximum results" cap, a full zone listing or zone list larger than that cap may be truncated by NIOS. This does not affect challenge solving.
- **Not transactional.** `SetRecords`/`DeleteRecords` look up records and then act on them in separate WAPI calls, so a concurrent modification to the same name from elsewhere could race. `SetRecords` is not atomic: on a partial failure the zone may be left partway between the old and new state.
- **TXT quoting.** Only single-string TXT values are handled; a value containing spaces is sent as-is rather than quoted per RFC 1035. ACME challenge tokens are unaffected.

## Versioning

This project follows [Semantic Versioning](https://semver.org/). Until `v1.0.0`, breaking changes may ship in minor versions. As a rule of thumb for this repo:

- **Patch** (`0.x.Y`) — dependency bumps (including automated ones from Dependabot) and bug fixes with no API changes.
- **Minor** (`0.X.y`) — new features (e.g. a new supported record type or config option), additive and backwards compatible.
- **Major** (`X.0.0`, once ≥ `1.0.0`) — breaking API changes.

### Dependabot auto-merge

Patch and minor Dependabot PRs (`gomod` and `github-actions` ecosystems) are auto-merged via [`.github/workflows/dependabot-auto-merge.yml`](.github/workflows/dependabot-auto-merge.yml) once CI passes, using a squash merge whose commit message is just the PR title — no changelog dump or bot sign-off lands in history. Major-version bumps are deliberately excluded and are left as ordinary PRs for manual review, since a dependency's major bump can carry breaking changes CI alone might not catch.

**`infoblox-go-client` is excluded from auto-merge at every level.** The retry classifier in [`retry.go`](retry.go) recognises retryable failures by matching the client's HTTP-error *string* (`"WAPI request error: <code>"`), which the client exposes no typed alternative for. Any bump of that dependency needs a human to confirm the format is unchanged.

Note: GitHub's auto-merge only *guarantees* it waits for checks to finish when the target branch has branch protection requiring them; without that, this repo currently relies on `main`'s CI workflow completing normally before GitHub allows the merge to go through. Add a required-status-check branch protection rule on `main` (for the "Build, vet, and test" check) if you want that guarantee enforced rather than assumed.

## License

[MIT](LICENSE)
