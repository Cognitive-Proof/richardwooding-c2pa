# Experimental Live Media release checks

Status: the ten-task implementation and local verification are complete. This is
an experimental supported profile, not a C2PA 2.5 conformance certification or a
published/tagged release. The interoperability offset decision below prevents a
claim of literal compliance with all pinned Live Media text.

The normative/reference inputs are pinned in [the task record](../LIVE_MEDIA_TASKS.md).
See [the supported profile](live-media-profile.md) for API behavior and limits,
[executable public examples](../live_example_test.go) for validation and rotation,
and [the Rust harness](../validation/live-media-interop/README.md) for independent
verification. Examples run with `go test -run '^ExampleLiveMedia' .` and use no
network services or production credentials.

## Capability and evidence matrix

| Capability | Go evidence | Independent pinned Rust evidence |
| --- | --- | --- |
| Trusted init, complete moov binding, native session-key assertion and signerBinding | Init/signature/trust/malformed-input regressions | Both directions, explicit roots |
| Ed25519 VSI, manifest/key association, complete segment hash and selective emsg exclusion | COSE/carriage/hash/tampering tests and fuzzing | Both directions, three livesim2 segments |
| Sequence, explicit origin, key windows, signed/unsigned composition offsets | Arithmetic, reorder, boundary, expiry and cancellation tests | Shared broad window; Rust's tfdt timing differs |
| Session-key rotation and embedded announcements | Overlap, same-ID separation, backdating/replay, binding policy and rollback tests | Go-to-Rust rotation, Trusted announcement |
| Indexed ordinary media signing | Single-level sidx/index and base repair regressions | Not independently established for every supported layout |
| Remote init/media-bound stores | Local HTTP tests for pins, identity, trust/binding, limits, redirects, timeouts, tampering and rollback | Not verified |
| Long sessions and current credential checks | Monotonic IDs, history bounds, clock/expiry and real OCSP responder regressions | Not verified |
| RFC 3161/CAWG policy on locally authored output | Existing signing/identity tests plus timestamped announcements | Not established by the live interop harness |

Neither a Go roundtrip nor a successful signature primitive alone is described as
independent full-stream interoperability. Rust tests check their failure trackers
as well as return values. Production Rust source is pinned and unchanged; only
the documented test-module registration and retained adapter are installed.

## Local results (2026-10-16)

| Check | Result |
| --- | --- |
| Windows/amd64 Go 1.26.0 minimum toolchain: dependency checksums, build, vet, full tests and executable examples | Pass |
| Windows/amd64 Go 1.27.0: same checks | Pass |
| Go 1.27 full-suite statement coverage | 87.1% overall; live production files 86.2% (1428/1656 statements) |
| Five live fuzz targets, ten seconds each, two workers, dependencies offline | Pass; counts below |
| Fresh Rust-to-Go and Go-to-Rust streams and Go-to-Rust rotation | Pass, Rust/Cargo 1.98.1, native crypto, locked pinned SDK |
| Original captured/signed fixture checksum regressions | Pass; fresh replay wrote separate artifacts |
| Formatting, whitespace and PowerShell syntax | Pass |
| Local race detector | Unavailable: CGO is disabled and no C compiler was found; `go test -race` rejects this configuration |
| Linux matrix/race, golangci-lint and stable c2patool hosted jobs | Existing CI gates remain configured; not executed locally or claimed as passed |

Coverage describes this run, not a release threshold or proof of correctness.
Go 1.26 reported 86.7% overall; toolchain instrumentation differs. The fuzz counts
were 105,241 session-key, 120,924 VSI-envelope, 15,048 VSI-carriage, 19,758 timing
and 88,168 manifest-reference executions. No crash corpus was produced.

The existing CI matrix covers Go 1.26 and stable, including `-race`. The nightly
fuzz workflow now includes all five live targets. Normal Go CI validates retained
Rust fixtures offline; it does not build Rust or require an external simulator.
HTTP/OCSP tests use localhost test servers. Hosted workflows still need to run on
the branch/PR before merge; a local report does not replace those checks.

## Reproduction

With cached dependencies and a locally installed Go toolchain:

```powershell
.\validation\check-live-media.ps1
.\validation\check-live-media.ps1 -Fuzz -FuzzTime 10s
# On a host configured for CGO with a C compiler:
.\validation\check-live-media.ps1 -Race
# Optional fresh experimental Rust replay, preserving reviewed fixtures:
.\validation\check-live-media.ps1 -RustCheckout C:\work\c2pa-rs-interop
```

The script verifies cached dependencies, builds, vets, runs the complete suite and
writes coverage to a separate output directory. Optional `-OutputDirectory`
selects it. It disables dependency downloads and clears/restores interop generation
variables for the ordinary Go gate. A Rust checkout/toolchain and cached Cargo
dependencies are separate prerequisites; the Rust adapter may need Cargo network
access on its first build. Use `-GoCommand` with an installed toolchain's exact
`bin/go` path for offline version-floor checks; do not rely on automatic
`GOTOOLCHAIN` downloads while `GOSUMDB=off`.

On other shells the equivalent core checks are:

```sh
go mod verify
go build ./...
go vet ./...
go test ./... -count=1 -timeout=180s -coverprofile=coverage.out
# Add -race on a correctly configured host.
go test -run='^$' -fuzz='^FuzzLiveSessionKeys$' -fuzztime=10s -parallel=2 .
go test -run='^$' -fuzz='^FuzzLiveVSIEnvelope$' -fuzztime=10s -parallel=2 .
go test -run='^$' -fuzz='^FuzzLiveVSICarriage$' -fuzztime=10s -parallel=2 .
go test -run='^$' -fuzz='^FuzzLiveTiming$' -fuzztime=10s -parallel=2 .
go test -run='^$' -fuzz='^FuzzLiveManifestReference$' -fuzztime=10s -parallel=2 .
```

## Limits and remaining work

- The pinned spec says an emsg scheme predicate has offset 0. This profile and
  pinned Rust use **box-relative offset 12**. Resolving the normative discrepancy
  is required before claiming full conformance.
- One track/traf and one complete moof/mdat pair are supported; no edit lists,
  multi-track/DRM profile, progressive low-latency chunks, MPEG-TS, E-RTMP or
  per-segment full-manifest method is claimed. Existing finite-set Merkle APIs
  retain their separate behavior.
- VSI uses Ed25519 sessions. Ordinary signing repairs supported single-level
  indexes; announcement signing requires unindexed moof-relative addressing.
  Broader algorithms, layouts and remote-store authoring profiles need separate
  work. The reference helper only hosts a sender's current already-authored store.
- Rust maps decode time directly; Go uses sample PTS. Shared broad-window interop
  does not establish narrow timing-boundary agreement. Rust also rejects the
  schema's zero-second key window, which Go permits.
- Default exact event history fails closed at 65,536 events. Optional monotonic
  IDs must not wrap. Manifest history is bounded (64 default, 1024 maximum) with
  no eviction. Explicit reinitialization resets session history; persistent
  restart/resume or distributed publisher coordination is not provided.
- Remote fetches require caller-selected origins/transport policy. Byte/time
  bounds and digest pins do not replace origin/DNS/proxy policy. Revocation is
  off by default; enabled checks retain the established informational unknown
  policy on network/parse/freshness failure. Credential validity uses the
  validation clock, separately from sample presentation time.
- API instances are not concurrent-safe. Successful signing commits before
  publication, so callers retain exact output bytes for publication retries.
- Fresh remote/long-session Rust interoperability, local race/lint execution and
  hosted CI results remain gaps in this local verification report. None is
  presented as already established.
