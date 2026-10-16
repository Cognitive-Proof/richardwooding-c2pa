# Live Media implementation tasks

Work through these tasks in order, with tests and reviewable changes at each step.
Target: complete-segment BMFF/CMAF Verifiable Segment Info (VSI), in pure Go.
Reference spec: c2pa-org/specs-core at `2e6d3b4be833e8f779ddd25c467f20bb08ea366a`.
Reference acceptance tests: contentauth/c2pa-rs commit `8f16c0f78673461ba41c184e71d29a6492be571c`.

- [x] **1. Session-key primitives.** Internal Ed25519 session-key assertion encoding,
  strict native CBOR decoding, detached signer binding, validity/sequence bounds,
  malformed-input tests. No public API or claim of live validation yet.
- [x] **2. Trusted initialization and session state.** Public live API design,
  full init manifest validation and moov binding, assertion multiplicity,
  live status codes, transactional key admission and bounded state.
- [x] **3. VSI and BMFF carriage.** Attached COSE signatures, strict emsg parsing,
  selective exclusions, final-layout hashing, placement and index repair.
  Resolve/document the spec's offset-0 versus box-relative-offset-12 discrepancy.
- [x] **4. Timeline and segment validation.** Explicit presentation-time mapping,
  track selection, timing metadata, sequence checks and failure-safe continuity.
  Missing timeline information cannot produce a successful live verdict.
- [x] **5. Live signing.** Init and complete-segment authoring, fixed layout,
  unchanged media/event payloads, cancellation and output checks.
- [x] **6. livesim2 acceptance suite.** Import attributed/checksummed fixtures and
  port all six tests from the referenced commit. Keep CI offline.
- [x] **7. Independent interoperability.** Rust-signed to Go-validated and
  Go-signed to Rust-validated fixtures against a pinned experimental Rust version.
- [x] **8. Rotation and manifest announcements.** Overlapping key schedules,
  manifest-ID/key-ID associations, authenticated updates and rollback on failure.
- [x] **9. Remote manifest resolution and long sessions.** Opt-in bounded
  resolution, digest/trust/asset-binding checks, cache policy and credential rechecks.
- [x] **10. Documentation and release checks.** Supported profile, examples,
  fuzz/regression coverage, interoperability results and remaining limitations.

Separate later scope: per-segment full manifests, E-RTMP, broader algorithms,
multi-track/DRM profiles and progressive low-latency delivery. Existing finite-set
Merkle APIs retain their behavior.

## Task 1 boundary

These primitives verify association with supplied certificate bytes, not certificate
trust. Task 2 must validate the authorizing manifest and certificate before key
admission. Ed25519 is the initial supported profile; other algorithms return an
explicit unsupported error. Required tags and integer-keyed COSE maps must survive
without JSON conversion. The session private key signs a CBOR byte string
containing the leaf certificate DER; COSE encodes those payload bytes again in
Sig_structure. Task 7 corrected the original raw-DER interpretation after
independent cross-language failures demonstrated the mismatch.

Completed on branch `codex/live-media-session-keys`:

- `live_session_keys.go`: bounded native CBOR codec, Ed25519 signer bindings,
  duplicate-key rejection, explicit unsupported-algorithm errors, and inclusive
  presentation-time/sequence bounds with checked timestamp arithmetic.
- `live_session_keys_test.go`: independent Ed25519 verification of the COSE
  Sig_structure, malformed-input and boundary tests, and a deterministic fuzz seed.
- Validation with Go 1.27.0 on Windows/amd64: baseline and regression `go test ./...`
  passed; `go vet ./...` passed; focused tests and a final 15-second fuzz run passed
  (233,557 executions). Regression tests use local HTTP servers and were run outside
  the network-restricted sandbox. Formatting and whitespace checks passed.

No Rust interoperability run or public live-stream support is claimed by Task 1.
## Task 2 completed

- Added `NewLiveMediaValidator(opts ...ValidateOption)` and a usable zero value.
  `ValidateInitSegment(ctx, reader)` returns the existing `ValidationResult` type;
  `Initialized()` and `ManifestID()` expose the admitted initialization identity.
- Reuses full manifest validation and requires verified signature, certificate trust
  and binding. Requires one standard manifest with a signed flat BMFF v3 assertion
  that covers the entire moov, including its children. The merkle field must be absent.
- Requires a complete ftyp/moov init structure without mdat or media-fragment boxes.
  Scan-capped or malformed structures cannot initialize a session.
- Admits exactly one signed, native-CBOR session-keys assertion after checking its
  signer bindings. Missing, repeated, unreferenced or JSON assertions are rejected.
- Installs all keys atomically. A successful explicit reinitialization begins a new
  session and replaces the previous state. Failures and cancellation preserve it.
  State retains one manifest identity, copied leaf DER and at most 256 keys; result
  certificate buffers do not alias admitted state. Methods are not concurrent-safe.
- Added failure-severity `livevideo.init.invalid`, `livevideo.manifest.invalid`
  and `livevideo.sessionkey.invalid` status codes at their emission sites.
- Tests cover authenticated initialization, trust rejection, assertion multiplicity,
  wrong bindings, malformed/capped input, cancellation, state replacement/rollback,
  required claim references, moov exclusions and merkle presence. A correctly signed
  hash that excludes moov passes general validation but fails live initialization.
- Validation: focused live tests, full `go test ./... -count=1`, `go vet ./...`,
  formatting and whitespace checks passed with Go 1.27.0 on Windows/amd64.

This increment authenticates initialization only. Segment validation, track/timeline
semantics and manifest/key rotation remain in the subsequent tasks.

## Task 3 completed

- `live_vsi.go`: internal tagged, attached Ed25519 COSE signing/verification,
  authorizing manifest/key matching, bounded CBOR payload parsing, selective
  BMFF hash exclusions and a fixed-layout complete-segment builder.
- `live_emsg.go`: exact VSI scheme/value and v0 timing/header parsing, producer
  preamble placement, single-level sidx repair and explicit tfhd base remapping.
  Unsupported index/base layouts fail without changing the source buffer.
- `docs/live-media-profile.md` documents the box-relative offset-12 compatibility
  choice. The spec's offset-0 discrepancy remains open; the generic hash engine
  is unchanged. Exclusion matches that are not actual VSI events are rejected.
- Media and unrelated events, including SCTE-35 v1 events, remain covered by the
  hash. All included box offsets reflect the final layout. The initial authoring
  profile supports one moof/mdat pair and one VSI event; broader layouts remain
  explicit follow-on scope. Optional manifestUri payloads are currently rejected.
- Tests cover independent Ed25519 Sig_structure verification and independent
  SHA-256 hashing of delivered offsets/bytes, malformed authenticated payloads,
  wrong key/manifest IDs, attached-payload requirements, timing metadata,
  SCTE-35/media tampering and removal, URI/value/v1 prefix lookalikes, indexed
  layouts, prft preservation, explicit tfhd offsets, cancellation and rollback.
- Validation: focused live tests, full `go test ./... -count=1`, `go vet ./...`,
  formatting and whitespace checks passed. Two 15-second fuzz runs passed:
  carriage (48,415 executions) and COSE envelopes (210,362 executions).

No public media-segment validation verdict is exposed by these primitives. The
stateful checks (presentation-time mapping, sequence/minimum-sequence checks,
event-ID uniqueness and atomic continuity updates) are Task 4. The public live
signer remains Task 5; independent Rust interoperability remains Task 7.

## Task 4 completed

- Added `SetMediaTimeOrigin` and `ValidateMediaSegment`, with a public
  `LiveMediaSegmentResult` reporting statuses, sequence, presentation time and
  binding outcome. Missing origins cannot produce a successful live verdict.
- Initialization now authenticates one track's tkhd ID, mdhd timescale and optional
  trex duration defaults. Version-0 and version-1 headers are supported. Multiple
  tracks and edit lists are rejected by this profile.
- `live_timing.go` parses mfhd/tfhd/tfdt/trun timing, resolves sample durations
  through trun/tfhd/trex, sums runs and bounds aggregate sample counts. Nonzero
  composition offsets were initially unsupported (extended in Task 6). No fallback to iat/current time
  or automatic prft mapping is used.
- Maps 64-bit media ticks using checked integer seconds/fractions. Avoids floating
  point and time.Duration overflow, including exact key-window rejection when a
  timestamp exceeds an endpoint by less than one nanosecond.
- Requires signature/hash verification, correct track ID, matching emsg timing,
  matching mfhd sequence, increasing accepted sequence, key minimum sequence,
  presentation-start validity and unique event ID. Forward sequence gaps are
  allowed. Embedded manifest updates remain explicitly unsupported until Task 8.
- Sequence/event history is committed only after all checks and the final context
  check. Up to 65,536 event IDs are retained without eviction; exhaustion fails
  closed. Accepted timeline mappings are frozen until explicit reinitialization,
  which begins a new session and clears timing/continuity state.
- Tests cover epoch-based 64-bit timestamps, expiry partway through a sequence,
  missing/wrong/frozen origins, replay/order/minimum-sequence checks, event-ID
  reuse, tampering rollback and valid retries, wrong tracks, composition offsets,
  header versions, default/sample durations, parser limits and cancellation.
- Validation: all focused live tests, full `go test ./... -count=1`, `go vet ./...`,
  formatting and whitespace checks passed. The 15-second timing-parser fuzz run
  passed with 210,992 executions.

The supported timing, sequence and resource-limit decisions are documented in
`docs/live-media-profile.md`, including the public validation call sequence.
Independent Rust interoperability and broader media profiles remain later work.

## Task 5 completed

- Added `NewLiveMediaSigner` and `LiveMediaSignerConfig`. Session keys/IDs may be
  supplied or securely generated; input key buffers are copied. Creation time,
  validity period and minimum sequence are explicit session metadata, including
  support for archived-media creation times.
- Added `SignInitSegment`, `SetMediaTimeOrigin`, `SignMediaSegment`, `Initialized`
  and `ManifestID`. Signing returns complete byte buffers after self-validation;
  output publication is the caller's responsibility. A signer initializes once.
- Init signing uses the existing manifest policy, including configured timestamp,
  identity and hash algorithms, then checks live structure, track/moov binding
  and session-key association. Receiver trust remains receiver-configured.
- Media signing derives mfhd sequences and event timing from the source, assigns
  event IDs and validates the final signed bytes against session state. Failed
  attempts return no output and consume no sequence/event ID. Successful return
  commits the sequence; callers retain returned bytes for publication retries.
- Tests use a separately configured receiver, check SCTE-35/source preservation,
  index/base-offset layouts, metadata generation/copying, invalid configurations,
  failed init/media retries, and sampled cancellation points throughout both
  pipelines. Tests also cover timestamped init, CAWG identity and SHA-384 init
  policy combined with VSI media signing.
- Validation: focused public signing tests, full `go test ./... -count=1`,
  `go vet ./...`, formatting and whitespace checks passed on Go 1.27.0 Windows/amd64.
- Added public signing examples and a README entry pointing to the supported
  profile and its limitations.

## Task 6 completed

- Imported the original livesim2 capture bundle from commit
  `8f16c0f78673461ba41c184e71d29a6492be571c` into `testdata/live_video/livesim2`.
  Includes init, three media segments, MPD, capture metadata/checksums, upstream
  verification/recapture script, original README and source/simulator licenses.
  Also retained the pinned c2pa-rs MIT license for the adapted test scenarios.
- Captured responses are unchanged. Added a local fixture README and a targeted
  .gitattributes rule to preserve exact capture/provenance bytes on Windows.
- `livesim2_test.go` ports the six original scenarios using public Go APIs and an
  explicit test trust pool. Independently pins all five response hashes/sizes,
  checks capture.json/SHA256SUMS, and verifies native session-key/certificate
  association. All acceptance tests run offline.
- Real captured media revealed nonzero composition offsets, which the initial
  timing profile had rejected. Extended parsing to combine tfdt, cumulative sample
  durations and signed/unsigned trun composition offsets. Uses the earliest sample
  PTS and complete presentation span across runs, with underflow/overflow checks.
  Actual capture PTS is tfdt + 6000 ticks, with a 180000-tick presentation span;
  tests explicitly assert this rather than the original Rust test's tfdt-only
  approximation. Added composition/reordering/key-window regression tests.
- The public Go signer rejects an expired third segment itself. The expiry test
  checks that refusal, then builds the same cryptographically valid expired vector
  through the internal builder to prove receiver rejection without advancing state.
- Validation: all six scenarios plus checksum test passed with GOPROXY/GOSUMDB
  disabled in the network-restricted sandbox; upstream capture.py verified all five
  responses offline. Full `go test ./... -count=1`, `go vet ./...`, formatting and
  whitespace checks passed. Timing fuzzing, seeded with the real captured trun,
  passed 112,137 executions in a 15-second run.

These unsigned simulator captures demonstrate Go round trips and rejection
behavior on real DASH media. Independent Rust/Go signature interoperability is
the next task, not a claim established by this acceptance suite.

Next: Task 7, pinned Rust-signed/Go-validated and Go-signed/Rust-validated fixtures.

## Task 7 completed

- Built contentauth/c2pa-rs at the exact pinned commit with its Cargo.lock,
  Rust/Cargo 1.98.1 and native crypto. Production Rust code is unchanged; only a
  test-module registration and the retained adapter are installed.
- Verified Rust-authored init plus three media segments with Go and the reciprocal
  Go-authored stream with Rust. Both receivers use explicit test CAs and full
  manifest trust checks, and reject sample-byte tampering. Go rejects an empty
  trust pool; Rust rejects an unrelated CA. Rust checks tracker failures as well
  as return values. The original six Rust livesim2 tests also pass.
- Independent failures exposed the earlier Go signerBinding encoding mistake:
  Rust signs a CBOR-encoded certificate as detached COSE payload, while Go had
  signed raw DER. Corrected both Go authoring and verification, updated the
  independently assembled Sig_structure test, and added raw-DER rejection.
- Rust's ephemeral test certificate generator emits an SKI extension rejected by
  Go x509. The harness supplies valid Go-generated test credentials to Rust;
  Rust still independently authors every C2PA manifest, binding and VSI signature.
  No receiving trust or certificate checks are bypassed.
- Retained both signed streams, test roots, verification clocks, checksums and
  provenance under `testdata/live_video/interop`. Normal Go CI independently
  validates the Rust fixtures offline at their recorded certificate clock.
  `validation/live-media-interop/run.ps1` reproduces both directions with fresh
  credentials; its Rust adapter only accesses private state to model archived
  session creation time.
- Compatibility scope: one-track complete segments, explicit Unix-epoch origin,
  Ed25519 sessions, positive 60-second validity, offset-12 exclusions. The pinned
  Rust uses tfdt decode time; Go includes sample composition offsets. The shared
  window admits both and does not demonstrate narrow-boundary timing agreement.
  Rust rejects zero-second windows; Go permits them. These are documented limits,
  not claims of complete C2PA conformance.
- Validation: complete reproduction script passed both directions and negatives;
  all six pinned Rust acceptance tests passed; full `go test ./... -count=1`
  and `go vet ./...` passed with Go 1.27.0 on Windows/amd64.

Next: Task 8, rotation and authenticated manifest announcements.

## Task 8 completed

- Added `AddSessionKey` with copied/generated credentials, schedule bounds,
  duplicate-ID checks and monotonic admission. Keys scheduled before init are
  included there; running-session additions require a signed announcement.
  Selection uses sequence and actual sample PTS, preferring the eligible key
  with the greatest minimum sequence, then latest addition on ties.
- Added `SignMediaSegmentWithManifest` using the normal manifest signing,
  timestamp and identity pipeline. A selective VSI exclusion breaks the hash
  cycle; the final VSI includes the signed manifest in its segment hash. The
  writer accepts unindexed, moof-relative segments. Indexed/absolute-base
  announcement authoring is explicitly refused, with ordinary VSI unchanged.
- The receiver authenticates a standard manifest, flat binding, exact identifier,
  trust chain and every session-key signerBinding before staging keys. Newly
  disclosed keys cannot predate the announcing sequence. Full VSI, hash, timing,
  expiry and continuity success is required before installing the staged state.
- Retained `(manifestId, kid)` associations allow overlapping older keys and
  prevent same-ID substitution across manifests. Old references do not roll back
  the latest announcement. Retired announcements and changed stores reusing an ID
  are refused. Bound history to 64 manifests, each with at most 256 keys; no
  eviction weakens replay protection. Session origin/event/sequence history is
  preserved until explicit reinitialization.
- Tests cover scheduled overlap, running rotation, same-ID key separation,
  backdated/replayed announcements, unsafe binding exclusions, wrong trust,
  tampered media/VSI, timestamped output, limits and transactional cancellation
  at 24 signing and 24 receiving checkpoints. Failed attempts preserve pending
  schedules and consume no sequence or event IDs.
- Independently validated a Go-authored livesim2 stream rotating on segment two
  with the pinned Rust SDK, explicit trust and a `Trusted` announcement verdict.
  Added an optional reproducible rotation path to the retained harness. Existing
  Task 7 fixture bytes/checksums remain unchanged.
- Validation: full `go test ./... -count=1` and `go vet ./...` passed with Go
  1.27.0 on Windows/amd64; the pinned Rust rotation check passed.

Next: Task 9, bounded opt-in remote manifest resolution and long-session policy.

## Task 9 completed

- Added strict `manifestUri` decoding with explicit SHA-256/384/512 digest,
  optional unsigned size and absolute HTTP(S) URLs without userinfo/fragments.
  `WithLiveRemoteManifests` enables requests only for copied, explicit origin
  allowlists. Redirects/cookie jars are disabled; status, response body, declared
  size and request deadline are bounded. Defaults are 4 MiB/10 seconds, with
  hard maxima of 16 MiB/one minute. Default validation makes no remote requests.
- Verify the whole response digest before parsing, then run complete detached
  manifest signature/trust/assertion/timestamp validation against the actual
  media segment or retained authenticated init, in original file coordinates.
  Init bindings must include all moov; media-bound newly disclosed keys enforce
  the announcement sequence floor. No key discovery bypasses asset binding.
- Cache only verified manifest/key associations, copied signer DER, size and
  digest pins. Response bodies and failed resolutions are not cached. Cached
  references must match their authorizing store exactly; known keys avoid
  refetching. Immutable identity pins live until reinitialization, with bounded
  history and no eviction that weakens replay checks. Admission is transactional
  through VSI/hash/timing/continuity success; embedded announcements take priority.
- Added `WithLiveSessionPolicy`: optional strictly increasing event IDs use a
  constant-memory high-water mark beyond 65,536 events; repeated/decreasing/wrapped
  IDs fail closed. Manifest capacity defaults to 64, configurable through 1024.
  Sender configuration uses `LiveMediaSignerConfig.SessionPolicy`.
- Recheck authorizing credential path/profile/trust/expiry for each media
  segment against WithClock, independently of manifest signing timestamps.
  Opt-in online revocation is rechecked at bounded intervals (default five
  minutes), with a total ten-second network budget and current OCSP/CRL update
  windows. Confirmed revocation/invalid credentials fail; network/parse/stale
  answers retain the established informational unknown policy. Failed segments
  do not commit recheck timestamps. Clock rollback triggers rechecking.
- Added copied `ManifestStore()` output and `SetManifestURI(url)` for the current
  sender store; embedded announcements clear stale references. These APIs do not
  publish or fetch data. Moved store extraction before signer commits after
  cancellation sweep tests exposed context checks after state installation.
- Tests exercise both init/media detached bindings, cache reuse and mismatched
  pins, origin/redirect/status/size/time limits, cancellation, trust/identifier/
  binding/signature/media failures, actual periodic OCSP revocation and stale
  responses, expiry/retry, policy limits, monotonic history and sender references.
- Validation: full `go test ./... -count=1`, `go vet ./...`, formatting and
  whitespace checks passed on Go 1.27.0 Windows/amd64. Ten-second reference-parser
  fuzzing passed 122,056 executions. Existing pinned Rust-to-Go fixtures and
  checksums still pass; remote retrieval itself has not been independently
  cross-validated with Rust.

Next: Task 10, documentation examples, release checks and remaining limitations.

## Task 10 completed

- Added external-package executable examples for independently validating the
  retained Rust stream and authoring/receiving a livesim2 key rotation through
  only the public Go API. Examples use explicit test trust, separate certificate
  and media clocks, and no external services or production credentials.
- Added `docs/live-media-release-checks.md` with a capability/evidence matrix,
  reproducible commands, actual toolchain results, coverage and remaining gaps.
  Linked it from the README/profile and corrected stale implementation comments.
  The offset-12 compatibility decision remains a blocker to claiming literal
  conformance with the pinned offset-0 spec text; no full C2PA certification is
  claimed. Remote/long-session independent Rust coverage remains unestablished.
- Added `validation/check-live-media.ps1` for dependency integrity, build, vet,
  full tests/coverage, optional fuzz/race checks and optional fresh Rust replay.
  Verified its environment isolation/restoration with generation variables set:
  the ordinary gate did not regenerate fixtures. Coverage/artifacts go into a
  separate directory. Offline minimum-version checks use a cached binary.
- Changed interoperability replay to generate fresh artifacts outside reviewed
  testdata by default, refuse output inside testdata, and validate the fresh Rust
  stream through an explicit test override. The replay passed both directions
  and Go-to-Rust rotation after Tasks 8/9; original fixture checksums still pass.
  Rust production source and Cargo.lock remain pinned and unchanged.
- Added all five live targets to the existing nightly fuzz matrix. Local
  ten-second runs passed 349,139 combined executions with no crash corpus.
- Windows/amd64 release gates passed with Go 1.26.0 (go.mod floor) and Go 1.27.0:
  `go mod verify`, `go build ./...`, `go vet ./...` and full test/example suites.
  Go 1.27 coverage was 87.1% overall and 86.2% for live production statements.
- Local race detection was unavailable (CGO disabled; no C compiler found), and
  golangci-lint was not installed. Existing hosted Linux/race/lint/c2patool gates
  remain required before merge; this report does not claim they ran or passed.

All ten implementation tasks are complete for the documented experimental
profile. No release/tag/publication is created by these checks. See the release
report for conformance limits, unverified profiles and remaining hosted gates.
