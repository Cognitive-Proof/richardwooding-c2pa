# Experimental Live Media profile

Implementation target: BMFF/CMAF Verifiable Segment Info (VSI), using
`c2pa-org/specs-core` at `2e6d3b4be833e8f779ddd25c467f20bb08ea366a`.
This document records implementation choices while the live API is being built.
It is not a declaration of complete C2PA 2.5 conformance. Task 7 verifies the
shared profile against a pinned Rust implementation; see
[interoperability results](../validation/live-media-interop/README.md).
See [release checks and remaining gaps](live-media-release-checks.md) and the
[executable public API examples](../live_example_test.go).

## VSI signatures and payloads

`signerBinding` uses the certificate DER encoded as a CBOR byte string as the
detached payload. COSE encodes those payload bytes inside its Sig_structure.
Independent testing against Rust identified and corrected the earlier raw-DER
interpretation; raw-DER bindings are rejected without a compatibility fallback.

- Session signatures use Ed25519 / COSE EdDSA (`alg = -8`). The algorithm is in
  the protected header; a nonempty byte-string `kid` is in the unprotected header.
- The envelope is a tag-18 COSE Sign1 with an attached CBOR payload. Verification
  uses the stored payload bytes. Detached VSI payloads are rejected.
- The payload has an unsigned 64-bit sequence number, a nonempty manifest ID
  matching the authenticated key's authorizing manifest, and a BMFF hash map.
- The initial hash profile uses an explicit SHA-256/384/512 algorithm and a digest
  of the matching length. Authoring currently emits SHA-256. The `merkle` field
  must be absent, including null or empty forms.
- Optional `iat` is not emitted or used as a validity clock. Unknown critical
  headers are rejected. `manifestUri` is a digest-pinned HTTP(S) store reference;
  retrieval is disabled unless an explicit remote policy allows its origin.

## Exclusion-offset compatibility decision

The pinned Live Media text prescribes a scheme predicate with `offset = 0`.
The existing BMFF hash engine interprets predicate offsets from the beginning
of the complete box. For a normal 32-bit, version-0 `emsg`, the layout is:

| Offset | Contents |
| --- | --- |
| 0 | 32-bit box size |
| 4 | `emsg` box type |
| 8 | version and flags |
| 12 | NUL-terminated `scheme_id_uri` |

This implementation uses **box-relative offset 12**, matching the convention
described by the experimental Rust work in
[contentauth/c2pa-rs #2867](https://github.com/contentauth/c2pa-rs/pull/2867).
It does not reinterpret offset 0 or change the shared BMFF hash engine. Resolving
the discrepancy in the specification remains necessary before claiming complete
conformance.

The emitted exclusion is `/emsg` with the 33 scheme bytes
`urn:c2pa:verifiable-segment-info\0` (including the NUL terminator, per
[c2pa-org/specs-core #2542](https://github.com/c2pa-org/specs-core/pull/2542))
at offset 12, so the byte-prefix data predicate matches only the exact scheme;
an event whose scheme merely starts with the VSI URI is hashed. During the
transition, validation also accepts the older unterminated 32-byte value. Because
that value matches as a prefix, validation additionally requires **every matched
box to be a valid VSI event** (c2pa-org/specs-core #2619). This rejects longer
lookalike schemes, incorrect values, and version-1 timing bytes that imitate the
prefix. Every VSI event must
be fully excluded. Other events, media, and embedded manifest boxes remain hashed.
The current profile rejects additional exclusion paths and subset exclusions.

## Carriage and layout

- VSI `emsg` boxes use 32-bit size headers, version 0, zero flags, the exact VSI
  scheme, `value = fseg`, zero presentation delta, and nonzero timescale/duration.
- The initial profile requires exactly one VSI event per complete segment.
  Unrelated version-0 and version-1 events remain opaque and hashed, including
  SCTE-35. A version-1 event explicitly naming the VSI scheme is rejected.
- Internal authoring supports one `moof`/`mdat` pair, an optional leading `styp`,
  one leading single-level `sidx`, and leading `prft`. It places VSI after that
  preamble and before existing events/the first `moof`. It preserves source boxes
  except for the index/base fields that insertion requires changing.
- The signer first reserves an event containing a fixed-size placeholder digest
  and Ed25519 signature. It hashes the resulting layout after repairing offsets,
  then replaces only the excluded event bytes. Included top-level box offsets are
  hashed in their final delivered coordinates.
- For a supported `sidx`, insertion at the beginning of, or inside, a referenced
  subsegment increases that reference's size. Insertion before the indexed range
  increases `first_offset`, preserving the original referenced bytes. Other
  references and index timing/SAP metadata remain unchanged.
- Explicit `tfhd.base_data_offset` values after the insertion point are remapped.
  Otherwise `default-base-is-moof` is required. Ambiguous implicit bases, explicit
  bases before insertion, hierarchical/multiple indexes, `ssix`, out-of-file index
  references and multiple `moof`/`mdat` pairs are refused by authoring.
- Existing VSI input is refused rather than silently stripped or re-signed.
  Input buffers are not modified, including on failure. Complete segments are
  bounded by `ValidateMaxScan`; VSI metadata is bounded by 1 MiB.

## Stateful segment validation

`LiveMediaValidator.ValidateMediaSegment` uses authenticated initialization state
and a caller-supplied media-time origin. It returns a `LiveMediaSegmentResult`
with per-segment statuses, the signed sequence number, mapped presentation time,
and a binding outcome. `Valid` requires all supported checks to pass. A verified
binding alone reports the narrower signature-checked media hash and can coexist
with a failed timing or continuity check.

Initialization admits exactly one track with a nonzero `tkhd` track ID and `mdhd`
timescale. Version-0 and version-1 track/media headers are supported. Track IDs in
media `tfhd` must match the authenticated track. Multiple tracks and edit lists
remain unsupported. Sample presentation times combine `tfdt`, cumulative decode
durations and `trun` composition offsets. Version-0 offsets are unsigned and
version-1 offsets are signed. The earliest sample PTS is the segment presentation
start, even if that sample is not first in decode order. Negative absolute media
presentation times and overflowing decode/presentation ranges are rejected.

Set the media-time origin **after successful initialization and before accepting
media**. For DASH, the caller derives it from `availabilityStartTime + Period.start
- presentationTimeOffset/timescale`. Epoch-based livesim2 streams use the Unix
epoch. There is no fallback to `iat`, current time or `prft`; producer-time boxes
remain hashed but are not used to infer a mapping in this profile. The origin
cannot change after a segment has been accepted. Successful explicit
reinitialization starts a new session and clears origin and continuity history.

Sample durations come from `trun`, then `tfhd` defaults, then matching `trex`
defaults. Decode time carries across runs within the single supported track
fragment. The `emsg` timescale must match the authenticated track scale, and its
duration must equal the presentation span from the earliest sample PTS to the
latest sample presentation end. For the captured livesim2 segments this equals
the summed decode duration, while presentation starts 6000 ticks after `tfdt`.
A segment is limited to 1,048,576 samples across all runs. Unknown/missing
durations, malformed sample tables and overflowing time ranges fail validation.
All timing bytes are checked only after signature/media hash validation.

The VSI sequence must equal the 32-bit `mfhd.sequence_number` in this profile;
the alternate DASH segment-indexing scheme is not implemented. Repeated or
decreasing sequences and values below the selected key's minimum fail. Forward
gaps are accepted as missing segments. The segment's mapped presentation start
must fall within the selected key's inclusive validity interval. Calculations use
64-bit integer arithmetic without `time.Duration` overflow or floating-point
conversion. Reported times round down to nanoseconds, while validity checks also
account for positive subnanosecond remainders.

VSI event IDs must be unique across accepted segments; they need not increase.
By default the validator retains at most 65,536 IDs and then fails closed rather
than evicting history and allowing reuse. The optional monotonic-ID policy below
supports longer sessions with constant memory. Failed segments, unreadable
inputs, scan caps and cancellation consume neither sequence numbers nor event IDs.
Embedded C2PA manifest announcements are validated transactionally; they preserve
the media-time origin and continuity history.

Example call sequence (the caller supplies `ctx`, `initReader`, `mediaReader`
and its trust pool):

```go
live := c2pa.NewLiveMediaValidator(c2pa.WithSigningTrust(pool))
initialization := live.ValidateInitSegment(ctx, initReader)
if !initialization.Valid {
    // Inspect initialization.Statuses; no session keys were admitted.
    return
}
if err := live.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
    return
}
segment := live.ValidateMediaSegment(ctx, mediaReader)
if !segment.Valid {
    // Inspect segment.Statuses; accepted continuity state is unchanged.
    return
}
```

## Public live signing

`NewLiveMediaSigner` takes an existing manifest `Signer` and a
`LiveMediaSignerConfig`. Omitted session keys and key IDs are generated with
`crypto/rand` (Ed25519 and a 16-byte ID). Supplied key/ID byte slices are copied.
`CreatedAt` defaults to the current UTC time; set it explicitly when signing
archived captures against their original presentation timeline. `ValidityPeriod`
is in seconds, with zero describing an instantaneous window. Set a useful period
explicitly. The initial profile uses 32-bit `mfhd` sequences, so the minimum
sequence cannot exceed that range.

The signer supplies the session-keys assertion and binds it to the manifest's
signer certificate. The caller supplies the usual manifest actions and other
assertions. The normal init signing pipeline checks manifest signatures, hash
bindings, and configured RFC 3161 timestamps or CAWG identity assertions. It then
checks the live-specific structure, track, moov coverage and session-key binding.
The receiver applies its own trust policy to the resulting init.

After init signing, set the explicit media-time origin. `SignMediaSegment` derives
sequence numbers and event timing from the complete source media, assigns event
IDs starting at zero, and self-validates each signed result against its admitted
session. This uses the same timing, expiry, continuity and resource-limit policy
as the public validator.

All signing methods return a complete byte buffer after validation. Failures
return no output and leave session state unchanged, including event IDs. Once
bytes are successfully returned, the signing sequence is committed; publishing
or persisting those bytes is the caller's operation. Keep the returned bytes for
retrying publication. A successful init can be signed only once per signer;
construct another signer for a new session. These methods are not concurrent-safe.

Example (the caller supplies a configured `manifestSigner`, context/readers,
session creation time, first sequence, media-time origin and an application-specific
`publish` function):

```go
live, err := c2pa.NewLiveMediaSigner(manifestSigner, c2pa.LiveMediaSignerConfig{
    CreatedAt:         sessionCreatedAt,
    ValidityPeriod:    3600,
    MinSequenceNumber: firstSequence,
})
if err != nil {
    return err
}
signedInit, err := live.SignInitSegment(ctx, initReader, c2pa.Manifest{
    Title: "Live stream",
    Actions: []c2pa.Action{{
        Action:            c2pa.ActionCreated,
        DigitalSourceType: c2pa.DigitalSourceTypeDigitalCapture,
    }},
})
if err != nil {
    return err
}
if err := live.SetMediaTimeOrigin(mediaTimeOrigin); err != nil {
    return err
}
signedMedia, err := live.SignMediaSegment(ctx, mediaReader)
if err != nil {
    return err
}
return publish(signedInit, signedMedia)
```

Independent Rust/Go interoperability for the shared initial profile is covered
by Task 7's retained fixtures and harness.

## Key rotation and authenticated announcements

Call `AddSessionKey(LiveMediaSignerConfig)` to schedule another session key.
Keys added before `SignInitSegment` are included in the init assertion. Keys added
after initialization require `SignMediaSegmentWithManifest(ctx, reader, manifest)`
before ordinary media signing resumes. That method announces the full schedule in
a new standard C2PA manifest; it can also announce a provenance change without
adding a key. The manifest signer stays the one passed to the constructor.

Selection evaluates sequence and earliest sample PTS, then chooses the eligible
key with the greatest `MinSequenceNumber`, preferring the latest added key on
ties. Earlier keys remain usable during overlapping windows. Key IDs must be
unique within a schedule/manifest; different manifests can authorize different
keys with the same ID. The receiver selects by `(manifestId, kid)` and verifies
the signature against that exact association. An earlier association may still
validate an overlapping segment without changing the latest announcement label
returned by `ManifestID()`.

For a newly disclosed key, `MinSequenceNumber` must be at least the announcing
segment's sequence and greater than the last accepted sequence. Repeating an
identical already-known key does not impose this new-key floor. Changing the key,
binding, creation time, validity or minimum makes it a new key. Once media signing
has started, scheduling also rejects a minimum at or below the last signed
sequence. Announce the key before its minimum passes; a late announcement fails
without advancing state.

The receiver requires one manifest box before VSI, the exact VSI `manifestId`, a
trusted claim signature, a flat signed BMFF v3 binding and exactly one native-CBOR
session-keys assertion. It checks every signer binding. The manifest may exclude
the standard C2PA UUID/ftyp/mfra boxes and selectively matched VSI events; arbitrary
paths and subset exclusions are refused. The VSI hash includes the final signed
manifest and all other segment content, including SCTE-35 events. This ordering
avoids a circular hash while authenticating the announcement and media together.

New keys and associations are staged until the VSI signature, media hash, timing,
key window, sequence and event-ID checks all pass. Failure or cancellation changes
neither the active manifest nor keys, origin, sequence or event history. Repeated
current announcements must contain exactly the same store bytes and still pass
segment continuity; altered stores reusing an identifier and reannounced retired
identifiers are refused. A failed segment can be retried with its original bytes.

The receiver defaults to 64 manifest associations, including the init, each with
at most 256 keys and a 1 MiB session assertion. The session policy below can raise
the manifest limit to 1024. It fails closed at capacity; no eviction weakens replay
protection. Explicit initialization replacement resets that history.

Announcement authoring supports unindexed segments with `default-base-is-moof`
sample addressing and an optional leading `styp`. It refuses `sidx`, `ssix`,
`mfra`, absolute/implicit sample bases, existing manifests and existing VSI, with
no output or state change. Ordinary VSI authoring retains its existing index
repair support. Timestamp and identity signing retain the manifest signer's
normal policy; receivers use their own configured trust pools.

Example during a running session (the caller supplies the next complete segment,
its sequence and a key creation time appropriate to the presentation timeline):

```go
if err := live.AddSessionKey(c2pa.LiveMediaSignerConfig{
    CreatedAt: nextKeyCreatedAt,
    ValidityPeriod: 3600,
    MinSequenceNumber: nextSequence,
}); err != nil {
    return err
}
announced, err := live.SignMediaSegmentWithManifest(ctx, nextSegment, c2pa.Manifest{
    Title: "Session key rotation",
    Actions: []c2pa.Action{{
        Action: c2pa.ActionCreated,
        DigitalSourceType: c2pa.DigitalSourceTypeDigitalCapture,
    }},
})
if err != nil {
    return err
}
// Publish these exact bytes; successful signing has committed the sequence.
return publish(announced)
```

The receiver continues calling `ValidateMediaSegment` on the same instance; no
separate unverified-key admission API or reinitialization is required.

## Remote manifests and long sessions

`WithLiveRemoteManifests(LiveRemoteManifestPolicy)` explicitly enables retrieval.
`AllowedOrigins` is a copied allowlist of `scheme://host[:port]` entries. HTTP and
HTTPS are supported; URL userinfo and fragments are rejected. Redirects are never
followed, including same-origin redirects. The remote client uses `WithHTTPClient`
with its cookie jar disabled, a context deadline, a response byte cap and status
200 required. The application selects allowed origins and a transport appropriate
to its DNS/proxy policy. Merely calling `WithHTTPClient` does not enable retrieval.

Defaults are 4 MiB per response and 10 seconds per request; hard maxima are 16 MiB
and one minute. Declared Content-Length and optional signed `size` are checked,
and the body reader also enforces the byte cap for chunked/compressed responses.
`manifestUri` requires an explicit SHA-256/384/512 `alg` and matching byte-string
`hash`. The digest of the entire response is verified before parsing any keys.

The response must be a raw C2PA Manifest Store with the requested active manifest
identifier. It undergoes the normal signature, trust, assertion, timestamp and
binding validation. The binding must cover either this media segment (selective
VSI exclusion allowed) or the exact admitted initialization segment, including
all of moov. The validator retains init bytes and checks original file offsets;
it does not insert a replacement UUID box to make a remote binding pass.
Media-bound newly disclosed keys follow the announcement sequence floor.
Init-bound keys can predate this segment, and normal VSI sequence/time limits
still apply. A trusted signature or matching URL alone never admits keys.

The session cache retains authenticated `(manifestId, kid)` associations, signer
certificate DER, store size, and SHA-256/384/512 pins; it does not retain downloaded
response bodies or cache failed resolutions. A reference to a cached manifest
must match its exact digest/size and cannot add another key to that identifier.
Known keys require no network access, even with remote retrieval disabled. Pins
remain immutable until explicit reinitialization; there is no HTTP freshness or
TTL-based replacement of a trusted identity. Credential freshness is checked
separately below. Embedded announcements take precedence over fetching.
All newly discovered state is staged until the complete segment validates.

`WithLiveSessionPolicy(LiveSessionPolicy)` controls bounded long-session behavior:

- `MonotonicEventIDs: true` requires each accepted ID to strictly increase and
  retains only the last ID, allowing sessions beyond 65,536 segments without
  forgetting replay history. A repeated/decreasing ID or uint32 wrap fails closed.
- `MaxManifests` defaults to 64 and accepts 1 through 1024. Earlier keys/digests
  remain available without eviction; rotate/reinitialize explicitly at capacity.
- `RevocationRecheckInterval` defaults to five minutes and accepts one second
  through one hour. Online checking still requires `WithOnlineRevocation(true)`.
  A recheck has a total ten-second network budget. OCSP/CRL answers are checked
  for current ThisUpdate/NextUpdate validity; stale answers are not authoritative.

The authorizing certificate path, profile, trust and expiration are checked for
every accepted media segment against `WithClock` (default current time). This
live credential check is independent of the historical signing time in a trusted
manifest timestamp. Archived-stream tests should supply their verification clock.
Confirmed revocation or expired/untrusted credentials fail with
`livevideo.sessionkey.invalid`; detailed credential statuses accompany it.
Revocation network/parse/freshness failures retain the library's existing
informational `unknown` policy. Failed segments do not advance recheck timestamps,
keys, event IDs or continuity. Backward clock movement triggers a new recheck.

Example receiver configuration:

```go
live := c2pa.NewLiveMediaValidator(
    c2pa.WithSigningTrust(pool),
    c2pa.WithLiveRemoteManifests(c2pa.LiveRemoteManifestPolicy{
        AllowedOrigins: []string{"https://provenance.example.org"},
        MaxBytes: 4 << 20,
        Timeout: 5 * time.Second,
    }),
    c2pa.WithLiveSessionPolicy(c2pa.LiveSessionPolicy{
        MonotonicEventIDs: true,
        MaxManifests: 128,
        RevocationRecheckInterval: 5 * time.Minute,
    }),
    c2pa.WithOnlineRevocation(true),
)
```

The sender can set `LiveMediaSignerConfig.SessionPolicy` at construction; adding
a key does not change the session policy. `ManifestStore()` returns a copied raw
store to publish, and `SetManifestURI(url)` adds a SHA-256-pinned reference to it
in subsequent VSI signatures. Passing an empty URL clears the reference. A
successful embedded announcement replaces the store and clears the previous URI.
These methods neither publish nor fetch data; callers must host the exact store
for the stream's lifetime. Remote retrieval is supported for both init-bound and
media-bound stores; the public sender's reference helper points to its current
already-authored store.

## Offline livesim2 acceptance

The six acceptance scenarios from c2pa-rs commit
`8f16c0f78673461ba41c184e71d29a6492be571c` are ported in `livesim2_test.go`, using
the original captured media bytes. Run `go test ./... -run '^TestLivesim2' -count=1`.
See [the fixture notes](../testdata/live_video/livesim2/README.md) for pinned
checksums, provenance, licenses, the composition-time correction and the expiry
negative-vector adaptation. These tests require no simulator, Docker or network.
