# Independent live-media interoperability

The adapter runs against contentauth/c2pa-rs commit
`8f16c0f78673461ba41c184e71d29a6492be571c`, using its locked dependencies and
`--no-default-features --features rust_native_crypto,unstable_live_video`.
It adds a test child module to `sdk/src/live_video/vsi_signing.rs`; production
Rust implementation code is unchanged. The child module can set `created_at`
to the archived capture's presentation time without adding a public SDK API.

From a Go checkout, with Rust/Cargo and Go installed:

```powershell
git clone https://github.com/contentauth/c2pa-rs C:\work\c2pa-rs-interop
git -C C:\work\c2pa-rs-interop checkout 8f16c0f78673461ba41c184e71d29a6492be571c
.\validation\live-media-interop\run.ps1 -RustCheckout C:\work\c2pa-rs-interop
```

Use a dedicated Rust checkout: the script installs the retained test adapter.
Credential generation and output generation are explicit operations; normal
`go test ./...` reads the retained Rust fixtures entirely offline and uses their
recorded verification time. A full Rust replay regenerates fresh certificates
because Rust validates manifest certificate lifetimes against its wall clock.
The script writes fresh artifacts to a temporary directory, or the directory
passed with `-OutputDirectory`; it refuses outputs inside this checkout's
`testdata` tree. Reviewed fixture bytes and checksums remain unchanged. Replacing
fixtures is a separate review step covering the bytes, provenance and digests.
The script leaves test-only private credentials in the printed output directory;
never use them outside these tests. No private credential is required in the
retained fixtures. The selected test reads the fresh Rust artifacts through
`C2PA_INTEROP_RUST`; the script restores its environment when it finishes.

The Go credential generator issues an ordinary P-256 test CA and Ed25519 leaf for
the Rust manifest signer. The pinned SDK's `EphemeralSigner` certificate generator
emits a subject-key-identifier extension Go's standard X.509 parser rejects.
Using valid X.509 credentials avoids changing either validator's certificate
requirements. Rust independently authors the C2PA manifest, native session-key
assertion, signer binding, VSI COSE signature, BMFF exclusions and media hashes.
Go independently authors the reciprocal stream, using an ES256 manifest signer.
Both use Ed25519 session keys and explicit test trust roots; neither receiving
validator disables trust verification.

Each direction checks one trusted initialization and three ordered signed media
segments from the original livesim2 capture. Both reject sample-byte tampering
using fresh receivers, and Go rejects the Rust initialization with an empty trust
pool. Rust checks `StatusTracker` failures in addition to return values because
the live API can return `Ok` after recording a validation failure.

## Profile boundaries

- Both sides use Unix epoch as the media-time origin, first sequence 880000021,
  session creation 1760000042 Unix seconds, a 60-second validity window, one
  track and complete media segments. No network or system trust root is needed.
- `signerBinding` signs a CBOR byte string containing the certificate DER as
  the detached COSE payload. The COSE Sig_structure then encodes that payload
  as a byte string. Task 7 exposed and corrected the earlier Go interpretation
  that signed raw DER. The old raw-DER encoding is rejected, without fallback.
- The pinned Rust validator maps `tfdt` decode time directly to presentation
  time; Go evaluates sample presentation offsets. The capture's earliest PTS is
  6000/90000 seconds after decode time. The shared 60-second window admits both;
  passing this suite does not demonstrate agreement at narrow time boundaries.
- Rust requires positive validity periods; Go additionally permits the schema's
  zero-second instantaneous window. That case is outside this shared profile.
- Both implementations use the documented box-relative exclusion offset 12.
  The retained Task 7 fixtures verify the initial session profile. Task 8 adds
  an optional Go-authored rotation stream; remote resolution and multi-track media
  are outside the verified profile. These are not full C2PA conformance claims.

## Rotation regression (Task 8)

`run.ps1` also generates a temporary Go-authored livesim2 stream that announces a
new key in segment two, then uses it in segment three. The pinned Rust SDK checks
all three via `validate_verifiable_segment_info_with_context`, with explicit root
trust enabled and the announcement's key-manifest state required to be `Trusted`.
Both directions and this Go-to-Rust rotation check were replayed after Task 9 on
2026-10-16. The original twelve retained fixture files and their hashes remained
unchanged. Remote retrieval and long-session policies have Go regression coverage;
they have not been independently verified against Rust.

To repeat only rotation without regenerating the Task 7 fixture files, install
the adapter as above, set `C2PA_INTEROP_ROTATION` to a temporary output directory
in both shells, run `go test -run '^TestLiveInteropGenerateRotation$' -count=1 .`,
then run the pinned Cargo command with test filter
`go_interop_validate_go_rotation`. No private credential export is needed for this
rotation stream. The optional Rust test is inactive when that variable is absent.

Signed fixture provenance and checksums are in
`testdata/live_video/interop/README.md`. Original media provenance and applicable
licenses remain in `testdata/live_video/livesim2/`.
