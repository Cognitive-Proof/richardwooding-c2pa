# Signed Rust/Go Live Media fixtures

Generated and independently verified on 2026-10-16 with:

- Rust SDK: contentauth/c2pa-rs `8f16c0f78673461ba41c184e71d29a6492be571c`
  (`c2pa 0.91.0-dev`), unchanged production code and locked dependencies.
- Rust/Cargo 1.98.1, Windows x86_64 MSVC;
  `--no-default-features --features rust_native_crypto,unstable_live_video`.
- Go 1.27.0, Windows/amd64; this checkout's experimental Live Media API.
- Retained adapter: `validation/live-media-interop/go_interop_harness.rs`.
  Only a `cfg(test)` child-module registration is added to the Rust source.

`rust/` contains initialization and media authored by the pinned Rust SDK;
`go/` contains the reciprocal Go-authored stream. Each carries an explicit
test-only trust root and a recorded manifest-verification time. Neither contains
private keys. Roots are test fixtures, not production trust anchors. SHA256SUMS
covers all twelve files; `TestLiveInteropFixtureChecksums` verifies them offline.

Each signed set derives from the original `../livesim2/init.mp4` and three media
responses, with first sequence 880000021. Both use an Ed25519 session key, creation
time 1760000042 Unix seconds, 60-second validity and explicit Unix-epoch media
origin. The media sample payload is unchanged. Rust includes its own VSI and
manifest; Go includes independently authored VSI and manifest. See the harness
README for the certificate-generation workaround and timing-profile differences.

The full reproduction script passed both directions: trusted init, session-key
binding and three sequential media segments; each receiver also rejected changed
sample bytes. Go rejected an empty trust pool, and Rust rejected the other
stream's CA. The six original pinned Rust livesim2 acceptance tests also passed.

Normal Go CI uses the recorded Rust fixture verification clock, so certificate
expiration does not make the regression time-dependent. Replaying Rust's
wall-clock manifest checks requires regenerating fixtures using `run.ps1`.
Generation uses new test credentials and random manifest identities. Review new
bytes, checksums and provenance together; do not substitute a Go roundtrip for
the independent Rust check.

The underlying media and upstream fixture provenance/licenses are preserved in
`../livesim2/README.md`, `LICENSE-content`, `LICENSE-livesim2.md`, and
`LICENSE-c2pa-rs-MIT`. These signed derivatives retain those applicable terms.
