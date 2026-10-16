# livesim2 offline acceptance fixtures

Imported from [contentauth/c2pa-rs commit
8f16c0f78673461ba41c184e71d29a6492be571c](https://github.com/contentauth/c2pa-rs/tree/8f16c0f78673461ba41c184e71d29a6492be571c/sdk/tests/fixtures/live_video/livesim2)
on 2026-10-16. The captured responses, `capture.json`, `SHA256SUMS`, licenses and
`capture.py` retain their upstream bytes. The original upstream README is preserved
as [UPSTREAM.md](UPSTREAM.md).

The capture is unsigned DASH-IF livesim2 v1.14.0 output: `testpic_2s/V300`, an init,
three consecutive media segments, and an MPD, with a fixed simulator clock and a
real SCTE-35 event in the first media segment. Exact request URLs, hashes, lengths,
server-reported version and observed source revision are in `capture.json`.
Media/init responses total 118,622 bytes; including the MPD they total 120,828 bytes.
The files were not re-encoded or edited.

## Verification

From this Go repository's root, verify the pinned files and run the six acceptance
scenarios without networking:

```sh
go test ./... -run '^TestLivesim2' -count=1
```

The tests independently pin all five response hashes and lengths, and also check
that `capture.json` and `SHA256SUMS` agree with those pins. `.gitattributes` disables
line-ending conversion for this directory, including the checksummed MPD.

The retained upstream verifier also works offline using only Python's standard
library:

```sh
python3 testdata/live_video/livesim2/capture.py
```

An optional network recapture is available by explicitly adding `--recapture`.
The script stages every response and refuses to replace files if any response's
length/hash differs. `--base-url` can select a local simulator. No recapture or
network access is used by Go tests. Reviewing a different capture requires updating
the media, provenance, checksums and Go hash pins together.

## Go test adaptations

`livesim2_test.go` ports all six acceptance scenarios: round trip with epoch media
time, SCTE-35 payload tampering, removal of the SCTE-35 event, media tampering,
expiry during the sequence, and an incorrect time origin. It uses the public Go
signing/validation APIs, current test certificates and an explicit test trust pool.
The session key's creation time is configured to match the archived media period;
no global trust bypass or current-time fallback is used.

Two differences from the original Rust test are intentional:

- The real media uses nonzero `trun` composition offsets. Its earliest sample PTS
  is `tfdt + 6000` ticks, or 66.666... ms after decode start at timescale 90000.
  The Go tests assert this actual presentation start (reported at nanosecond
  precision), rather than treating `tfdt` alone as presentation time. Each captured
  segment's presentation span remains 180000 ticks, or two seconds. Signed/unsigned
  composition offsets, reordered samples and multiple runs are covered separately
  in `live_composition_test.go`.
- The public Go signer self-validates and refuses to return the expired third
  segment. The expiry test asserts that refusal, then uses the low-level builder
  with the same test key to make a cryptographically valid negative vector. The
  receiver must reject it without advancing sequence/event-ID state.

The captures are unsigned simulator responses. These tests establish Go round
trips and rejection behavior using real DASH media; they do not establish
independent Rust/Go signature interoperability. That is a separate test task.

## Attribution and licenses

- Original Rust acceptance tests: Copyright 2026 Adobe, Apache-2.0 OR MIT.
  The MIT license from the pinned c2pa-rs revision is `LICENSE-c2pa-rs-MIT`.
- Source media: DASH Industry Forum `livesim-content`, Apache-2.0;
  retained license: `LICENSE-content`.
- livesim2 simulator: DASH Industry Forum, BSD-3-Clause;
  retained license/copyright: `LICENSE-livesim2.md`.

See `UPSTREAM.md` for the full original capture provenance and scope.
