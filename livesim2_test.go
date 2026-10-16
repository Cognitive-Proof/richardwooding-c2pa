// Acceptance scenarios adapted from contentauth/c2pa-rs commit
// 8f16c0f78673461ba41c184e71d29a6492be571c (Copyright 2026 Adobe).
// The original tests are Apache-2.0 OR MIT; the MIT license and fixture licenses
// are retained in testdata/live_video/livesim2. This port runs entirely offline.
package c2pa

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const livesim2FirstSequence = uint64(880000021)
const livesim2FirstSeconds = int64(1760000042)
const livesim2Scale = uint32(90000)
const livesim2Duration = uint32(180000)
const livesim2Root = "testdata/live_video/livesim2"

// Pin both size and digest independently of the imported capture.json. Updates
// require reviewing the bytes, provenance and these pins together.
var livesim2Pins = map[string]struct {
	size int
	sha  string
}{
	"Manifest.mpd":  {2206, "2649172874a82f3f8120df02903d34977fa4be466d77e76f428f6335d2170d3e"},
	"init.mp4":      {678, "e922cb882aa584fdd48abb12900175bd81e362b0a8878f646b09d069d23e26bd"},
	"880000021.m4s": {39032, "484a0ad5b092f53910cd2730f047315ea1c0a7be58ba736b72237729d0a0e702"},
	"880000022.m4s": {39479, "8a62e597e5cd4f5644544c74f67026d139a7d4df40d69ace7beb156809f466d9"},
	"880000023.m4s": {39433, "bca600cfdd7a719495cb3b6dcefe366c1ececb1c2af22e73b1460b865045442b"},
}

func livesim2Read(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(livesim2Root, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func loadLivesim2(t testing.TB) map[string][]byte {
	t.Helper()
	var record struct {
		Timescale     uint32 `json:"timescale"`
		FirstSequence uint64 `json:"first_sequence_number"`
		FirstSeconds  int64  `json:"first_presentation_time_seconds"`
		Duration      uint32 `json:"segment_duration_seconds"`
		Files         []struct {
			Name string `json:"name"`
			Size int    `json:"size"`
			SHA  string `json:"sha256"`
		} `json:"files"`
	}
	if err := json.Unmarshal(livesim2Read(t, "capture.json"), &record); err != nil {
		t.Fatal(err)
	}
	if record.Timescale != livesim2Scale || record.FirstSequence != livesim2FirstSequence || record.FirstSeconds != livesim2FirstSeconds || record.Duration != 2 || len(record.Files) != len(livesim2Pins) {
		t.Fatal("capture metadata differs from pinned acceptance profile")
	}
	files := make(map[string][]byte)
	for _, entry := range record.Files {
		pin, ok := livesim2Pins[entry.Name]
		if !ok || files[entry.Name] != nil || entry.Size != pin.size || entry.SHA != pin.sha {
			t.Fatalf("unexpected capture entry: %s", entry.Name)
		}
		data := livesim2Read(t, entry.Name)
		digest := sha256.Sum256(data)
		if len(data) != pin.size || hex.EncodeToString(digest[:]) != pin.sha {
			t.Fatalf("%s differs from the pinned capture", entry.Name)
		}
		files[entry.Name] = data
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(string(livesim2Read(t, "SHA256SUMS"))), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatal("invalid SHA256SUMS")
		}
		pin, ok := livesim2Pins[fields[1]]
		if !ok || seen[fields[1]] || fields[0] != pin.sha {
			t.Fatal("SHA256SUMS differs from pinned capture")
		}
		seen[fields[1]] = true
	}
	if len(seen) != len(livesim2Pins) {
		t.Fatal("incomplete SHA256SUMS")
	}
	return files
}

func TestLivesim2CaptureChecksums(t *testing.T) { _ = loadLivesim2(t) }

type livesim2Capture struct {
	files  map[string][]byte
	init   []byte
	author *LiveMediaSigner
	config LiveMediaSignerConfig
	roots  *x509.CertPool
}

func newLivesim2Capture(t testing.TB, validity uint64) livesim2Capture {
	t.Helper()
	files := loadLivesim2(t)
	manifestSigner, sc := newTestSigner(t)
	cfg := LiveMediaSignerConfig{SessionKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32)), KeyID: []byte("livesim2-session"), CreatedAt: time.Unix(livesim2FirstSeconds, 0), ValidityPeriod: validity, MinSequenceNumber: livesim2FirstSequence}
	author, err := NewLiveMediaSigner(manifestSigner, cfg)
	if err != nil {
		t.Fatal(err)
	}
	init, err := author.SignInitSegment(context.Background(), bytes.NewReader(files["init.mp4"]), createdManifest("livesim2 offline acceptance"))
	if err != nil {
		t.Fatal(err)
	}
	if err := author.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	return livesim2Capture{files, init, author, cfg, sc.roots}
}

func (c livesim2Capture) receiver(t testing.TB, origin time.Time) *LiveMediaValidator {
	t.Helper()
	v := NewLiveMediaValidator(WithSigningTrust(c.roots))
	r := v.ValidateInitSegment(context.Background(), bytes.NewReader(c.init))
	if !r.Valid || r.Binding != BindingVerified {
		t.Fatalf("captured init failed validation: %+v", r.Statuses)
	}
	// Confirm native assertion bytes and the carried certificate authorize the
	// key, without JSON conversion or globally disabling trust verification.
	m := parseStore(context.Background(), extractJUMBF(context.Background(), BMFF, c.init)).active()
	a, err := liveInitSessionAssertion(m)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := decodeLiveSessionKeys(a.data, r.SignerChain[0].Raw)
	if err != nil || len(keys) != 1 || keys[0].minSequence != livesim2FirstSequence || keys[0].validity != c.config.ValidityPeriod || !keys[0].created.Equal(c.config.CreatedAt) {
		t.Fatalf("native session keys: %+v, %v", keys, err)
	}
	if err := v.SetMediaTimeOrigin(origin); err != nil {
		t.Fatal(err)
	}
	return v
}

var livesim2Media = []string{"880000021.m4s", "880000022.m4s", "880000023.m4s"}

func (c livesim2Capture) sign(t testing.TB, index int) []byte {
	t.Helper()
	signed, err := c.author.SignMediaSegment(context.Background(), bytes.NewReader(c.files[livesim2Media[index]]))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func livesim2SCTE35(data []byte) *bmffBox {
	for _, b := range parseBMFFBoxes(context.Background(), data) {
		if b.typ != "emsg" {
			continue
		}
		p := data[b.start+b.headerLen : b.end]
		if len(p) > 24 && p[0] == 1 && bytes.HasPrefix(p[24:], []byte("urn:scte:scte35:2013:bin\x00")) {
			return b
		}
	}
	return nil
}

func TestLivesim2CapturedDASHSegmentsRoundTripWithEpochTiming(t *testing.T) {
	c := newLivesim2Capture(t, 10)
	v := c.receiver(t, time.Unix(0, 0))
	if v.init.track.timescale != livesim2Scale {
		t.Fatal("captured timescale differs")
	}
	if livesim2SCTE35(c.files[livesim2Media[0]]) == nil || livesim2SCTE35(c.files[livesim2Media[1]]) != nil {
		t.Fatal("unexpected captured SCTE-35 layout")
	}
	for i, name := range livesim2Media {
		source := c.files[name]
		if string(source[4:8]) != "styp" {
			t.Fatal("source does not begin with styp")
		}
		timing, err := liveSegmentTiming(context.Background(), source, parseBMFFBoxes(context.Background(), source), v.init.track)
		expectedTicks := uint64(livesim2FirstSeconds+int64(2*i)) * uint64(livesim2Scale)
		if err != nil || uint64(timing.sequence) != livesim2FirstSequence+uint64(i) || timing.start != expectedTicks || timing.presentationStart != expectedTicks+6000 || timing.duration != uint64(livesim2Duration) || expectedTicks <= uint64(^uint32(0)) {
			t.Fatalf("capture timing: %+v %v", timing, err)
		}
		signed := c.sign(t, i)
		_, vsi := liveTestEvent(t, signed)
		if string(signed[4:8]) != "styp" || !bytes.Equal(append(bytes.Clone(signed[:vsi.start]), signed[vsi.end:]...), source) {
			t.Fatal("original capture boxes were not preserved")
		}
		r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(signed))
		if !r.Valid || r.Binding != BindingVerified || r.SequenceNumber != livesim2FirstSequence+uint64(i) || !r.PresentationTime.Equal(time.Unix(livesim2FirstSeconds+int64(2*i), 66_666_666)) {
			t.Fatalf("captured round trip: %+v", r)
		}
	}
	if v.init.lastSequence != livesim2FirstSequence+2 {
		t.Fatal("last accepted live sequence differs")
	}
}

func assertLivesim2HashFailure(t testing.TB, c livesim2Capture, segment []byte) {
	t.Helper()
	v := c.receiver(t, time.Unix(0, 0))
	r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(segment))
	if r.Valid || r.Binding != BindingFailed || !r.Has(StatusLiveVideoSegmentInvalid) || v.init.seen || len(v.init.eventIDs) != 0 {
		t.Fatalf("tampering accepted or changed continuity: %+v", r)
	}
	found := false
	for _, status := range r.Statuses {
		if status.Err != nil && strings.Contains(status.Err.Error(), "bmffHash verification failed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected actual media digest mismatch: %+v", r.Statuses)
	}
}

func TestLivesim2TamperedSCTE35CueFailsMediaHash(t *testing.T) {
	c := newLivesim2Capture(t, 10)
	signed := c.sign(t, 0)
	cue := livesim2SCTE35(signed)
	original := livesim2SCTE35(c.files[livesim2Media[0]])
	if cue == nil || original == nil || !bytes.Equal(signed[cue.start:cue.end], c.files[livesim2Media[0]][original.start:original.end]) {
		t.Fatal("original cue changed before tampering")
	}
	signed[cue.end-1] ^= 1
	assertLivesim2HashFailure(t, c, signed)
}

func TestLivesim2RemovedSCTE35CueFailsMediaHash(t *testing.T) {
	c := newLivesim2Capture(t, 10)
	signed := c.sign(t, 0)
	cue := livesim2SCTE35(signed)
	if cue == nil {
		t.Fatal("missing captured cue")
	}
	signed = append(signed[:cue.start], signed[cue.end:]...)
	assertLivesim2HashFailure(t, c, signed)
}

func TestLivesim2TamperedMediaPayloadFailsMediaHash(t *testing.T) {
	c := newLivesim2Capture(t, 10)
	signed := c.sign(t, 0)
	mdat := topBox(signed, "mdat")
	if mdat == nil {
		t.Fatal("no mdat")
	}
	signed[mdat.end-1] ^= 1
	assertLivesim2HashFailure(t, c, signed)
}

func TestLivesim2KeyExpiryUsesCapturedPresentationTime(t *testing.T) {
	c := newLivesim2Capture(t, 3)
	v := c.receiver(t, time.Unix(0, 0))
	for i := 0; i < 2; i++ {
		signed := c.sign(t, i)
		if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(signed)); !r.Valid {
			t.Fatal(r.Statuses)
		}
	}
	// The public Go signer itself refuses to emit expired media. Construct the
	// cryptographically valid negative vector with the low-level builder so the
	// receiver still exercises the original Rust test's expiry rejection.
	if out, err := c.author.SignMediaSegment(context.Background(), bytes.NewReader(c.files[livesim2Media[2]])); out != nil || err == nil {
		t.Fatal("public signer emitted expired segment")
	}
	signed, err := buildLiveVSISegment(context.Background(), c.files[livesim2Media[2]], c.config.SessionKey, c.config.KeyID, c.author.ManifestID(), livesim2FirstSequence+2, liveEvent{timescale: livesim2Scale, duration: livesim2Duration, id: 2})
	if err != nil {
		t.Fatal(err)
	}
	r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(signed))
	if r.Valid || r.Binding != BindingVerified || !r.Has(StatusLiveVideoSegmentInvalid) || v.init.lastSequence != livesim2FirstSequence+1 || len(v.init.eventIDs) != 2 {
		t.Fatalf("expiry advanced state: %+v", r)
	}
	found := false
	for _, status := range r.Statuses {
		if strings.Contains(status.Explanation, "presentation time is outside") {
			found = true
		}
	}
	if !found {
		t.Fatalf("failure was not presentation-time expiry: %+v", r.Statuses)
	}
}

func TestLivesim2WrongEpochOriginFailsKeyValidity(t *testing.T) {
	c := newLivesim2Capture(t, 10)
	signed := c.sign(t, 0)
	v := c.receiver(t, time.Unix(3600, 0))
	r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(signed))
	if r.Valid || r.Binding != BindingVerified || !r.Has(StatusLiveVideoSegmentInvalid) || v.init.seen || len(v.init.eventIDs) != 0 {
		t.Fatalf("incorrect origin accepted: %+v", r)
	}
	if err := v.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(signed)); !r.Valid {
		t.Fatalf("failed origin check consumed continuity: %+v", r)
	}
}
