package c2pa

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"math"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const liveTestSequence = uint64(880000021)
const liveTestEpochSeconds = uint64(1760000042)

func liveTimedInit(id, scale, duration uint32) []byte {
	return liveTimedInitVersion(id, scale, duration, 0)
}
func liveTimedInitVersion(id, scale, duration uint32, version byte) []byte {
	tkhdLen, mdhdLen, offset := 84, 24, 12
	if version == 1 {
		tkhdLen, mdhdLen, offset = 96, 36, 20
	}
	tkhd := make([]byte, tkhdLen)
	tkhd[0] = version
	tkhd[3] = 3
	binary.BigEndian.PutUint32(tkhd[offset:], id)
	mdhd := make([]byte, mdhdLen)
	mdhd[0] = version
	binary.BigEndian.PutUint32(mdhd[offset:], scale)
	trex := make([]byte, 24)
	binary.BigEndian.PutUint32(trex[4:], id)
	binary.BigEndian.PutUint32(trex[8:], 1)
	binary.BigEndian.PutUint32(trex[12:], duration)
	return bytes.Join([][]byte{synthBox("ftyp", []byte("iso6"), make([]byte, 4), []byte("dash")),
		synthBox("moov", synthBox("mvhd", make([]byte, 100)), synthBox("trak", synthBox("tkhd", tkhd), synthBox("mdia", synthBox("mdhd", mdhd))), synthBox("mvex", synthBox("trex", trex)))}, nil)
}

type liveSegmentFixture struct {
	validator       *LiveMediaValidator
	private         ed25519.PrivateKey
	init            []byte
	scale, duration uint32
}

func newLiveSegmentFixture(t testing.TB, scale, duration uint32, validity uint64) liveSegmentFixture {
	t.Helper()
	s, sc := newTestSigner(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32))
	k, err := newLiveSessionKey(private, []byte("session"), sc.chain[0].Raw, time.Unix(int64(liveTestEpochSeconds), 0), validity, liveTestSequence)
	if err != nil {
		t.Fatal(err)
	}
	data, err := encodeLiveSessionKeys([]liveSessionKey{k})
	if err != nil {
		t.Fatal(err)
	}
	m := createdManifest("timed init")
	m.Assertions = []Assertion{{Label: liveSessionKeysLabel, Value: cbor.RawMessage(data)}}
	init := signBytes(t, s, BMFF, liveTimedInit(7, scale, duration), m)
	v := NewLiveMediaValidator(WithSigningTrust(sc.roots))
	if r := v.ValidateInitSegment(context.Background(), bytes.NewReader(init)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	return liveSegmentFixture{v, private, init, scale, duration}
}

func liveMediaSource(sequence uint32, ticks uint64, id, duration uint32, composition int32) []byte {
	mfhd := synthBox("mfhd", make([]byte, 4), binary.BigEndian.AppendUint32(nil, sequence))
	tfhd := synthBox("tfhd", []byte{0, 2, 0, 0}, binary.BigEndian.AppendUint32(nil, id))
	tfdt := synthBox("tfdt", []byte{1, 0, 0, 0}, binary.BigEndian.AppendUint64(nil, ticks))
	flags := uint32(0x301)
	if composition != 0 {
		flags |= 0x800
	}
	if composition < 0 {
		flags |= 1 << 24
	}
	p := binary.BigEndian.AppendUint32(nil, flags)
	p = binary.BigEndian.AppendUint32(p, 1)
	p = binary.BigEndian.AppendUint32(p, 0)
	p = binary.BigEndian.AppendUint32(p, duration)
	p = binary.BigEndian.AppendUint32(p, 40)
	if composition != 0 {
		p = binary.BigEndian.AppendUint32(p, uint32(composition))
	}
	moof := synthBox("moof", mfhd, synthBox("traf", tfhd, tfdt, synthBox("trun", p)))
	trun := matchBMFFXPath(context.Background(), parseBMFFBoxes(context.Background(), moof), "/moof/traf/trun")[0]
	binary.BigEndian.PutUint32(moof[trun.start+trun.headerLen+8:], uint32(len(moof)+8))
	return bytes.Join([][]byte{synthBox("styp", []byte("msdh"), make([]byte, 4), []byte("msdh")), moof, synthBox("mdat", make([]byte, 40))}, nil)
}

func (f liveSegmentFixture) segment(t testing.TB, sequence uint64, ticks uint64, eventID uint32) []byte {
	t.Helper()
	out, err := buildLiveVSISegment(context.Background(), liveMediaSource(uint32(sequence), ticks, 7, f.duration, 0), f.private, []byte("session"), f.validator.ManifestID(), sequence, liveEvent{timescale: f.scale, duration: f.duration, id: eventID})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLiveMediaPresentationTimeAndExpiry(t *testing.T) {
	f := newLiveSegmentFixture(t, 90000, 180000, 3)
	if err := f.validator.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < 3; i++ {
		segment := f.segment(t, liveTestSequence+i, (liveTestEpochSeconds+2*i)*90000, uint32(i))
		r := f.validator.ValidateMediaSegment(context.Background(), bytes.NewReader(segment))
		if i < 2 {
			if !r.Valid || r.Binding != BindingVerified || !r.PresentationTime.Equal(time.Unix(int64(liveTestEpochSeconds+2*i), 0)) {
				t.Fatalf("segment %d: %+v", i, r)
			}
		} else if r.Valid || !r.Has(StatusLiveVideoSegmentInvalid) {
			t.Fatalf("expired segment accepted: %+v", r)
		}
	}
	if f.validator.init.lastSequence != liveTestSequence+1 || len(f.validator.init.eventIDs) != 2 {
		t.Fatal("expiry advanced continuity")
	}
	if err := f.validator.SetMediaTimeOrigin(time.Unix(3600, 0)); err == nil {
		t.Fatal("accepted timeline changed mid-session")
	}
	if r := f.validator.ValidateInitSegment(context.Background(), bytes.NewReader(f.init)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	if f.validator.init.origin != nil || f.validator.init.seen || len(f.validator.init.eventIDs) != 0 {
		t.Fatal("new session retained timeline/continuity")
	}
}

func TestLiveMediaRequiresCorrectOrigin(t *testing.T) {
	f := newLiveSegmentFixture(t, 90000, 180000, 10)
	segment := f.segment(t, liveTestSequence, liveTestEpochSeconds*90000, 1)
	if r := f.validator.ValidateMediaSegment(context.Background(), bytes.NewReader(segment)); r.Valid || f.validator.init.seen {
		t.Fatal("missing origin accepted")
	}
	if err := f.validator.SetMediaTimeOrigin(time.Unix(3600, 0)); err != nil {
		t.Fatal(err)
	}
	if r := f.validator.ValidateMediaSegment(context.Background(), bytes.NewReader(segment)); r.Valid || f.validator.init.seen {
		t.Fatal("wrong origin accepted")
	}
	if err := f.validator.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if r := f.validator.ValidateMediaSegment(context.Background(), bytes.NewReader(segment)); !r.Valid {
		t.Fatal(r.Statuses)
	}
}

func TestLiveMediaContinuityAndEventIDs(t *testing.T) {
	f := newLiveSegmentFixture(t, 1000, 2000, 20)
	if err := f.validator.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	base := liveTestEpochSeconds * 1000
	first := f.segment(t, liveTestSequence, base, 42)
	if r := f.validator.ValidateMediaSegment(context.Background(), bytes.NewReader(first)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	for _, bad := range [][]byte{first, f.segment(t, liveTestSequence-1, base, 43), f.segment(t, liveTestSequence+1, base+2000, 42)} {
		r := f.validator.ValidateMediaSegment(context.Background(), bytes.NewReader(bad))
		if r.Valid || !r.Has(StatusLiveVideoSegmentInvalid) || f.validator.init.lastSequence != liveTestSequence || len(f.validator.init.eventIDs) != 1 {
			t.Fatalf("bad continuity admitted: %+v", r)
		}
	}
	clean := f.segment(t, liveTestSequence+1, base+2000, 43)
	tampered := bytes.Clone(clean)
	tampered[len(tampered)-1] ^= 1
	if r := f.validator.ValidateMediaSegment(context.Background(), bytes.NewReader(tampered)); r.Valid || f.validator.init.lastSequence != liveTestSequence {
		t.Fatal("tampering advanced continuity")
	}
	if r := f.validator.ValidateMediaSegment(context.Background(), bytes.NewReader(clean)); !r.Valid {
		t.Fatalf("failed attempt consumed sequence or event ID: %+v", r)
	}
	// Distinct event IDs need not increase. Forward sequence gaps are tolerated.
	next := f.segment(t, liveTestSequence+2, base+4000, 1)
	if r := f.validator.ValidateMediaSegment(context.Background(), bytes.NewReader(next)); !r.Valid {
		t.Fatal(r.Statuses)
	}
}

func TestLiveMediaRejectsTimingAndHashTampering(t *testing.T) {
	for _, kind := range []string{"event scale", "event duration", "media hash", "track ID", "presentation underflow", "sequence mismatch", "below minimum"} {
		t.Run(kind, func(t *testing.T) {
			f := newLiveSegmentFixture(t, 1000, 2000, 10)
			if err := f.validator.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
				t.Fatal(err)
			}
			seq := liveTestSequence
			if kind == "below minimum" {
				seq--
			}
			segment := f.segment(t, seq, liveTestEpochSeconds*1000, 1)
			switch kind {
			case "event scale", "event duration":
				_, box := liveTestEvent(t, segment)
				at := box.start + 12 + len(liveVSIScheme) + 1 + len("fseg") + 1
				if kind == "event duration" {
					at += 8
				}
				binary.BigEndian.PutUint32(segment[at:], 123)
			case "media hash":
				segment[len(segment)-1] ^= 1
			case "track ID", "presentation underflow", "sequence mismatch":
				id, cto, wireSeq := uint32(7), int32(0), uint32(seq)
				ticks := liveTestEpochSeconds * 1000
				if kind == "track ID" {
					id = 8
				}
				if kind == "presentation underflow" {
					cto = -1
					ticks = 0
				}
				if kind == "sequence mismatch" {
					wireSeq++
				}
				var err error
				segment, err = buildLiveVSISegment(context.Background(), liveMediaSource(wireSeq, ticks, id, 2000, cto), f.private, []byte("session"), f.validator.ManifestID(), seq, liveEvent{timescale: 1000, duration: 2000, id: 1})
				if err != nil {
					t.Fatal(err)
				}
			}
			r := f.validator.ValidateMediaSegment(context.Background(), bytes.NewReader(segment))
			if r.Valid || f.validator.init.seen || len(f.validator.init.eventIDs) != 0 {
				t.Fatalf("invalid segment advanced state: %+v", r)
			}
		})
	}
}

func TestLivePresentationArithmetic(t *testing.T) {
	for _, scale := range []uint32{1, 1000, 90000, math.MaxUint32} {
		at, sub, err := livePresentationTime(time.Unix(0, 0), liveTestEpochSeconds*uint64(scale), scale)
		if err != nil || sub || !at.Equal(time.Unix(int64(liveTestEpochSeconds), 0)) {
			t.Fatalf("scale %d: %v %v", scale, at, err)
		}
	}
	if _, _, err := livePresentationTime(time.Unix(0, 0), math.MaxUint64, 1); err == nil {
		t.Fatal("timestamp overflow accepted")
	}
	seconds := uint64(400 * 365 * 24 * 60 * 60)
	if at, _, err := livePresentationTime(time.Unix(0, 0), seconds, 1); err != nil || at.Unix() != int64(seconds) {
		t.Fatal("time.Duration overflow")
	}
	// One tick after an instantaneous key window must fail even when the
	// presentation time rounds down to the same displayed nanosecond.
	f := newLiveSegmentFixture(t, math.MaxUint32, 1, 0)
	if err := f.validator.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	base := liveTestEpochSeconds * uint64(math.MaxUint32)
	if r := f.validator.ValidateMediaSegment(context.Background(), bytes.NewReader(f.segment(t, liveTestSequence, base+1, 1))); r.Valid {
		t.Fatal("subnanosecond expiry accepted")
	}
	if r := f.validator.ValidateMediaSegment(context.Background(), bytes.NewReader(f.segment(t, liveTestSequence, base, 1))); !r.Valid {
		t.Fatal(r.Statuses)
	}
}

func TestLiveTrackVersionsAndDefaultDuration(t *testing.T) {
	for _, version := range []byte{0, 1} {
		init := liveTimedInitVersion(7, 90000, 180000, version)
		track, err := liveInitTrack(init, topBox(init, "moov"))
		if err != nil || track.id != 7 || track.timescale != 90000 {
			t.Fatalf("track v%d: %+v %v", version, track, err)
		}
		_, segments := unsignedFragmentedSet(1, fragOpts{sidxVersion: -1})
		tfhd := matchBMFFXPath(context.Background(), parseBMFFBoxes(context.Background(), segments[0]), "/moof/traf/tfhd")[0]
		binary.BigEndian.PutUint32(segments[0][tfhd.start+tfhd.headerLen+4:], 7)
		timing, err := liveSegmentTiming(context.Background(), segments[0], parseBMFFBoxes(context.Background(), segments[0]), track)
		if err != nil || timing.duration != 180000 {
			t.Fatalf("trex duration: %+v %v", timing, err)
		}
	}
}

func TestLiveMediaCancellationAndBoundedHistory(t *testing.T) {
	f := newLiveSegmentFixture(t, 1000, 2000, 10)
	if err := f.validator.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	data := f.segment(t, liveTestSequence, liveTestEpochSeconds*1000, math.MaxUint32)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := f.validator.ValidateMediaSegment(ctx, bytes.NewReader(data)); r.Valid || f.validator.init.seen {
		t.Fatal("cancellation admitted segment")
	}
	f.validator.init.eventIDs = make(map[uint32]struct{}, maxLiveEventIDs)
	for i := uint32(0); i < maxLiveEventIDs; i++ {
		f.validator.init.eventIDs[i] = struct{}{}
	}
	if r := f.validator.ValidateMediaSegment(context.Background(), bytes.NewReader(data)); r.Valid || f.validator.init.seen {
		t.Fatal("history limit ignored")
	}
	var empty LiveMediaValidator
	if r := empty.ValidateMediaSegment(context.Background(), bytes.NewReader(data)); r.Valid || !r.Has(StatusLiveVideoInitInvalid) {
		t.Fatal("uninitialized session admitted media")
	}
}

func TestLiveTrackRejectsAmbiguity(t *testing.T) {
	base := liveTimedInit(7, 90000, 180000)
	moov := topBox(base, "moov")
	trak, _ := liveChild(moov.children, "trak")
	tkhd, _ := liveChild(trak.children, "tkhd")
	mdia, _ := liveChild(trak.children, "mdia")
	mdhd, _ := liveChild(mdia.children, "mdhd")
	for _, kind := range []string{"multiple tracks", "edits", "zero timescale", "wrong defaults"} {
		t.Run(kind, func(t *testing.T) {
			bad := bytes.Clone(base)
			switch kind {
			case "multiple tracks":
				bad = synthBox("moov", base[trak.start:trak.end], base[trak.start:trak.end])
			case "edits":
				bad = synthBox("moov", synthBox("trak", base[tkhd.start:tkhd.end], base[mdia.start:mdia.end], synthBox("edts")))
			case "zero timescale":
				binary.BigEndian.PutUint32(bad[mdhd.start+mdhd.headerLen+12:], 0)
			case "wrong defaults":
				trex := matchBMFFXPath(context.Background(), parseBMFFBoxes(context.Background(), bad), "/moov/mvex/trex")[0]
				binary.BigEndian.PutUint32(bad[trex.start+trex.headerLen+4:], 8)
			}
			if _, err := liveInitTrack(bad, topBox(bad, "moov")); err == nil {
				t.Fatal("ambiguous track metadata accepted")
			}
		})
	}
}

func TestLiveRunTimingValidation(t *testing.T) {
	ctx := context.Background()
	// Per-sample durations override track defaults, and several runs can be summed.
	run := []byte{0, 0, 1, 0, 0, 0, 0, 2, 0, 0, 0, 10, 0, 0, 0, 20}
	if got, err := liveRunPresentation(ctx, run, 999, 0); err != nil || got.duration != 30 {
		t.Fatalf("sample duration: %+v %v", got, err)
	}
	for _, bad := range [][]byte{run[:len(run)-1], append(bytes.Clone(run), 0), {0, 0, 0, 0, 0, 0, 0, 1}, {0, 0, 0, 0, 0, 16, 0, 1}} {
		if _, err := liveRunPresentation(ctx, bad, 0, 0); err == nil {
			t.Fatal("malformed duration run accepted")
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := liveRunPresentation(ctx, run, 2000, 0); err != context.Canceled {
		t.Fatal("sample parsing ignored cancellation")
	}
}

func FuzzLiveTiming(f *testing.F) {
	source := liveMediaSource(uint32(liveTestSequence), liveTestEpochSeconds*90000, 7, 180000, 0)
	trun := matchBMFFXPath(context.Background(), parseBMFFBoxes(context.Background(), source), "/moof/traf/trun")[0]
	f.Add(source, false)
	f.Add(source[trun.start+trun.headerLen:trun.end], true)
	f.Add([]byte{0}, true)
	files := loadLivesim2(f)
	captured := files["880000021.m4s"]
	capturedRun := matchBMFFXPath(context.Background(), parseBMFFBoxes(context.Background(), captured), "/moof/traf/trun")[0]
	f.Add(captured[capturedRun.start+capturedRun.headerLen:capturedRun.end], true)
	f.Fuzz(func(t *testing.T, data []byte, run bool) {
		if len(data) > maxLiveSessionAssertion {
			return
		}
		if run {
			_, _ = liveRunPresentation(context.Background(), data, 180000, 1<<32)
			return
		}
		top, err := liveSegmentBoxes(context.Background(), data)
		if err == nil {
			_, _ = liveSegmentTiming(context.Background(), data, top, liveTrack{id: 7, timescale: 90000, defaultDuration: 180000})
		}
	})
}
