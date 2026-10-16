package c2pa

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"testing"
	"time"
)

func compositionRun(version byte, durations []uint32, offsets []int64) []byte {
	p := binary.BigEndian.AppendUint32(nil, uint32(version)<<24|0x900)
	p = binary.BigEndian.AppendUint32(p, uint32(len(durations)))
	for i, duration := range durations {
		p = binary.BigEndian.AppendUint32(p, duration)
		p = binary.BigEndian.AppendUint32(p, uint32(offsets[i]))
	}
	return p
}

func TestLiveCompositionPresentation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		version    byte
		start      uint64
		durations  []uint32
		offsets    []int64
		first, end uint64
		invalid    bool
	}{
		{"reordered signed", 1, 100, []uint32{10, 10}, []int64{10, -10}, 100, 120, false},
		{"negative offset", 1, 100, []uint32{10}, []int64{-10}, 90, 100, false},
		{"unsigned high bit", 0, 0, []uint32{1}, []int64{1 << 31}, 1 << 31, (1 << 31) + 1, false},
		{"signed underflow", 1, 0, []uint32{1}, []int64{-1}, 0, 0, true},
		{"signed minimum", 1, 0, []uint32{1}, []int64{math.MinInt32}, 0, 0, true},
		{"composition overflow", 0, math.MaxUint64 - 2, []uint32{1}, []int64{3}, 0, 0, true},
		{"presentation end overflow", 0, math.MaxUint64 - 1, []uint32{2}, []int64{0}, 0, 0, true},
		{"decode end overflow", 1, math.MaxUint64 - 1, []uint32{2}, []int64{-1}, 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run, err := liveRunPresentation(context.Background(), compositionRun(tc.version, tc.durations, tc.offsets), 0, tc.start)
			if (err != nil) != tc.invalid {
				t.Fatalf("extent %+v: %v", run, err)
			}
			if err == nil && (run.first != tc.first || run.end != tc.end) {
				t.Fatalf("extent %+v, want %d..%d", run, tc.first, tc.end)
			}
		})
	}
}

func TestLiveCompositionAcrossRuns(t *testing.T) {
	// Second run DTS must continue after the first run. Its negative offset
	// moves its PTS before the first sample, despite its later decode order.
	data := bytes.Join([][]byte{synthBox("moof",
		synthBox("mfhd", make([]byte, 4), binary.BigEndian.AppendUint32(nil, 1)),
		synthBox("traf",
			synthBox("tfhd", []byte{0, 2, 0, 0}, binary.BigEndian.AppendUint32(nil, 7)),
			synthBox("tfdt", []byte{1, 0, 0, 0}, binary.BigEndian.AppendUint64(nil, 100)),
			synthBox("trun", compositionRun(0, []uint32{10}, []int64{20})),
			synthBox("trun", compositionRun(1, []uint32{10}, []int64{-10})))),
		synthBox("mdat", []byte{1})}, nil)
	timing, err := liveSegmentTiming(context.Background(), data, parseBMFFBoxes(context.Background(), data), liveTrack{id: 7, timescale: 1000})
	if err != nil || timing.start != 100 || timing.presentationStart != 100 || timing.duration != 30 {
		t.Fatalf("run carry/presentation span: %+v %v", timing, err)
	}
}

func TestLiveCompositionControlsKeyWindow(t *testing.T) {
	for _, offset := range []int32{-1, 1} {
		f := newLiveSegmentFixture(t, 1000, 2000, 0)
		if err := f.validator.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
			t.Fatal(err)
		}
		source := liveMediaSource(uint32(liveTestSequence), liveTestEpochSeconds*1000, 7, 2000, offset)
		signed, err := buildLiveVSISegment(context.Background(), source, f.private, []byte("session"), f.validator.ManifestID(), liveTestSequence, liveEvent{timescale: 1000, duration: 2000, id: 1})
		if err != nil {
			t.Fatal(err)
		}
		r := f.validator.ValidateMediaSegment(context.Background(), bytes.NewReader(signed))
		if r.Valid || r.Binding != BindingVerified || f.validator.init.seen {
			t.Fatalf("used decode time instead of PTS for offset %d: %+v", offset, r)
		}
	}
}
