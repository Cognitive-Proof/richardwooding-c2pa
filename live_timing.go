package c2pa

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"time"
)

type liveTrack struct{ id, timescale, defaultDuration uint32 }
type liveTiming struct {
	sequence          uint32
	start, duration   uint64
	presentationStart uint64
}

func liveChild(boxes []*bmffBox, typ string) (*bmffBox, error) {
	var found *bmffBox
	for _, b := range boxes {
		if b.typ == typ {
			if found != nil {
				return nil, errors.New("duplicate " + typ + " box")
			}
			found = b
		}
	}
	if found == nil {
		return nil, errors.New("missing " + typ + " box")
	}
	return found, nil
}

func liveInitTrack(data []byte, moov *bmffBox) (liveTrack, error) {
	var track liveTrack
	trak, err := liveChild(moov.children, "trak")
	if err != nil {
		return track, err
	}
	for _, b := range trak.children {
		if b.typ == "edts" {
			return track, errors.New("live edit lists are not supported by this profile")
		}
	}
	tkhd, err := liveChild(trak.children, "tkhd")
	if err != nil {
		return track, err
	}
	p := data[tkhd.start+tkhd.headerLen : tkhd.end]
	if len(p) < 4 {
		return track, errors.New("truncated tkhd")
	}
	offset, size := 12, 84
	if p[0] == 1 {
		offset, size = 20, 96
	} else if p[0] != 0 {
		return track, errors.New("unsupported tkhd version")
	}
	if len(p) != size {
		return track, errors.New("invalid tkhd size")
	}
	track.id = binary.BigEndian.Uint32(p[offset:])
	mdia, err := liveChild(trak.children, "mdia")
	if err != nil {
		return track, err
	}
	mdhd, err := liveChild(mdia.children, "mdhd")
	if err != nil {
		return track, err
	}
	p = data[mdhd.start+mdhd.headerLen : mdhd.end]
	if len(p) < 4 || p[1] != 0 || p[2] != 0 || p[3] != 0 {
		return track, errors.New("invalid mdhd")
	}
	offset, size = 12, 24
	if p[0] == 1 {
		offset, size = 20, 36
	} else if p[0] != 0 {
		return track, errors.New("unsupported mdhd version")
	}
	if len(p) != size {
		return track, errors.New("invalid mdhd size")
	}
	track.timescale = binary.BigEndian.Uint32(p[offset:])
	if track.id == 0 || track.timescale == 0 {
		return track, errors.New("track ID and timescale must be nonzero")
	}
	// trex is optional when every trun/tfhd supplies its sample durations.
	seenMvex := false
	for _, mvex := range moov.children {
		if mvex.typ != "mvex" {
			continue
		}
		if seenMvex {
			return track, errors.New("duplicate mvex")
		}
		seenMvex = true
		trex, err := liveChild(mvex.children, "trex")
		if err != nil {
			return track, err
		}
		p := data[trex.start+trex.headerLen : trex.end]
		if len(p) != 24 || binary.BigEndian.Uint32(p) != 0 || binary.BigEndian.Uint32(p[4:]) != track.id {
			return track, errors.New("invalid trex track defaults")
		}
		track.defaultDuration = binary.BigEndian.Uint32(p[12:])
	}
	return track, nil
}

func liveSegmentTiming(ctx context.Context, data []byte, top []*bmffBox, track liveTrack) (timing liveTiming, err error) {
	moof, err := liveChild(top, "moof")
	if err != nil {
		return timing, err
	}
	mdat, err := liveChild(top, "mdat")
	if err != nil {
		return timing, err
	}
	if mdat.start < moof.end || mdat.end-mdat.start <= mdat.headerLen {
		return timing, errors.New("segment requires media after moof")
	}
	mfhd, err := liveChild(moof.children, "mfhd")
	if err != nil {
		return timing, err
	}
	p := data[mfhd.start+mfhd.headerLen : mfhd.end]
	if len(p) != 8 || binary.BigEndian.Uint32(p) != 0 {
		return timing, errors.New("invalid mfhd")
	}
	timing.sequence = binary.BigEndian.Uint32(p[4:])
	traf, err := liveChild(moof.children, "traf")
	if err != nil {
		return timing, err
	}
	tfhd, err := liveChild(traf.children, "tfhd")
	if err != nil {
		return timing, err
	}
	p = data[tfhd.start+tfhd.headerLen : tfhd.end]
	if len(p) < 8 || p[0] != 0 || binary.BigEndian.Uint32(p[4:]) != track.id {
		return timing, errors.New("tfhd does not identify authenticated track")
	}
	flags := binary.BigEndian.Uint32(p) & 0xffffff
	if flags & ^uint32(0x02003b) != 0 {
		return timing, errors.New("unsupported tfhd flags")
	}
	at := 8
	if flags&1 != 0 {
		at += 8
	}
	if flags&2 != 0 {
		at += 4
	}
	defaultDuration := track.defaultDuration
	if flags&8 != 0 {
		if at+4 > len(p) {
			return timing, errors.New("truncated tfhd duration")
		}
		defaultDuration = binary.BigEndian.Uint32(p[at:])
		at += 4
	}
	if flags&16 != 0 {
		at += 4
	}
	if flags&32 != 0 {
		at += 4
	}
	if at != len(p) {
		return timing, errors.New("invalid tfhd fields")
	}
	tfdt, err := liveChild(traf.children, "tfdt")
	if err != nil {
		return timing, err
	}
	p = data[tfdt.start+tfdt.headerLen : tfdt.end]
	if len(p) < 4 || p[1] != 0 || p[2] != 0 || p[3] != 0 {
		return timing, errors.New("invalid tfdt")
	}
	switch {
	case p[0] == 0 && len(p) == 8:
		timing.start = uint64(binary.BigEndian.Uint32(p[4:]))
	case p[0] == 1 && len(p) == 12:
		timing.start = binary.BigEndian.Uint64(p[4:])
	default:
		return timing, errors.New("invalid tfdt version or size")
	}
	runs := 0
	var samples uint64
	var decoded, presentationEnd uint64
	timing.presentationStart = math.MaxUint64
	for _, b := range traf.children {
		if b.typ != "trun" {
			continue
		}
		runs++
		raw := data[b.start+b.headerLen : b.end]
		if len(raw) < 8 {
			return timing, errors.New("truncated trun")
		}
		samples += uint64(binary.BigEndian.Uint32(raw[4:]))
		if samples > 1<<20 {
			return timing, errors.New("segment sample count exceeds limit")
		}
		if decoded > math.MaxUint64-timing.start {
			return timing, errors.New("decode-time overflow")
		}
		run, err := liveRunPresentation(ctx, raw, defaultDuration, timing.start+decoded)
		if err != nil {
			return timing, err
		}
		if run.duration > math.MaxUint64-decoded {
			return timing, errors.New("segment duration overflow")
		}
		decoded += run.duration
		if run.first < timing.presentationStart {
			timing.presentationStart = run.first
		}
		if run.end > presentationEnd {
			presentationEnd = run.end
		}
	}
	if runs == 0 || decoded == 0 || timing.start > math.MaxUint64-decoded || presentationEnd <= timing.presentationStart {
		return timing, errors.New("invalid segment duration or decode-time range")
	}
	timing.duration = presentationEnd - timing.presentationStart
	return timing, ctx.Err()
}

type liveRunExtent struct{ duration, first, end uint64 }

// trun v0 composition offsets are unsigned; v1 offsets are signed. Compute the
// earliest sample PTS and latest presentation end across decode-ordered samples,
// not just the first sample's offset. The caller carries DTS across runs.
func liveRunPresentation(ctx context.Context, p []byte, fallback uint32, decodeStart uint64) (extent liveRunExtent, err error) {
	extent.first = math.MaxUint64
	if len(p) < 8 || p[0] > 1 {
		return extent, errors.New("invalid trun")
	}
	flags := binary.BigEndian.Uint32(p) & 0xffffff
	if flags & ^uint32(0xf05) != 0 {
		return extent, errors.New("unsupported trun flags")
	}
	if flags&4 != 0 && flags&0x400 != 0 {
		return extent, errors.New("conflicting trun sample flags")
	}
	count := binary.BigEndian.Uint32(p[4:])
	if count == 0 || count > 1<<20 {
		return extent, errors.New("unsupported trun sample count")
	}
	at := 8
	if flags&1 != 0 {
		at += 4
	}
	if flags&4 != 0 {
		at += 4
	}
	width := 0
	for _, bit := range []uint32{0x100, 0x200, 0x400, 0x800} {
		if flags&bit != 0 {
			width += 4
		}
	}
	if at > len(p) || uint64(count)*uint64(width) != uint64(len(p)-at) {
		return extent, errors.New("truncated or trailing trun sample data")
	}
	for i := uint32(0); i < count; i++ {
		if err := ctx.Err(); err != nil {
			return extent, err
		}
		duration := fallback
		if flags&0x100 != 0 {
			duration = binary.BigEndian.Uint32(p[at:])
			at += 4
		}
		if duration == 0 {
			return extent, errors.New("missing or zero sample duration")
		}
		if flags&0x200 != 0 {
			at += 4
		}
		if flags&0x400 != 0 {
			at += 4
		}
		var composition int64
		if flags&0x800 != 0 {
			composition = int64(binary.BigEndian.Uint32(p[at:]))
			if p[0] == 1 {
				composition = int64(int32(binary.BigEndian.Uint32(p[at:])))
			}
			at += 4
		}
		if extent.duration > math.MaxUint64-decodeStart {
			return extent, errors.New("sample decode-time overflow")
		}
		decode := decodeStart + extent.duration
		if uint64(duration) > math.MaxUint64-decode {
			return extent, errors.New("sample decode-end overflow")
		}
		pts := decode
		if composition < 0 {
			if uint64(-composition) > pts {
				return extent, errors.New("negative absolute presentation time is unsupported")
			}
			pts -= uint64(-composition)
		} else {
			if uint64(composition) > math.MaxUint64-pts {
				return extent, errors.New("sample presentation-time overflow")
			}
			pts += uint64(composition)
		}
		if uint64(duration) > math.MaxUint64-pts || uint64(duration) > math.MaxUint64-extent.duration {
			return extent, errors.New("sample presentation-end overflow")
		}
		if pts < extent.first {
			extent.first = pts
		}
		if pts+uint64(duration) > extent.end {
			extent.end = pts + uint64(duration)
		}
		extent.duration += uint64(duration)
	}
	return extent, nil
}

// Map ticks without time.Duration's ~292-year overflow or floating-point loss.
// subNano records a positive fractional nanosecond so key-window checks remain
// exact even when the media timescale exceeds nanosecond resolution.
func livePresentationTime(origin time.Time, ticks uint64, scale uint32) (at time.Time, subNano bool, err error) {
	if scale == 0 || origin.Year() < 0 || origin.Year() > 9999 {
		return at, false, errors.New("invalid presentation-time origin or timescale")
	}
	last := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	seconds := ticks / uint64(scale)
	if origin.After(last) || seconds > uint64(last.Unix()-origin.Unix()) {
		return at, false, errors.New("presentation time outside supported range")
	}
	numerator := (ticks % uint64(scale)) * 1_000_000_000
	at = time.Unix(origin.Unix()+int64(seconds), int64(origin.Nanosecond())+int64(numerator/uint64(scale))).UTC()
	if at.After(last) || (at.Equal(last) && numerator%uint64(scale) != 0) {
		return time.Time{}, false, errors.New("presentation time overflow")
	}
	return at, numerator%uint64(scale) != 0, nil
}
