package c2pa

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
)

type liveEvent struct {
	timescale uint32
	duration  uint32
	id        uint32
	payload   []byte
}

func encodeLiveEMSG(event liveEvent) ([]byte, error) {
	if event.timescale == 0 || event.duration == 0 || len(event.payload) == 0 || len(event.payload) > maxLiveSessionAssertion {
		return nil, errors.New("invalid VSI event timing or payload size")
	}
	size := 8 + 4 + len(liveVSIScheme) + 1 + len("fseg") + 1 + 16 + len(event.payload)
	out := binary.BigEndian.AppendUint32(nil, uint32(size))
	out = append(out, "emsg"...)
	out = append(out, 0, 0, 0, 0)
	out = append(out, liveVSIScheme...)
	out = append(out, 0)
	out = append(out, "fseg"...)
	out = append(out, 0)
	out = binary.BigEndian.AppendUint32(out, event.timescale)
	out = binary.BigEndian.AppendUint32(out, 0) // presentation_time_delta
	out = binary.BigEndian.AppendUint32(out, event.duration)
	out = binary.BigEndian.AppendUint32(out, event.id)
	return append(out, event.payload...), nil
}

// Unrelated events (including v1 SCTE-35) stay opaque and covered by the hash.
// An exact VSI scheme with wrong value/flags/timing is an error, not an event
// that the caller can silently ignore. Hash exclusion lookalikes are checked by
// liveVSIHash as well, even if their scheme or version is not recognized here.
func parseLiveEMSG(data []byte, b *bmffBox) (event liveEvent, isVSI bool, err error) {
	if b.typ != "emsg" {
		return event, false, nil
	}
	p := data[b.start+b.headerLen : b.end]
	if len(p) < 4 {
		return event, false, nil
	}
	if p[0] != 0 {
		// v1 moves scheme_id_uri after 20 bytes of timing metadata. A v1
		// event explicitly claiming the VSI scheme is invalid, even though
		// unrelated v1 events such as SCTE-35 remain supported as opaque data.
		if p[0] == 1 && len(p) > 24 {
			end := bytes.IndexByte(p[24:], 0)
			if end >= 0 && string(p[24:24+end]) == liveVSIScheme {
				return event, true, errors.New("VSI emsg must use version 0")
			}
		}
		return event, false, nil
	}
	uriEnd := bytes.IndexByte(p[4:], 0)
	if uriEnd < 0 {
		return event, false, nil
	}
	uriEnd += 4
	if string(p[4:uriEnd]) != liveVSIScheme {
		return event, false, nil
	}
	isVSI = true
	if b.headerLen != 8 || !bytes.Equal(p[:4], []byte{0, 0, 0, 0}) {
		return event, true, errors.New("unsupported VSI emsg header")
	}
	p = p[uriEnd+1:]
	valueEnd := bytes.IndexByte(p, 0)
	if valueEnd < 0 || string(p[:valueEnd]) != "fseg" {
		return event, true, errors.New("invalid VSI emsg value")
	}
	p = p[valueEnd+1:]
	if len(p) <= 16 || len(p)-16 > maxLiveSessionAssertion {
		return event, true, errors.New("invalid VSI emsg timing or payload size")
	}
	event.timescale = binary.BigEndian.Uint32(p)
	delta := binary.BigEndian.Uint32(p[4:])
	event.duration = binary.BigEndian.Uint32(p[8:])
	event.id = binary.BigEndian.Uint32(p[12:])
	if delta != 0 || event.timescale == 0 || event.duration == 0 {
		return event, true, errors.New("invalid VSI emsg timing")
	}
	event.payload = p[16:]
	return event, true, nil
}

func liveSegmentBoxes(ctx context.Context, data []byte) ([]*bmffBox, error) {
	if len(data) == 0 || len(data) > ValidateMaxScan {
		return nil, errors.New("invalid live segment size")
	}
	top := parseBMFFBoxes(ctx, data)
	var complete func([]*bmffBox, int, int) error
	complete = func(boxes []*bmffBox, start, end int) error {
		at := start
		for _, b := range boxes {
			if err := ctx.Err(); err != nil {
				return err
			}
			if b.start != at {
				return errors.New("incomplete live segment structure")
			}
			if bmffContainers[b.typ] || bmffFullBoxContainers[b.typ] {
				p := b.start + b.headerLen
				if bmffFullBoxContainers[b.typ] {
					p += 4
				}
				if p > b.end {
					return errors.New("truncated live container")
				}
				if err := complete(b.children, p, b.end); err != nil {
					return err
				}
			}
			at = b.end
		}
		if at != end {
			return errors.New("incomplete live segment structure")
		}
		return nil
	}
	if err := complete(top, 0, len(data)); err != nil {
		return nil, err
	}
	return top, ctx.Err()
}

// insertLiveEMSG supports one moof/mdat pair, one optional single-level sidx,
// and leading styp/prft. Unsupported layouts fail before modifying any input.
func insertLiveEMSG(ctx context.Context, source, event []byte) ([]byte, int, error) {
	if len(source) > ValidateMaxScan-len(event) {
		return nil, 0, errors.New("live segment exceeds size limit")
	}
	top, err := liveSegmentBoxes(ctx, source)
	if err != nil {
		return nil, 0, err
	}
	var moof, mdat, sidx *bmffBox
	at := 0
	preamble := true
	for i, b := range top {
		_, isVSI, err := parseLiveEMSG(source, b)
		if err != nil || isVSI {
			return nil, 0, errors.New("source already contains VSI or an invalid VSI event")
		}
		switch b.typ {
		case "ftyp", "moov", "ssix":
			return nil, 0, errors.New("unsupported live media segment layout")
		case "styp":
			if i != 0 {
				return nil, 0, errors.New("styp must be first")
			}
		case "sidx":
			if !preamble || sidx != nil {
				return nil, 0, errors.New("unsupported live segment indexes")
			}
			sidx = b
		case "prft":
			if !preamble {
				return nil, 0, errors.New("prft must precede VSI insertion")
			}
		case "moof":
			if moof != nil {
				return nil, 0, errors.New("multiple moof boxes are not supported by VSI authoring yet")
			}
			moof = b
		case "mdat":
			if mdat != nil {
				return nil, 0, errors.New("multiple mdat boxes are not supported by VSI authoring yet")
			}
			mdat = b
		}
		if preamble && (b.typ == "styp" || b.typ == "sidx" || b.typ == "prft") {
			at = b.end
		} else {
			preamble = false
		}
	}
	if moof == nil || mdat == nil || moof.start >= mdat.start {
		return nil, 0, errors.New("live segment requires moof followed by mdat")
	}
	out := make([]byte, 0, len(source)+len(event))
	out = append(out, source[:at]...)
	out = append(out, event...)
	out = append(out, source[at:]...)
	remap := func(off int) (int, bool) {
		if off < 0 || off > len(source) {
			return 0, false
		}
		if off >= at {
			return off + len(event), true
		}
		return off, true
	}
	if sidx != nil {
		if err := patchLiveSidx(source, out, sidx, at, len(event)); err != nil {
			return nil, 0, err
		}
	}
	for _, traf := range moof.children {
		if traf.typ != "traf" {
			continue
		}
		for _, b := range traf.children {
			if b.typ != "tfhd" {
				continue
			}
			p := b.start + b.headerLen
			if p+8 > b.end || source[p] != 0 {
				return nil, 0, errors.New("invalid tfhd")
			}
			flags := uint32(source[p+1])<<16 | uint32(source[p+2])<<8 | uint32(source[p+3])
			if flags&1 == 0 && flags&0x020000 == 0 {
				return nil, 0, errors.New("implicit tfhd bases are not supported for VSI insertion")
			}
			if flags&1 != 0 {
				if p+16 > b.end || binary.BigEndian.Uint64(source[p+8:]) < uint64(at) {
					return nil, 0, errors.New("tfhd base before VSI insertion is unsupported")
				}
				if err := patchTfhdBase(source, out, b, remap, remap); err != nil {
					return nil, 0, err
				}
			}
		}
	}
	return out, at, ctx.Err()
}

// Preserve each sidx reference's original target bytes. If VSI is inserted at
// the start of, or inside, a referenced subsegment, include it in that reference.
// If it precedes the indexed range, adjust first_offset instead. Hierarchical
// indexes and out-of-file ranges need a packager-aware rewrite and are refused.
func patchLiveSidx(old, out []byte, b *bmffBox, at, added int) error {
	p := b.start + b.headerLen
	if p+4 > b.end || old[p] > 1 || !bytes.Equal(old[p+1:p+4], []byte{0, 0, 0}) {
		return errors.New("invalid sidx header")
	}
	w, offset := 4, p+16
	if old[p] == 1 {
		w, offset = 8, p+20
	}
	countAt := offset + w + 2
	if countAt+2 > b.end {
		return errors.New("truncated sidx")
	}
	first := uint64(binary.BigEndian.Uint32(old[offset:]))
	if w == 8 {
		first = binary.BigEndian.Uint64(old[offset:])
	}
	count := int(binary.BigEndian.Uint16(old[countAt:]))
	if count == 0 || b.end-(countAt+2) != count*12 || first > uint64(len(old)-b.end) {
		return errors.New("unsupported sidx references")
	}
	start := b.end + int(first)
	if at < start {
		first += uint64(added)
		if w == 4 && first > math.MaxUint32 {
			return errors.New("sidx first_offset overflow")
		}
		putN(out, offset, w, first)
	}
	for i := 0; i < count; i++ {
		field := countAt + 2 + i*12
		raw := binary.BigEndian.Uint32(old[field:])
		if raw>>31 != 0 {
			return errors.New("hierarchical sidx is unsupported")
		}
		size := int(raw & 0x7fffffff)
		if size == 0 || size > len(old)-start {
			return errors.New("sidx reference exceeds segment")
		}
		if at >= start && at < start+size {
			if added > math.MaxInt32-size {
				return errors.New("sidx referenced_size overflow")
			}
			binary.BigEndian.PutUint32(out[field:], uint32(size+added))
		}
		start += size
	}
	return nil
}
