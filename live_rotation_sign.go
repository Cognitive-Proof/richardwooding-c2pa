package c2pa

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

type liveSigningKey struct {
	key     liveSessionKey
	private ed25519.PrivateKey
}

func (s *LiveMediaSigner) sessionKeys() []liveSessionKey {
	keys := make([]liveSessionKey, len(s.schedule))
	for i, k := range s.schedule {
		keys[i] = k.key
	}
	return keys
}

// AddSessionKey schedules another Ed25519 key. Before initialization it is
// included in the init; afterwards SignMediaSegmentWithManifest must announce
// the schedule before ordinary signing resumes. IDs must be unique. Failure
// preserves the schedule. Config byte slices are copied as by the constructor.
func (s *LiveMediaSigner) AddSessionKey(cfg LiveMediaSignerConfig) error {
	if s == nil || s.manifestSigner == nil {
		return errors.New("live signer is not configured")
	}
	if len(s.schedule) >= maxLiveSessionKeys {
		return errors.New("session key schedule limit reached")
	}
	added, err := NewLiveMediaSigner(s.manifestSigner, cfg)
	if err != nil {
		return err
	}
	for _, k := range s.schedule {
		if bytes.Equal(k.key.kid, added.key.kid) {
			return errors.New("duplicate session key ID")
		}
	}
	if s.Initialized() && s.validator.init.seen && added.key.minSequence <= s.validator.init.lastSequence {
		return errors.New("new key minimum must follow the last signed sequence")
	}
	keys := append(s.sessionKeys(), added.key)
	if _, err := encodeLiveSessionKeys(keys); err != nil {
		return err
	}
	s.schedule = append(s.schedule, liveSigningKey{key: added.key, private: added.private})
	if s.Initialized() {
		s.needsAnnouncement = true
	}
	return nil
}

// Prefer the eligible key with the largest minimum sequence (latest added on
// ties), evaluating both sequence and actual sample presentation time.
func (s *LiveMediaSigner) keyForSegment(sequence, ticks uint64) (liveSigningKey, error) {
	at, sub, err := livePresentationTime(*s.validator.init.origin, ticks, s.validator.init.track.timescale)
	if err != nil {
		return liveSigningKey{}, err
	}
	var chosen *liveSigningKey
	for i := range s.schedule {
		k := &s.schedule[i]
		// permits uses checked seconds rather than time.Duration for long windows.
		if !k.key.permits(sequence, at) {
			continue
		}
		if sub && at.Unix() == k.key.created.Unix()+int64(k.key.validity) && at.Nanosecond() == k.key.created.Nanosecond() {
			continue
		}
		if chosen == nil || k.key.minSequence >= chosen.key.minSequence {
			chosen = k
		}
	}
	if chosen == nil {
		return liveSigningKey{}, errors.New("no session key permits segment sequence and presentation time")
	}
	return *chosen, nil
}

// liveAnnouncementBindingWriter reuses the normal signing pipeline with a
// media-segment embedder and a selective VSI exclusion to break the hash cycle:
// manifest binds media, VSI binds media AND the final signed manifest.
type liveAnnouncementBindingWriter struct {
	bmffFlatBinding
	checked *ValidationResult
}

func (b liveAnnouncementBindingWriter) validateOutput(ctx context.Context, data []byte, opts []ValidateOption) ValidationResult {
	r := b.bmffFlatBinding.validateOutput(ctx, data, opts)
	if b.checked != nil {
		*b.checked = r
	}
	return r
}

func (b liveAnnouncementBindingWriter) embedder() embedder { return liveAnnouncementEmbedder{} }
func announcementExclusions() []any                        { return append(bmffStandardExclusions(), liveVSIExclusions()...) }
func (b liveAnnouncementBindingWriter) payload(_ []byteRange, digest []byte) ([]byte, error) {
	return encMode.Marshal(map[string]any{"alg": b.alg, "hash": digest, "exclusions": announcementExclusions()})
}
func (b liveAnnouncementBindingWriter) digest(ctx context.Context, data []byte, _ []byteRange) ([]byte, error) {
	h, ok := hashByName(b.alg)
	if !ok {
		return nil, errors.New("unsupported announcement hash")
	}
	ex, _ := decodeBMFFExclusions(announcementExclusions())
	seg, ok := newBMFFSegment(ctx, data, ex)
	if !ok {
		return nil, errors.New("invalid announcement segment")
	}
	if err := hashBMFFTopLevel(ctx, data, seg.top, seg.ranges, h); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
func (b liveAnnouncementBindingWriter) compareRanges(ctx context.Context, data []byte, _ []byteRange) ([]byteRange, error) {
	ex, _ := decodeBMFFExclusions(announcementExclusions())
	seg, ok := newBMFFSegment(ctx, data, ex)
	if !ok {
		return nil, errors.New("invalid announcement layout")
	}
	return seg.ranges, ctx.Err()
}

type liveAnnouncementEmbedder struct{}

func (liveAnnouncementEmbedder) embed(ctx context.Context, asset, store []byte) ([]byte, []byteRange, error) {
	top, err := liveSegmentBoxes(ctx, asset)
	if err != nil {
		return nil, nil, err
	}
	at := 0
	if len(top) > 0 && top[0].typ == "styp" {
		at = top[0].end
	}
	for _, b := range top {
		if b.typ == "sidx" || b.typ == "ssix" || b.typ == "mfra" || b.typ == "ftyp" || b.typ == "moov" || (b.typ == "uuid" && b.usertype == c2paBoxUUID) {
			return nil, nil, errors.New("unsupported announcement layout or existing manifest")
		}
		if b.typ == "moof" {
			for _, traf := range b.children {
				for _, tfhd := range traf.children {
					if tfhd.typ != "tfhd" {
						continue
					}
					p := tfhd.start + tfhd.headerLen
					if p+8 > tfhd.end {
						return nil, nil, errors.New("truncated tfhd")
					}
					flags := binary.BigEndian.Uint32(asset[p:p+4]) & 0xffffff
					if flags&1 != 0 || flags&0x020000 == 0 {
						return nil, nil, errors.New("announcements require moof-relative sample addressing")
					}
				}
			}
		}
	}
	box, err := c2paBoxBytes("manifest", store)
	if err != nil {
		return nil, nil, err
	}
	if len(asset) >= ValidateMaxScan-len(box) {
		return nil, nil, ErrAssetTooLarge
	}
	out := make([]byte, 0, len(asset)+len(box))
	out = append(out, asset[:at]...)
	out = append(out, box...)
	out = append(out, asset[at:]...)
	return out, nil, ctx.Err()
}

// SignMediaSegmentWithManifest announces the full current schedule in a new
// standard C2PA manifest and signs this segment's VSI. Earlier associations,
// sequence/event history and media-time origin survive. Announcements support
// unindexed segments with moof-relative addressing; indexed/absolute-base inputs
// fail without output. Manifest signing retains the normal TSA/identity policy.
func (s *LiveMediaSigner) SignMediaSegmentWithManifest(ctx context.Context, input io.Reader, m Manifest) (output []byte, err error) {
	defer func() {
		if err != nil {
			if canceled := ctx.Err(); canceled != nil {
				err = canceled
			}
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !s.Initialized() || s.validator.init.origin == nil {
		return nil, errors.New("initialized signer and media-time origin required")
	}
	if input == nil {
		return nil, ErrNoInput
	}
	for _, a := range m.Assertions {
		if a.Label == liveSessionKeysLabel || strings.HasPrefix(a.Label, liveSessionKeysLabel+"__") {
			return nil, ErrManifestInvalid
		}
	}
	if err := validateManifest(m); err != nil {
		return nil, err
	}
	asset, err := readWholeAsset(ctx, input)
	if err != nil {
		return nil, err
	}
	top, err := liveSegmentBoxes(ctx, asset)
	if err != nil {
		return nil, err
	}
	timing, err := liveSegmentTiming(ctx, asset, top, s.validator.init.track)
	if err != nil {
		return nil, err
	}
	if timing.duration > math.MaxUint32 {
		return nil, errors.New("announcement duration exceeds emsg capacity")
	}
	for _, k := range s.schedule {
		if !s.validator.init.knowsKey(k.key) && k.key.minSequence < uint64(timing.sequence) {
			return nil, errors.New("new key minimum predates announcement segment")
		}
	}
	selected, err := s.keyForSegment(uint64(timing.sequence), timing.presentationStart)
	if err != nil {
		return nil, err
	}
	placeholderID, err := newManifestLabel(s.manifestSigner.cfg.vendor)
	if err != nil {
		return nil, err
	}
	draft, err := buildLiveVSISegment(ctx, asset, selected.private, selected.key.kid, placeholderID, uint64(timing.sequence), liveEvent{timescale: s.validator.init.track.timescale, duration: uint32(timing.duration), id: s.nextEventID})
	if err != nil {
		return nil, err
	}
	keys, err := encodeLiveSessionKeys(s.sessionKeys())
	if err != nil {
		return nil, err
	}
	m.Assertions = append(append([]Assertion(nil), m.Assertions...), Assertion{Label: liveSessionKeysLabel, Value: cbor.RawMessage(keys)})
	var checked ValidationResult
	final, err := s.manifestSigner.sign(ctx, BMFF, draft, m, liveAnnouncementBindingWriter{bmffFlatBinding: bmffFlatBinding{alg: s.manifestSigner.cfg.hashAlg}, checked: &checked})
	if err != nil {
		return nil, err
	}
	manifest := parseStore(ctx, extractJUMBF(ctx, BMFF, final)).active()
	if manifest == nil {
		return nil, ErrSelfCheckFailed
	}
	// Finalize only the excluded VSI bytes, leaving the verified manifest intact.
	var eventBox *bmffBox
	var event liveEvent
	for _, b := range parseBMFFBoxes(ctx, final) {
		e, yes, err := parseLiveEMSG(final, b)
		if err != nil {
			return nil, err
		}
		if yes {
			eventBox = b
			event = e
		}
	}
	if eventBox == nil {
		return nil, ErrSelfCheckFailed
	}
	ex, _ := decodeBMFFExclusions(liveVSIExclusions())
	digest, err := liveVSIHash(ctx, final, "sha256", ex)
	if err != nil {
		return nil, err
	}
	hash, err := encMode.Marshal(map[string]any{"alg": "sha256", "hash": digest, "exclusions": liveVSIExclusions()})
	if err != nil {
		return nil, err
	}
	event.payload, err = signLiveVSI(selected.private, selected.key.kid, liveVSIInfo{sequence: uint64(timing.sequence), manifestID: manifest.label, bmffHash: hash})
	if err != nil {
		return nil, err
	}
	encoded, err := encodeLiveEMSG(event)
	if err != nil {
		return nil, err
	}
	if len(encoded) != eventBox.end-eventBox.start {
		return nil, errors.New("announcement VSI layout changed")
	}
	copy(final[eventBox.start:eventBox.end], encoded)
	store := bytes.Clone(extractJUMBF(ctx, BMFF, final))
	// Only excluded VSI bytes changed after the pipeline's manifest self-check.
	// Reuse that verified result, including its configured TSA/identity trust,
	// while independently checking all live rules on a transactional candidate.
	candidate := &LiveMediaValidator{cfg: s.validator.cfg}
	candidate.init = s.validator.init
	result := candidate.validateMediaSegment(ctx, bytes.NewReader(final), &checked)
	if !result.Valid {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: announcement: %+v", ErrSelfCheckFailed, result.Statuses)
	}
	s.validator.init = candidate.init
	s.manifestStore = store
	s.manifestRef = nil
	s.needsAnnouncement = false
	s.nextEventID++
	return final, nil
}
