package c2pa

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"
)

// LiveMediaValidator holds the authenticated initialization state of one
// BMFF/CMAF VSI session. The initial profile supports Ed25519 session keys and a
// standard init manifest with a flat c2pa.hash.bmff.v3 binding. One track with
// explicit presentation-time mapping is supported. Methods must not be called concurrently.
// The zero value uses the same trust and validation defaults as Validate.
type LiveMediaValidator struct {
	cfg  *validateConfig
	init *liveMediaInit
}

// liveMediaInit is installed in one assignment after validation completes.
// One initialization and the session policy's bounded authorizing-manifest
// history are retained, each manifest with at most maxLiveSessionKeys keys.
// Neither caller-owned buffers nor certificates returned in results are retained.
type liveMediaInit struct {
	manifestID   string
	keys         map[string]liveSessionKey
	signerDER    []byte
	track        liveTrack
	origin       *time.Time
	seen         bool
	lastSequence uint64
	eventIDs     map[uint32]struct{}
	manifests    map[string]liveKeyManifest
	initData     []byte
	lastEventID  uint32
}

// NewLiveMediaValidator configures manifest validation using Validate's options,
// including WithSigningTrust, WithClock and WithOnlineRevocation.
func NewLiveMediaValidator(opts ...ValidateOption) *LiveMediaValidator {
	cfg := newValidator(context.Background(), BMFF, opts).cfg
	return &LiveMediaValidator{cfg: &cfg}
}

// Initialized reports whether an init segment has been authenticated successfully.
func (l *LiveMediaValidator) Initialized() bool { return l != nil && l.init != nil }

// ManifestID returns the most recently admitted manifest announcement's label,
// initially the init manifest, or "" before initialization. Failures leave it unchanged.
func (l *LiveMediaValidator) ManifestID() string {
	if !l.Initialized() {
		return ""
	}
	return l.init.manifestID
}

// ValidateInitSegment performs general C2PA validation, requires a complete init
// segment with ftyp and moov but no mdat, and checks the entire moov is covered by
// the active manifest's flat BMFF v3 binding. Exactly one signed, native-CBOR
// c2pa.session-keys assertion must bind its keys to that manifest's leaf certificate.
//
// Success begins a new session, replacing the previously admitted init and keys.
// Failure (including cancellation, truncation or untrusted credentials) preserves
// the prior state. The result describes this input, not the retained prior init.
// No key is checked against wall-clock time here: validity windows are evaluated
// against the media segment's presentation time when that segment is validated.
func (l *LiveMediaValidator) ValidateInitSegment(ctx context.Context, r io.Reader) ValidationResult {
	v := newValidator(ctx, BMFF, nil)
	if l != nil && l.cfg != nil {
		v.cfg = *l.cfg
	}
	result := v.run(r)
	if l == nil {
		v.add(StatusGeneralError, "", "nil LiveMediaValidator", nil)
		return v.finish()
	}
	top := parseBMFFBoxes(ctx, v.data)
	moov, err := liveInitStructure(ctx, v.data, top)
	if len(v.data) >= v.cfg.maxScan {
		err = errors.New("initialization reached the scan cap; complete input is required")
	}
	if err != nil {
		v.add(StatusLiveVideoInitInvalid, result.ActiveManifestLabel, err.Error(), err)
		return v.finish()
	}
	if !result.Valid || result.Binding != BindingVerified ||
		!result.hasForActive(StatusClaimSignatureValidated) || !result.hasForActive(StatusSigningCredentialTrusted) {
		v.add(StatusLiveVideoManifestInvalid, result.ActiveManifestLabel, "initialization manifest did not pass signature, trust and asset-binding validation", nil)
		return v.finish()
	}
	m := parseStore(ctx, extractJUMBF(ctx, BMFF, v.data)).active()
	if m == nil || m.update || m.label != result.ActiveManifestLabel {
		v.add(StatusLiveVideoManifestInvalid, result.ActiveManifestLabel, "VSI initialization requires an active standard manifest", nil)
		return v.finish()
	}
	if err := liveInitBinding(ctx, v.data, top, moov, m); err != nil {
		v.add(StatusLiveVideoManifestInvalid, m.label, err.Error(), err)
		return v.finish()
	}
	track, err := liveInitTrack(v.data, moov)
	if err != nil {
		v.add(StatusLiveVideoInitInvalid, m.label, err.Error(), err)
		return v.finish()
	}
	assertion, err := liveInitSessionAssertion(m)
	if err != nil {
		v.add(StatusLiveVideoSessionKeyInvalid, m.label+"/"+liveSessionKeysLabel, err.Error(), err)
		return v.finish()
	}
	if len(result.SignerChain) == 0 || result.SignerChain[0] == nil {
		v.add(StatusLiveVideoManifestInvalid, m.label, "initialization has no authenticated signer certificate", nil)
		return v.finish()
	}
	der := result.SignerChain[0].Raw
	keys, err := decodeLiveSessionKeys(assertion.data, der)
	if err != nil {
		v.add(StatusLiveVideoSessionKeyInvalid, m.label+"/"+liveSessionKeysLabel, "initialization session keys are invalid", err)
		return v.finish()
	}
	next := &liveMediaInit{manifestID: m.label, keys: make(map[string]liveSessionKey, len(keys)), signerDER: append([]byte(nil), der...), track: track}
	for _, k := range keys {
		next.keys[string(k.kid)] = k
	}
	next.recordManifest(m.label, extractJUMBF(ctx, BMFF, v.data))
	next.setManifestChain(m.label, result.SignerChain)
	next.initData = append([]byte(nil), v.data...)
	// finish checks cancellation again before any state is changed.
	result = v.finish()
	if result.Valid {
		l.init = next
	}
	return result
}

// The shared box parser is deliberately best-effort. Initialization needs a
// complete structure at every container level, not just a parseable prefix.
func liveInitStructure(ctx context.Context, data []byte, top []*bmffBox) (*bmffBox, error) {
	var moov *bmffBox
	ftyp := 0
	var walk func([]*bmffBox, int, int) error
	walk = func(boxes []*bmffBox, start, end int) error {
		at := start
		for _, b := range boxes {
			if err := ctx.Err(); err != nil {
				return err
			}
			if b.start != at {
				return errors.New("incomplete initialization box structure")
			}
			if b.typ == "mdat" {
				return errors.New("initialization segment contains mdat")
			}
			if bmffContainers[b.typ] || bmffFullBoxContainers[b.typ] {
				childStart := b.start + b.headerLen
				if bmffFullBoxContainers[b.typ] {
					childStart += 4
				}
				if childStart > b.end {
					return errors.New("truncated initialization container")
				}
				if err := walk(b.children, childStart, b.end); err != nil {
					return err
				}
			}
			at = b.end
		}
		if at != end {
			return errors.New("incomplete initialization box structure")
		}
		return nil
	}
	if err := walk(top, 0, len(data)); err != nil {
		return nil, err
	}
	for _, b := range top {
		switch b.typ {
		case "ftyp":
			ftyp++
		case "moov":
			if moov != nil {
				return nil, errors.New("initialization has multiple moov boxes")
			}
			moov = b
		case "moof", "styp":
			return nil, errors.New("media segment supplied as initialization")
		}
	}
	if ftyp != 1 || moov == nil {
		return nil, errors.New("initialization requires one ftyp and one moov")
	}
	return moov, nil
}

func liveInitBinding(ctx context.Context, data []byte, top []*bmffBox, moov *bmffBox, m *parsedManifest) error {
	var binding *rawAssertion
	for i := range m.assertions {
		a := &m.assertions[i]
		if a.label == "c2pa.hash.bmff" || strings.HasPrefix(a.label, "c2pa.hash.bmff.") {
			if binding != nil || a.label != "c2pa.hash.bmff.v3" || a.tbox != "cbor" {
				return errors.New("live initialization requires exactly one native-CBOR BMFF v3 binding")
			}
			binding = a
		}
	}
	if binding == nil || !liveClaimReferences(m, binding.label) {
		return errors.New("initialization lacks a signed BMFF v3 binding")
	}
	fields, err := liveMap(binding.data, "hash")
	if err != nil {
		return err
	}
	if _, present := fields["merkle"]; present {
		return errors.New("live initialization BMFF binding must not contain merkle")
	}
	if !isCBORByteString(fields["hash"]) {
		return errors.New("live initialization requires a flat BMFF hash")
	}
	var decoded map[string]any
	if err := decMode.Unmarshal(binding.data, &decoded); err != nil {
		return err
	}
	exclusions, ok := decodeBMFFExclusions(decoded["exclusions"])
	if !ok {
		return errors.New("invalid initialization hash exclusions")
	}
	for _, r := range bmffExclusionByteRanges(ctx, data, top, exclusions) {
		if r.start < moov.end && r.start+r.length > moov.start {
			return errors.New("initialization hash excludes part of moov")
		}
	}
	return ctx.Err()
}

func liveClaimReferences(m *parsedManifest, label string) bool {
	count := 0
	for _, ref := range claimAssertionEntries(m.claim) {
		if assertionLabelFromURL(ref.url) == label {
			count++
		}
	}
	return count == 1
}

func liveInitSessionAssertion(m *parsedManifest) (*rawAssertion, error) {
	var found *rawAssertion
	for i := range m.assertions {
		a := &m.assertions[i]
		if a.label != liveSessionKeysLabel && !strings.HasPrefix(a.label, liveSessionKeysLabel+"__") {
			continue
		}
		if found != nil || a.label != liveSessionKeysLabel || a.tbox != "cbor" {
			return nil, errors.New("initialization requires exactly one native-CBOR session-keys assertion")
		}
		found = a
	}
	if found == nil || !liveClaimReferences(m, liveSessionKeysLabel) {
		return nil, errors.New("initialization lacks a signed session-keys assertion")
	}
	return found, nil
}
