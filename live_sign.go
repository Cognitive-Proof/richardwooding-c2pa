package c2pa

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// LiveMediaSignerConfig describes the initial Ed25519 session key. An omitted
// SessionKey or KeyID is generated with crypto/rand; supplied byte slices are
// copied. CreatedAt defaults to the current UTC time when zero. Explicit creation
// times support archived media whose presentation clock differs from today's.
// ValidityPeriod is seconds from CreatedAt (zero permits only that instant).
// MinSequenceNumber is the earliest permitted media sequence, inclusive.
type LiveMediaSignerConfig struct {
	SessionKey        ed25519.PrivateKey
	KeyID             []byte
	CreatedAt         time.Time
	ValidityPeriod    uint64
	MinSequenceNumber uint64
	// SessionPolicy is fixed at construction; AddSessionKey does not change it.
	SessionPolicy LiveSessionPolicy
}

// LiveMediaSigner signs one BMFF/CMAF VSI session. It uses a normal Signer for
// the init manifest and an Ed25519 session key for complete media segments.
// Initialize once, set the media-time origin, then sign segments in sequence.
// Methods return fully prepared byte buffers and must not be used concurrently.
// Publishing/persisting those buffers is the caller's responsibility.
type LiveMediaSigner struct {
	manifestSigner    *Signer
	private           ed25519.PrivateKey
	key               liveSessionKey
	validator         *LiveMediaValidator
	nextEventID       uint32
	schedule          []liveSigningKey
	needsAnnouncement bool
	manifestStore     []byte
	manifestRef       *liveManifestReference
	sessionPolicy     LiveSessionPolicy
}

// NewLiveMediaSigner creates a session and binds its key to manifestSigner's
// leaf certificate. The Signer must come from NewSigner. Init signing uses its
// normal manifest policy, including configured timestamp and identity signing.
// A receiver still supplies its own trust policy when validating the output.
func NewLiveMediaSigner(manifestSigner *Signer, cfg LiveMediaSignerConfig) (*LiveMediaSigner, error) {
	if manifestSigner == nil || manifestSigner.key == nil || len(manifestSigner.chainDER) == 0 || len(manifestSigner.chainDER[0]) == 0 {
		return nil, fmt.Errorf("%w: live media requires an initialized manifest signer", ErrSignerKey)
	}
	if cfg.MinSequenceNumber > math.MaxUint32 {
		return nil, fmt.Errorf("%w: live profile uses 32-bit mfhd sequences", ErrSignerOption)
	}
	private := ed25519.PrivateKey(bytes.Clone(cfg.SessionKey))
	if len(private) == 0 {
		_, generated, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		private = generated
	}
	kid := bytes.Clone(cfg.KeyID)
	if len(kid) == 0 {
		kid = make([]byte, 16)
		if _, err := rand.Read(kid); err != nil {
			return nil, err
		}
	}
	created := cfg.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	key, err := newLiveSessionKey(private, kid, manifestSigner.chainDER[0], created, cfg.ValidityPeriod, cfg.MinSequenceNumber)
	if err != nil {
		return nil, err
	}
	if _, err := encodeLiveSessionKeys([]liveSessionKey{key}); err != nil {
		return nil, err
	}
	check := NewLiveMediaValidator(WithLiveSessionPolicy(cfg.SessionPolicy))
	if _, err := check.sessionPolicy(); err != nil {
		return nil, err
	}
	return &LiveMediaSigner{manifestSigner: manifestSigner, private: private, key: key, schedule: []liveSigningKey{{key: key, private: private}}, sessionPolicy: cfg.SessionPolicy}, nil
}

// Initialized reports whether this signer has produced its authenticated init.
func (s *LiveMediaSigner) Initialized() bool { return s != nil && s.validator.Initialized() }

// ManifestID returns the latest successfully signed manifest's label, initially
// the init manifest, or "" before successful init signing.
func (s *LiveMediaSigner) ManifestID() string {
	if !s.Initialized() {
		return ""
	}
	return s.validator.ManifestID()
}

// SignInitSegment adds the session-keys assertion to m and signs a complete
// single-track initialization segment. The caller supplies the manifest's actions
// as for Signer.Sign; caller-supplied session-keys assertions are refused.
//
// The normal signing pipeline validates the signed manifest, certificate profile,
// hash binding and any configured timestamps/identities before return. Live
// structure, track metadata, moov coverage and session-key binding are checked
// as well. Success initializes this signer exactly once. Failure returns no
// output and leaves it available for retry. To begin another session, construct
// another LiveMediaSigner.
func (s *LiveMediaSigner) SignInitSegment(ctx context.Context, input io.Reader, m Manifest) (output []byte, err error) {
	defer func() {
		if err != nil {
			if canceled := ctx.Err(); canceled != nil {
				err = canceled
			}
		}
	}()
	if s == nil || s.manifestSigner == nil {
		return nil, errors.New("live media signer is not configured")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.Initialized() {
		return nil, errors.New("live media signer already initialized")
	}
	if input == nil {
		return nil, ErrNoInput
	}
	for _, a := range m.Assertions {
		if a.Label == liveSessionKeysLabel || strings.HasPrefix(a.Label, liveSessionKeysLabel+"__") {
			return nil, fmt.Errorf("%w: live signer supplies session-keys assertions", ErrManifestInvalid)
		}
	}
	if err := validateManifest(m); err != nil {
		return nil, err
	}
	asset, err := readWholeAsset(ctx, input)
	if err != nil {
		return nil, err
	}
	top := parseBMFFBoxes(ctx, asset)
	moov, err := liveInitStructure(ctx, asset, top)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedAsset, err)
	}
	if _, err := liveInitTrack(asset, moov); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedAsset, err)
	}
	assertion, err := encodeLiveSessionKeys(s.sessionKeys())
	if err != nil {
		return nil, err
	}
	// Do not append into the caller's assertion backing array.
	m.Assertions = append(append([]Assertion(nil), m.Assertions...), Assertion{Label: liveSessionKeysLabel, Value: cbor.RawMessage(assertion)})
	final, err := s.manifestSigner.sign(ctx, BMFF, asset, m, bmffFlatBinding{alg: s.manifestSigner.cfg.hashAlg})
	if err != nil {
		return nil, err
	}
	// The shared signing pipeline has already authenticated this locally produced
	// output with the configured credential and the token's own TSA chain. Reuse
	// that result rather than imposing a different TSA trust policy in a second
	// generic validation pass. Independently check all live-specific init rules.
	top = parseBMFFBoxes(ctx, final)
	moov, err = liveInitStructure(ctx, final, top)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSelfCheckFailed, err)
	}
	track, err := liveInitTrack(final, moov)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSelfCheckFailed, err)
	}
	manifest := parseStore(ctx, extractJUMBF(ctx, BMFF, final)).active()
	if manifest == nil || manifest.update {
		return nil, fmt.Errorf("%w: live init has no standard manifest", ErrSelfCheckFailed)
	}
	if err := liveInitBinding(ctx, final, top, moov, manifest); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSelfCheckFailed, err)
	}
	keysAssertion, err := liveInitSessionAssertion(manifest)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSelfCheckFailed, err)
	}
	keys, err := decodeLiveSessionKeys(keysAssertion.data, s.manifestSigner.chainDER[0])
	if err != nil || len(keys) != len(s.schedule) {
		return nil, fmt.Errorf("%w: live init key binding: %v", ErrSelfCheckFailed, err)
	}
	state := &liveMediaInit{manifestID: manifest.label, track: track, signerDER: bytes.Clone(s.manifestSigner.chainDER[0]), keys: map[string]liveSessionKey{string(keys[0].kid): keys[0]}}
	for _, k := range keys {
		state.keys[string(k.kid)] = k
	}
	store := bytes.Clone(extractJUMBF(ctx, BMFF, final))
	state.recordManifest(manifest.label, store)
	state.setManifestChain(manifest.label, s.manifestSigner.chain)
	state.initData = bytes.Clone(final)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.manifestSigner.chain[len(s.manifestSigner.chain)-1])
	s.validator = NewLiveMediaValidator(WithSigningTrust(pool), WithLiveSessionPolicy(s.sessionPolicy))
	s.validator.init = state
	s.manifestStore = store
	s.needsAnnouncement = false
	return final, nil
}

// SetMediaTimeOrigin configures the same explicit mapping as the validator's
// method. Call after init signing and before the first accepted media segment.
func (s *LiveMediaSigner) SetMediaTimeOrigin(origin time.Time) error {
	if !s.Initialized() {
		return errors.New("sign the live initialization before setting its media-time origin")
	}
	return s.validator.SetMediaTimeOrigin(origin)
}

// SignMediaSegment signs a complete segment using its mfhd sequence and parsed
// track/sample timing, assigns a session-unique event ID, and validates the result
// against this session. Supports the same timing profile as ValidateMediaSegment
// and the insertion/index layouts documented in docs/live-media-profile.md.
//
// Failure returns no output and consumes no sequence or event ID. Success returns
// the complete signed bytes and advances state before handing them to the caller.
// Subsequent publication failure does not roll back that accepted sequence.
func (s *LiveMediaSigner) SignMediaSegment(ctx context.Context, input io.Reader) (output []byte, err error) {
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
	if !s.Initialized() {
		return nil, errors.New("sign the live initialization before media segments")
	}
	if s.needsAnnouncement {
		return nil, errors.New("new session keys require SignMediaSegmentWithManifest")
	}
	if input == nil {
		return nil, ErrNoInput
	}
	if s.validator.init.origin == nil {
		return nil, errors.New("explicit presentation-time origin is required before signing media")
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
		return nil, errors.New("media duration exceeds VSI emsg capacity")
	}
	selected, err := s.keyForSegment(uint64(timing.sequence), timing.presentationStart)
	if err != nil {
		return nil, err
	}
	final, err := buildLiveVSISegmentWithReference(ctx, asset, selected.private, selected.key.kid, s.ManifestID(), uint64(timing.sequence), liveEvent{timescale: s.validator.init.track.timescale, duration: uint32(timing.duration), id: s.nextEventID}, s.manifestRef)
	if err != nil {
		return nil, err
	}
	result := s.validator.ValidateMediaSegment(ctx, bytes.NewReader(final))
	if !result.Valid {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, status := range result.Statuses {
			if status.Severity == SeverityFailure {
				return nil, fmt.Errorf("%w: %s: %s", ErrSelfCheckFailed, status.Code, status.Explanation)
			}
		}
		return nil, ErrSelfCheckFailed
	}
	s.nextEventID++
	return final, nil
}
