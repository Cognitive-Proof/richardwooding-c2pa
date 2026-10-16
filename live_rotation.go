package c2pa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"time"
)

// Bound retained manifest/key associations without evicting replay history.
const maxLiveManifests = 64

type liveKeyManifest struct {
	keys      map[string]liveSessionKey
	digest    [32]byte
	hashes    map[string][]byte
	size      int
	chainDER  [][]byte
	checkedAt time.Time
}

func (s *liveMediaInit) recordManifest(id string, store []byte) {
	if s.manifests == nil {
		s.manifests = make(map[string]liveKeyManifest)
	}
	hashes := make(map[string][]byte)
	for _, alg := range []string{"sha256", "sha384", "sha512"} {
		h, _ := hashByName(alg)
		h.Write(store)
		hashes[alg] = h.Sum(nil)
	}
	s.manifests[id] = liveKeyManifest{keys: s.keys, digest: sha256.Sum256(store), hashes: hashes, size: len(store)}
}

func (s *liveMediaInit) setManifestChain(id string, chain []*x509.Certificate) {
	m := s.manifests[id]
	for _, cert := range chain {
		m.chainDER = append(m.chainDER, bytes.Clone(cert.Raw))
	}
	s.manifests[id] = m
}

func (s *liveMediaInit) keyForManifest(id, kid string) (liveSessionKey, bool) {
	if m, ok := s.manifests[id]; ok {
		k, ok := m.keys[kid]
		return k, ok
	}
	return liveSessionKey{}, false
}

func cloneLiveState(s *liveMediaInit) *liveMediaInit {
	n := *s
	n.manifests = make(map[string]liveKeyManifest, len(s.manifests))
	for id, m := range s.manifests {
		n.manifests[id] = m
	}
	n.eventIDs = make(map[uint32]struct{}, len(s.eventIDs))
	for id := range s.eventIDs {
		n.eventIDs[id] = struct{}{}
	}
	return &n
}

func sameLiveKey(a, b liveSessionKey) bool {
	return bytes.Equal(a.kid, b.kid) && bytes.Equal(a.public, b.public) && bytes.Equal(a.binding, b.binding) && a.minSequence == b.minSequence && a.created.Equal(b.created) && a.validity == b.validity
}

func (s *liveMediaInit) knowsKey(key liveSessionKey) bool {
	for _, m := range s.manifests {
		for _, k := range m.keys {
			if sameLiveKey(k, key) {
				return true
			}
		}
	}
	return false
}

// All checks run on a candidate. The caller installs it only after validating
// this segment's VSI, complete media hash, presentation time and continuity.
func (l *LiveMediaValidator) stageLiveAnnouncement(ctx context.Context, data []byte, prior *liveMediaInit, id string, sequence uint64) (*liveMediaInit, StatusCode, error) {
	result := Validate(ctx, BMFF, bytes.NewReader(data), func(c *validateConfig) {
		if l.cfg != nil {
			*c = *l.cfg
		}
	})
	p, err := l.sessionPolicy()
	if err != nil {
		return nil, StatusLiveVideoManifestInvalid, err
	}
	return stageLiveAnnouncementResult(ctx, data, prior, id, sequence, result, p.MaxManifests)
}

func stageLiveAnnouncementResult(ctx context.Context, data []byte, prior *liveMediaInit, id string, sequence uint64, result ValidationResult, limits ...int) (*liveMediaInit, StatusCode, error) {
	store := extractJUMBF(ctx, BMFF, data)
	m := parseStore(ctx, store).active()
	if m == nil {
		return nil, StatusLiveVideoManifestInvalid, errors.New("missing announcement manifest")
	}
	if err := liveAnnouncementBinding(m); err != nil {
		return nil, StatusLiveVideoManifestInvalid, err
	}
	limit := maxLiveManifests
	if len(limits) > 0 {
		limit = limits[0]
	}
	return stageLiveStoreResult(ctx, store, prior, id, sequence, result, true, limit)
}

func stageLiveStoreResult(ctx context.Context, store []byte, prior *liveMediaInit, id string, sequence uint64, result ValidationResult, announcement bool, limit int) (*liveMediaInit, StatusCode, error) {
	bad := func(code StatusCode, err error) (*liveMediaInit, StatusCode, error) { return nil, code, err }
	if !result.Valid || result.Binding != BindingVerified || !result.hasForActive(StatusClaimSignatureValidated) || !result.hasForActive(StatusSigningCredentialTrusted) || result.ActiveManifestLabel != id || len(result.SignerChain) == 0 || result.SignerChain[0] == nil {
		return bad(StatusLiveVideoManifestInvalid, errors.New("announcement failed manifest signature, trust, binding or identifier checks"))
	}
	m := parseStore(ctx, store).active()
	if m == nil || m.update {
		return bad(StatusLiveVideoManifestInvalid, errors.New("announcement requires a standard manifest"))
	}
	a, err := liveInitSessionAssertion(m)
	if err != nil {
		return bad(StatusLiveVideoSessionKeyInvalid, err)
	}
	keys, err := decodeLiveSessionKeys(a.data, result.SignerChain[0].Raw)
	if err != nil {
		return bad(StatusLiveVideoSessionKeyInvalid, err)
	}
	if known, ok := prior.manifests[id]; ok {
		if (announcement && id != prior.manifestID) || known.digest != sha256.Sum256(store) {
			return bad(StatusLiveVideoManifestInvalid, errors.New("manifest identifier reused or retired announcement replayed"))
		}
		return cloneLiveState(prior), "", nil
	}
	if len(prior.manifests) >= limit {
		return bad(StatusLiveVideoManifestInvalid, errors.New("manifest history limit reached; reinitialization required"))
	}
	n := cloneLiveState(prior)
	n.keys = make(map[string]liveSessionKey, len(keys))
	for _, k := range keys {
		if announcement && !prior.knowsKey(k) && (k.minSequence < sequence || (prior.seen && k.minSequence <= prior.lastSequence)) {
			return bad(StatusLiveVideoSessionKeyInvalid, errors.New("new key minimum sequence predates announcement"))
		}
		n.keys[string(k.kid)] = k
	}
	n.manifestID = id
	n.signerDER = bytes.Clone(result.SignerChain[0].Raw)
	n.recordManifest(id, store)
	n.setManifestChain(id, result.SignerChain)
	return n, "", ctx.Err()
}

// An announcement must bind the whole segment, except the standard BMFF
// exclusions and selectively matched VSI. Arbitrary/subset exclusions could
// transplant keys from an unrelated asset and are not admitted by this profile.
func liveAnnouncementBinding(m *parsedManifest) error {
	var binding *rawAssertion
	for i := range m.assertions {
		a := &m.assertions[i]
		if a.label == "c2pa.hash.bmff" || strings.HasPrefix(a.label, "c2pa.hash.bmff.") {
			if binding != nil || a.label != "c2pa.hash.bmff.v3" {
				return errors.New("duplicate announcement binding")
			}
			binding = a
		}
	}
	if binding == nil || binding.tbox != "cbor" || !liveClaimReferences(m, binding.label) {
		return errors.New("announcement lacks signed BMFF v3 binding")
	}
	f, err := liveMap(binding.data, "hash", "exclusions")
	if err != nil {
		return err
	}
	if _, ok := f["merkle"]; ok || !isCBORByteString(f["hash"]) {
		return errors.New("announcement requires flat hash")
	}
	var raw any
	// Decode the normal CBOR representation using the shared exclusion parser.
	if err := decMode.Unmarshal(f["exclusions"], &raw); err != nil {
		return err
	}
	exclusions, ok := decodeBMFFExclusions(raw)
	if !ok {
		return errors.New("invalid announcement exclusions")
	}
	for _, e := range exclusions {
		if len(e.subset) != 0 {
			return errors.New("announcement subset exclusions unsupported")
		}
		switch e.xpath {
		case "/ftyp", "/mfra":
			if len(e.data) != 0 {
				return errors.New("unexpected standard exclusion predicate")
			}
		case "/uuid":
			if len(e.data) != 1 || e.data[0].offset != 8 || !bytes.Equal(e.data[0].value, c2paBoxUUID[:]) {
				return errors.New("announcement may exclude only C2PA uuid boxes")
			}
		case "/emsg":
			if len(e.data) != 1 || e.data[0].offset != 12 || !isLiveVSIExclusionValue(e.data[0].value) {
				return errors.New("announcement may exclude only VSI events")
			}
		default:
			return errors.New("announcement excludes segment content")
		}
	}
	return nil
}
