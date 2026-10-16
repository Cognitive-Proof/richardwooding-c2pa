package c2pa

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

const liveVSIScheme = "urn:c2pa:verifiable-segment-info"

// liveVSISchemeExclusion is the bmffHash exclusion value from
// c2pa-org/specs-core#2542: the scheme_id_uri including its NUL terminator, so
// the byte-prefix predicate matches only the exact VSI scheme. Validators still
// accept the unterminated legacy value during the transition; liveVSIHash then
// rejects any longer-scheme lookalike that the prefix would also exclude.
const liveVSISchemeExclusion = liveVSIScheme + "\x00"

func isLiveVSIExclusionValue(v []byte) bool {
	return string(v) == liveVSISchemeExclusion || string(v) == liveVSIScheme
}

// These internal primitives authenticate a VSI envelope and its media hash.
// Key admission, presentation-time validity, sequence continuity and session-wide
// emsg ID uniqueness belong to the stateful validator.
type liveVSIInfo struct {
	sequence    uint64
	manifestID  string
	bmffHash    cbor.RawMessage
	manifestRef *liveManifestReference
}

func signLiveVSI(private ed25519.PrivateKey, kid []byte, info liveVSIInfo) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize || !bytes.Equal(private, ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])) {
		return nil, errors.New("invalid Ed25519 session private key")
	}
	if len(kid) == 0 || info.manifestID == "" {
		return nil, errors.New("VSI requires kid and manifestId")
	}
	if _, _, _, err := decodeLiveVSIHash(info.bmffHash); err != nil {
		return nil, err
	}
	fields := map[string]any{"sequenceNumber": info.sequence, "manifestId": info.manifestID, "bmffHash": info.bmffHash}
	if r := info.manifestRef; r != nil {
		v := map[string]any{"url": r.url, "alg": r.alg, "hash": r.hash}
		if r.size != nil {
			v["size"] = *r.size
		}
		fields["manifestUri"] = v
	}
	payload, err := encMode.Marshal(fields)
	if err != nil {
		return nil, err
	}
	msg := cose.NewSign1Message()
	msg.Headers.Protected[cose.HeaderLabelAlgorithm] = cose.AlgorithmEdDSA
	msg.Headers.Unprotected[cose.HeaderLabelKeyID] = kid
	msg.Payload = payload
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, private)
	if err != nil {
		return nil, err
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, err
	}
	encoded, err := msg.MarshalCBOR()
	if err == nil && len(encoded) > maxLiveSessionAssertion {
		return nil, errors.New("VSI exceeds size limit")
	}
	return encoded, err
}

// verifyLiveVSI requires an already authenticated session key and its authorizing
// manifest ID. Never trust the envelope's unprotected kid to select another key
// after verification, and never re-encode the attached payload before verifying.
func verifyLiveVSI(encoded []byte, key liveSessionKey, manifestID string) (info liveVSIInfo, err error) {
	if len(encoded) > maxLiveSessionAssertion {
		return info, errors.New("VSI exceeds size limit")
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(encoded); err != nil {
		return info, err
	}
	if msg.Payload == nil {
		return info, errors.New("VSI payload must be attached")
	}
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil || alg != cose.AlgorithmEdDSA {
		return info, errLiveSessionAlgorithm
	}
	if _, present := msg.Headers.Protected[cose.HeaderLabelKeyID]; present {
		return info, errors.New("VSI kid must be unprotected")
	}
	kid, ok := msg.Headers.Unprotected[cose.HeaderLabelKeyID].([]byte)
	if !ok || len(kid) == 0 || !bytes.Equal(kid, key.kid) || len(key.public) != ed25519.PublicKeySize {
		return info, errors.New("VSI kid does not match session key")
	}
	critical, err := msg.Headers.Protected.Critical()
	if err != nil {
		return info, err
	}
	for _, label := range critical {
		if label != cose.HeaderLabelAlgorithm {
			return info, errors.New("unsupported critical VSI header")
		}
	}
	verifier, err := cose.NewVerifier(alg, key.public)
	if err != nil {
		return info, err
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return info, err
	}
	fields, err := liveMap(msg.Payload, "sequenceNumber", "manifestId", "bmffHash")
	if err != nil {
		return info, err
	}
	raw := fields["sequenceNumber"]
	if len(raw) == 0 || raw[0]>>5 != 0 {
		return info, errors.New("VSI sequenceNumber must be unsigned")
	}
	if err := liveDecMode.Unmarshal(raw, &info.sequence); err != nil {
		return info, err
	}
	raw = fields["manifestId"]
	if len(raw) == 0 || raw[0]>>5 != 3 || liveDecMode.Unmarshal(raw, &info.manifestID) != nil || info.manifestID == "" || info.manifestID != manifestID {
		return info, errors.New("VSI manifestId does not match authorizing manifest")
	}
	info.manifestRef, err = decodeLiveManifestReference(fields["manifestUri"])
	if err != nil {
		return info, err
	}
	info.bmffHash = bytes.Clone(fields["bmffHash"])
	_, _, _, err = decodeLiveVSIHash(info.bmffHash)
	return info, err
}

// Offset 12 is relative to the whole 32-bit v0 emsg box: size/type (8),
// version/flags (4), then scheme_id_uri. The pinned spec says offset 0; see
// docs/live-media-profile.md for the explicit compatibility decision.
func liveVSIExclusions() []any {
	return liveVSIExclusionsFor(liveVSISchemeExclusion)
}

func liveVSIExclusionsFor(value string) []any {
	return []any{map[string]any{"xpath": "/emsg", "data": []any{map[string]any{"offset": 12, "value": []byte(value)}}}}
}

func decodeLiveVSIHash(raw []byte) (alg string, digest []byte, exclusions []bmffExclusion, err error) {
	fields, err := liveMap(raw, "alg", "hash", "exclusions")
	if err != nil {
		return "", nil, nil, err
	}
	if _, present := fields["merkle"]; present {
		return "", nil, nil, errors.New("VSI bmffHash must not contain merkle")
	}
	if len(fields["alg"]) == 0 || fields["alg"][0]>>5 != 3 || liveDecMode.Unmarshal(fields["alg"], &alg) != nil {
		return "", nil, nil, errors.New("VSI hash requires an explicit algorithm")
	}
	h, ok := hashByName(alg)
	if !ok {
		return "", nil, nil, errors.New("unsupported VSI hash algorithm")
	}
	if !isCBORByteString(fields["hash"]) || liveDecMode.Unmarshal(fields["hash"], &digest) != nil || len(digest) != h.Size() {
		return "", nil, nil, errors.New("invalid VSI digest length or type")
	}
	var decoded any
	if err := decMode.Unmarshal(fields["exclusions"], &decoded); err != nil {
		return "", nil, nil, err
	}
	exclusions, ok = decodeBMFFExclusions(decoded)
	if !ok || len(exclusions) == 0 {
		return "", nil, nil, errors.New("VSI requires selective emsg exclusions")
	}
	// Initial profile allows only whole VSI events to be excluded, keeping all
	// media, other events and embedded manifests covered by the segment hash.
	for _, e := range exclusions {
		if e.xpath != "/emsg" || len(e.subset) != 0 {
			return "", nil, nil, errors.New("unsupported VSI exclusion")
		}
		selective := false
		for _, d := range e.data {
			if d.offset == 12 && isLiveVSIExclusionValue(d.value) {
				selective = true
			}
		}
		if !selective {
			return "", nil, nil, errors.New("VSI exclusion must match its scheme at box offset 12")
		}
	}
	return alg, digest, exclusions, nil
}

func liveVSIHash(ctx context.Context, segment []byte, alg string, exclusions []bmffExclusion) ([]byte, error) {
	if len(segment) > ValidateMaxScan {
		return nil, errors.New("live media segment exceeds size limit")
	}
	top, err := liveSegmentBoxes(ctx, segment)
	if err != nil {
		return nil, err
	}
	count := 0
	for _, b := range top {
		_, isVSI, parseErr := parseLiveEMSG(segment, b)
		if parseErr != nil {
			return nil, parseErr
		}
		if isVSI {
			count++
		}
		excluded := false
		for _, e := range exclusions {
			if e.xpath == "/emsg" && b.typ == "emsg" && bmffExclusionApplies(segment, b, e) {
				if !isVSI || len(e.subset) != 0 {
					return nil, errors.New("VSI exclusion matches a non-VSI event")
				}
				excluded = true
			}
		}
		if isVSI && !excluded {
			return nil, errors.New("VSI event is not excluded from its media hash")
		}
	}
	if count != 1 {
		return nil, errors.New("this profile requires exactly one VSI event per segment")
	}
	h, ok := hashByName(alg)
	if !ok {
		return nil, errors.New("unsupported VSI hash algorithm")
	}
	ranges := bmffExclusionByteRanges(ctx, segment, top, exclusions)
	if err := hashBMFFTopLevel(ctx, segment, top, ranges, h); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func verifyLiveVSIHash(ctx context.Context, segment []byte, info liveVSIInfo) error {
	alg, expected, exclusions, err := decodeLiveVSIHash(info.bmffHash)
	if err != nil {
		return err
	}
	digest, err := liveVSIHash(ctx, segment, alg, exclusions)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(digest, expected) != 1 {
		return errors.New("VSI bmffHash verification failed")
	}
	return nil
}

// buildLiveVSISegment reserves a fixed-width digest/signature at the final
// insertion point, hashes that layout including repaired offsets, then replaces
// only the excluded emsg bytes. It does not choose time mappings or advance any
// session state. The caller supplies event timing; ValidateMediaSegment checks it against media.
func buildLiveVSISegment(ctx context.Context, source []byte, private ed25519.PrivateKey, kid []byte, manifestID string, sequence uint64, event liveEvent) ([]byte, error) {
	return buildLiveVSISegmentWithReference(ctx, source, private, kid, manifestID, sequence, event, nil)
}

func buildLiveVSISegmentWithReference(ctx context.Context, source []byte, private ed25519.PrivateKey, kid []byte, manifestID string, sequence uint64, event liveEvent, ref *liveManifestReference) ([]byte, error) {
	return buildLiveVSISegmentWithExclusions(ctx, source, private, kid, manifestID, sequence, event, ref, liveVSIExclusions())
}

// buildLiveVSISegmentWithExclusions lets tests author the legacy exclusion form.
func buildLiveVSISegmentWithExclusions(ctx context.Context, source []byte, private ed25519.PrivateKey, kid []byte, manifestID string, sequence uint64, event liveEvent, ref *liveManifestReference, declared []any) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info := liveVSIInfo{sequence: sequence, manifestID: manifestID, manifestRef: ref}
	makeEvent := func(digest []byte) ([]byte, error) {
		var err error
		info.bmffHash, err = encMode.Marshal(map[string]any{"alg": "sha256", "hash": digest, "exclusions": declared})
		if err != nil {
			return nil, err
		}
		event.payload, err = signLiveVSI(private, kid, info)
		if err != nil {
			return nil, err
		}
		return encodeLiveEMSG(event)
	}
	draft, err := makeEvent(make([]byte, 32))
	if err != nil {
		return nil, err
	}
	layout, at, err := insertLiveEMSG(ctx, source, draft)
	if err != nil {
		return nil, err
	}
	exclusions, _ := decodeBMFFExclusions(declared)
	digest, err := liveVSIHash(ctx, layout, "sha256", exclusions)
	if err != nil {
		return nil, err
	}
	final, err := makeEvent(digest)
	if err != nil {
		return nil, err
	}
	if len(final) != len(draft) {
		return nil, errors.New("VSI layout changed after hashing")
	}
	copy(layout[at:at+len(final)], final)
	if err := verifyLiveVSIHash(ctx, layout, info); err != nil {
		return nil, fmt.Errorf("VSI output self-check: %w", err)
	}
	return layout, ctx.Err()
}
