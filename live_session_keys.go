package c2pa

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// Internal building blocks for the BMFF/CMAF VSI profile. These do not establish
// manifest or certificate trust: the stateful live validator does that before
// admitting any keys.
const liveSessionKeysLabel = "c2pa.session-keys"

const maxLiveSessionKeys = 256
const maxLiveSessionAssertion = 1 << 20

var errLiveSessionAlgorithm = errors.New("c2pa: unsupported live session key algorithm")

var liveDecMode = func() cbor.DecMode {
	dm, err := (cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:  16,
		MaxArrayElements: maxLiveSessionKeys,
		MaxMapPairs:      64,
	}).DecMode()
	if err != nil {
		panic(err)
	}
	return dm
}()

type liveSessionKey struct {
	kid         []byte
	public      ed25519.PublicKey
	minSequence uint64
	created     time.Time
	validity    uint64
	binding     cbor.RawMessage
}

// newLiveSessionKey binds the session key to the supplied signer's leaf DER.
// Certificate validation belongs to the authorizing manifest, not this helper.
func newLiveSessionKey(private ed25519.PrivateKey, kid, signerDER []byte, created time.Time, validity, minSequence uint64) (liveSessionKey, error) {
	k := liveSessionKey{kid: bytes.Clone(kid), created: created.UTC(), validity: validity, minSequence: minSequence}
	if len(private) != ed25519.PrivateKeySize || !bytes.Equal(private, ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])) {
		return k, errors.New("invalid Ed25519 session private key")
	}
	if len(kid) == 0 || len(signerDER) == 0 {
		return k, errors.New("session kid and signer certificate must be nonempty")
	}
	if err := k.checkWindow(); err != nil {
		return k, err
	}
	k.public = bytes.Clone(private.Public().(ed25519.PublicKey))
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, private)
	if err != nil {
		return k, err
	}
	msg := cose.NewSign1Message()
	msg.Headers.Protected[cose.HeaderLabelAlgorithm] = cose.AlgorithmEdDSA
	// The detached payload is the certificate encoded as a CBOR byte string.
	// COSE then wraps these encoded bytes in the Sig_structure payload string.
	msg.Payload, err = encMode.Marshal(signerDER)
	if err != nil {
		return k, err
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return k, err
	}
	msg.Payload = nil
	k.binding, err = msg.MarshalCBOR()
	return k, err
}

// checkWindow avoids time.Duration overflow (roughly 292 years) and limits
// authored/decoded timestamps to the RFC3339 year range. A zero-second window
// is allowed by the unsigned-integer schema and admits only the creation instant.
func (k liveSessionKey) checkWindow() error {
	if k.created.Year() < 0 || k.created.Year() > 9999 {
		return errors.New("session creation time outside RFC3339 range")
	}
	last := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	if k.created.After(last) || k.validity > uint64(last.Unix()-k.created.Unix()) {
		return errors.New("session validity period overflows supported timestamp range")
	}
	return nil
}

// permits uses the caller's mapped segment presentation time, never wall time.
// Both endpoints are inclusive. Continuity across segments is a separate check.
func (k liveSessionKey) permits(sequence uint64, presentation time.Time) bool {
	if k.checkWindow() != nil || sequence < k.minSequence || presentation.Before(k.created) {
		return false
	}
	end := time.Unix(k.created.Unix()+int64(k.validity), int64(k.created.Nanosecond()))
	return !presentation.After(end)
}

func encodeLiveSessionKeys(keys []liveSessionKey) ([]byte, error) {
	if len(keys) == 0 || len(keys) > maxLiveSessionKeys {
		return nil, errors.New("invalid session key count")
	}
	items := make([]map[string]any, len(keys))
	seen := make(map[string]bool)
	for i, k := range keys {
		if len(k.kid) == 0 || seen[string(k.kid)] || len(k.public) != ed25519.PublicKeySize || len(k.binding) == 0 {
			return nil, errors.New("invalid or duplicate session key")
		}
		if err := k.checkWindow(); err != nil {
			return nil, err
		}
		seen[string(k.kid)] = true
		items[i] = map[string]any{
			"key":               map[int64]any{1: 1, 2: k.kid, 3: int64(cose.AlgorithmEdDSA), -1: 6, -2: []byte(k.public)},
			"minSequenceNumber": k.minSequence,
			"createdAt":         cbor.Tag{Number: 0, Content: k.created.Format(time.RFC3339Nano)},
			"validityPeriod":    k.validity,
			"signerBinding":     k.binding,
		}
	}
	data, err := encMode.Marshal(map[string]any{"keys": items})
	if err == nil && len(data) > maxLiveSessionAssertion {
		err = errors.New("session assertion exceeds size limit")
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

// decodeLiveSessionKeys is atomic: any malformed key or failed signer binding
// rejects the whole assertion. Success proves possession/association only; the
// caller must authenticate the enclosing manifest and its certificate first.
func decodeLiveSessionKeys(data, signerDER []byte) ([]liveSessionKey, error) {
	if len(data) > maxLiveSessionAssertion || len(signerDER) == 0 {
		return nil, errors.New("invalid session assertion size or missing signer certificate")
	}
	top, err := liveMap(data, "keys")
	if err != nil {
		return nil, err
	}
	var raw []cbor.RawMessage
	if len(top["keys"]) == 0 || top["keys"][0]>>5 != 4 {
		return nil, errors.New("session keys must be an array")
	}
	if err := liveDecMode.Unmarshal(top["keys"], &raw); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("session keys array is empty")
	}
	keys := make([]liveSessionKey, 0, len(raw))
	seen := make(map[string]bool)
	for i, item := range raw {
		k, err := decodeLiveSessionKey(item, signerDER)
		if err != nil {
			return nil, fmt.Errorf("session key %d: %w", i, err)
		}
		if seen[string(k.kid)] {
			return nil, errors.New("duplicate session kid")
		}
		seen[string(k.kid)] = true
		keys = append(keys, k)
	}
	return keys, nil
}

func liveMap(raw []byte, required ...string) (map[string]cbor.RawMessage, error) {
	if len(raw) == 0 || raw[0]>>5 != 5 {
		return nil, errors.New("expected untagged CBOR map")
	}
	var fields map[string]cbor.RawMessage
	if err := liveDecMode.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return nil, fmt.Errorf("missing %s", name)
		}
	}
	return fields, nil
}

func decodeLiveSessionKey(raw, signerDER []byte) (k liveSessionKey, err error) {
	fields, err := liveMap(raw, "key", "minSequenceNumber", "createdAt", "validityPeriod", "signerBinding")
	if err != nil {
		return k, err
	}
	for name, dst := range map[string]*uint64{"minSequenceNumber": &k.minSequence, "validityPeriod": &k.validity} {
		b := fields[name]
		if len(b) == 0 || b[0]>>5 != 0 {
			return k, fmt.Errorf("%s must be an unsigned integer", name)
		}
		if err := liveDecMode.Unmarshal(b, dst); err != nil {
			return k, err
		}
	}
	var date cbor.RawTag
	if err := liveDecMode.Unmarshal(fields["createdAt"], &date); err != nil || date.Number != 0 || len(date.Content) == 0 || date.Content[0]>>5 != 3 {
		return k, errors.New("createdAt must be CBOR tag 0 containing RFC3339 text")
	}
	var stamp string
	if err := liveDecMode.Unmarshal(date.Content, &stamp); err != nil {
		return k, err
	}
	k.created, err = time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		return k, err
	}
	k.created = k.created.UTC()
	if err := k.checkWindow(); err != nil {
		return k, err
	}
	b := fields["key"]
	if len(b) == 0 || b[0]>>5 != 5 {
		return k, errors.New("COSE key must be a map")
	}
	var key map[int64]cbor.RawMessage
	if err := liveDecMode.Unmarshal(b, &key); err != nil {
		return k, err
	}
	// Initial profile: OKP / Ed25519. Never accept private material in an assertion.
	for label, want := range map[int64]int64{1: 1, -1: 6, 3: int64(cose.AlgorithmEdDSA)} {
		value, present := key[label]
		if label == 3 && !present {
			continue
		} // COSE_Key alg is optional.
		var n int64
		if len(value) == 0 || value[0]>>5 > 1 || liveDecMode.Unmarshal(value, &n) != nil || n != want {
			return k, errLiveSessionAlgorithm
		}
	}
	if _, ok := key[-4]; ok {
		return k, errors.New("session assertion contains private key material")
	}
	for label, dst := range map[int64]*[]byte{2: &k.kid, -2: (*[]byte)(&k.public)} {
		if !isCBORByteString(key[label]) {
			return k, errors.New("session kid and public key must be byte strings")
		}
		if err := liveDecMode.Unmarshal(key[label], dst); err != nil {
			return k, err
		}
	}
	if len(k.kid) == 0 || len(k.public) != ed25519.PublicKeySize {
		return k, errors.New("invalid session kid or Ed25519 public key length")
	}
	if ops, ok := key[4]; ok {
		var values []int64
		if len(ops) == 0 || ops[0]>>5 != 4 || liveDecMode.Unmarshal(ops, &values) != nil {
			return k, errors.New("invalid session key_ops")
		}
		seen := make(map[int64]bool)
		for _, op := range values {
			if (op != 1 && op != 2) || seen[op] {
				return k, errors.New("invalid session key_ops")
			}
			seen[op] = true
		}
		if !seen[2] {
			return k, errors.New("session key_ops does not permit verification")
		}
	}
	k.binding = bytes.Clone(fields["signerBinding"])
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(k.binding); err != nil {
		return k, fmt.Errorf("signerBinding: %w", err)
	}
	if msg.Payload != nil {
		return k, errors.New("signerBinding payload must be detached")
	}
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil || alg != cose.AlgorithmEdDSA {
		return k, errLiveSessionAlgorithm
	}
	critical, err := msg.Headers.Protected.Critical()
	if err != nil {
		return k, err
	}
	for _, label := range critical {
		if label != cose.HeaderLabelAlgorithm {
			return k, errors.New("unsupported critical signerBinding header")
		}
	}
	msg.Payload, err = encMode.Marshal(signerDER)
	if err != nil {
		return k, err
	}
	verifier, err := cose.NewVerifier(alg, k.public)
	if err != nil {
		return k, err
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return k, fmt.Errorf("signerBinding: %w", err)
	}
	return k, nil
}
