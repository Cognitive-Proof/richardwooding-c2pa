package c2pa

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

func liveKeyFixture(t testing.TB) (liveSessionKey, ed25519.PrivateKey, []byte) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	// Stable certificate bytes keep fuzz seeds valid across worker processes.
	// A different key signs the certificate, so the session binding test cannot
	// accidentally pass by using the certificate's signing key.
	manifestKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Unix(1700000000, 0), NotAfter: time.Unix(2000000000, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, manifestKey.Public(), manifestKey)
	if err != nil {
		t.Fatal(err)
	}
	k, err := newLiveSessionKey(private, []byte("livesim2-session"), der,
		time.Unix(1760000042, 123456789).UTC(), 10, 880000021)
	if err != nil {
		t.Fatal(err)
	}
	return k, private, der
}

func liveCBOR(t testing.TB, value any) cbor.RawMessage {
	t.Helper()
	b, err := encMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func liveKeyFields(t testing.TB, k liveSessionKey) map[string]cbor.RawMessage {
	t.Helper()
	b, err := encodeLiveSessionKeys([]liveSessionKey{k})
	if err != nil {
		t.Fatal(err)
	}
	var top struct {
		Keys []map[string]cbor.RawMessage `cbor:"keys"`
	}
	if err := liveDecMode.Unmarshal(b, &top); err != nil {
		t.Fatal(err)
	}
	return top.Keys[0]
}

func TestLiveSessionKeysRoundTrip(t *testing.T) {
	k, _, der := liveKeyFixture(t)
	k2 := k
	k2.kid = []byte("next")
	k2.minSequence = math.MaxUint64
	data, err := encodeLiveSessionKeys([]liveSessionKey{k, k2})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := decodeLiveSessionKeys(data, der)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || !keys[0].created.Equal(k.created) || keys[0].validity != 10 || keys[1].minSequence != math.MaxUint64 || !bytes.Equal(keys[0].public, k.public) || !bytes.Equal(keys[0].kid, k.kid) {
		t.Fatalf("round trip: %+v", keys)
	}
	fields := liveKeyFields(t, k)
	if fields["createdAt"][0] != 0xc0 || fields["signerBinding"][0] != 0xd2 {
		t.Fatal("required CBOR tags lost")
	}
	var pub map[int64]cbor.RawMessage
	if err := liveDecMode.Unmarshal(fields["key"], &pub); err != nil {
		t.Fatal(err)
	}
	if _, ok := pub[-4]; ok {
		t.Fatal("private material published")
	}
	// COSE_Key alg is optional; the binding still carries the protected alg.
	delete(pub, 3)
	pub[4] = liveCBOR(t, []int{1, 2})
	fields["key"] = liveCBOR(t, pub)
	if _, err := decodeLiveSessionKeys(liveCBOR(t, map[string]any{"keys": []any{fields}}), der); err != nil {
		t.Fatal(err)
	}
}

func TestLiveSessionSignerBindingIndependentVerification(t *testing.T) {
	k, _, der := liveKeyFixture(t)
	var tagged cbor.RawTag
	if err := liveDecMode.Unmarshal(k.binding, &tagged); err != nil {
		t.Fatal(err)
	}
	var parts []cbor.RawMessage
	if err := liveDecMode.Unmarshal(tagged.Content, &parts); err != nil {
		t.Fatal(err)
	}
	if tagged.Number != 18 || len(parts) != 4 || !bytes.Equal(parts[2], []byte{0xf6}) {
		t.Fatal("binding is not a tagged detached Sign1")
	}
	var protected, signature []byte
	if err := liveDecMode.Unmarshal(parts[0], &protected); err != nil {
		t.Fatal(err)
	}
	if err := liveDecMode.Unmarshal(parts[3], &signature); err != nil {
		t.Fatal(err)
	}
	// Verify using crypto/ed25519 over an independently assembled Sig_structure,
	// rather than round-tripping the same COSE signing/verifying helper.
	tbs := liveCBOR(t, []any{"Signature1", protected, []byte{}, []byte(liveCBOR(t, der))})
	if !ed25519.Verify(k.public, tbs, signature) {
		t.Fatal("session key did not sign the CBOR-encoded certificate")
	}
	rawDER := liveCBOR(t, []any{"Signature1", protected, []byte{}, der})
	if ed25519.Verify(k.public, rawDER, signature) {
		t.Fatal("unexpected raw-DER certificate payload")
	}
}

func TestLiveSessionKeyPresentationWindow(t *testing.T) {
	k, _, _ := liveKeyFixture(t)
	cases := []struct {
		name string
		seq  uint64
		at   time.Time
		want bool
	}{
		{"start", k.minSequence, k.created, true},
		{"end", k.minSequence, k.created.Add(10 * time.Second), true},
		{"early", k.minSequence, k.created.Add(-time.Nanosecond), false},
		{"late", k.minSequence, k.created.Add(10*time.Second + time.Nanosecond), false},
		{"sequence", k.minSequence - 1, k.created, false},
		{"max sequence", math.MaxUint64, k.created, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := k.permits(tc.seq, tc.at); got != tc.want {
				t.Fatalf("permits = %v", got)
			}
		})
	}
	k.validity = 0
	if !k.permits(k.minSequence, k.created) || k.permits(k.minSequence, k.created.Add(time.Nanosecond)) {
		t.Fatal("zero window")
	}
	k.validity = 400 * 365 * 24 * 60 * 60 // Must not pass through time.Duration.
	if !k.permits(k.minSequence, k.created.AddDate(399, 0, 0)) {
		t.Fatal("long window overflow")
	}
	k.validity = math.MaxUint64
	if k.permits(k.minSequence, k.created) {
		t.Fatal("overflowed window accepted")
	}
}

func TestLiveSessionKeysRejectMalformed(t *testing.T) {
	k, _, der := liveKeyFixture(t)
	prior := k
	prior.kid = []byte("previous-key")
	cases := map[string]func(map[string]cbor.RawMessage){
		"untagged creation": func(m map[string]cbor.RawMessage) { m["createdAt"] = liveCBOR(t, k.created.Format(time.RFC3339Nano)) },
		"epoch creation tag": func(m map[string]cbor.RawMessage) {
			m["createdAt"] = liveCBOR(t, cbor.Tag{Number: 1, Content: k.created.Unix()})
		},
		"invalid date":      func(m map[string]cbor.RawMessage) { m["createdAt"] = cbor.RawMessage{0xc0, 0x61, 'x'} },
		"negative sequence": func(m map[string]cbor.RawMessage) { m["minSequenceNumber"] = liveCBOR(t, -1) },
		"float period":      func(m map[string]cbor.RawMessage) { m["validityPeriod"] = liveCBOR(t, 10.0) },
		"overflow period":   func(m map[string]cbor.RawMessage) { m["validityPeriod"] = liveCBOR(t, uint64(math.MaxUint64)) },
		"untagged binding":  func(m map[string]cbor.RawMessage) { m["signerBinding"] = k.binding[1:] },
		"tampered binding": func(m map[string]cbor.RawMessage) {
			b := bytes.Clone(k.binding)
			b[len(b)-1] ^= 1
			m["signerBinding"] = b
		},
	}
	for _, name := range []string{"key", "createdAt", "minSequenceNumber", "validityPeriod", "signerBinding"} {
		cases["missing "+name] = func(m map[string]cbor.RawMessage) { delete(m, name) }
		cases["null "+name] = func(m map[string]cbor.RawMessage) { m[name] = liveCBOR(t, nil) }
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := liveKeyFields(t, k)
			mutate(m)
			data := liveCBOR(t, map[string]any{"keys": []any{liveKeyFields(t, prior), m}})
			if keys, err := decodeLiveSessionKeys(data, der); err == nil || keys != nil {
				t.Fatalf("invalid assertion admitted keys: %v, %v", keys, err)
			}
		})
	}
	keyCases := map[string]struct {
		label int64
		value any
	}{
		"wrong key type": {1, 2}, "wrong curve": {-1, 7}, "wrong algorithm": {3, -7},
		"short public key": {-2, []byte{1}}, "long public key": {-2, make([]byte, 33)},
		"text kid": {2, "kid"}, "empty kid": {2, []byte{}}, "private material": {-4, []byte{1}},
		"sign-only operations": {4, []int{1}}, "duplicate operations": {4, []int{2, 2}},
	}
	for name, tc := range keyCases {
		t.Run(name, func(t *testing.T) {
			m := liveKeyFields(t, k)
			var key map[int64]cbor.RawMessage
			if err := liveDecMode.Unmarshal(m["key"], &key); err != nil {
				t.Fatal(err)
			}
			key[tc.label] = liveCBOR(t, tc.value)
			m["key"] = liveCBOR(t, key)
			_, err := decodeLiveSessionKeys(liveCBOR(t, map[string]any{"keys": []any{m}}), der)
			if err == nil {
				t.Fatal("invalid COSE key accepted")
			}
			if tc.label == 1 || tc.label == -1 || tc.label == 3 {
				if !errors.Is(err, errLiveSessionAlgorithm) {
					t.Fatalf("unsupported algorithm not identified: %v", err)
				}
			}
		})
	}
}

func TestLiveSessionBindingHeaders(t *testing.T) {
	k, private, der := liveKeyFixture(t)
	for _, kind := range []string{"attached", "unprotected alg", "unknown critical", "raw DER"} {
		t.Run(kind, func(t *testing.T) {
			msg := cose.NewSign1Message()
			msg.Headers.Protected[cose.HeaderLabelAlgorithm] = cose.AlgorithmEdDSA
			if kind == "unknown critical" {
				msg.Headers.Protected[int64(99)] = true
				msg.Headers.Protected[cose.HeaderLabelCritical] = []any{int64(99)}
			}
			msg.Payload = liveCBOR(t, der)
			if kind == "raw DER" {
				msg.Payload = der
			}
			signer, err := cose.NewSigner(cose.AlgorithmEdDSA, private)
			if err != nil {
				t.Fatal(err)
			}
			if err := msg.Sign(rand.Reader, nil, signer); err != nil {
				t.Fatal(err)
			}
			if kind != "attached" {
				msg.Payload = nil
			}
			if kind == "unprotected alg" {
				delete(msg.Headers.Protected, cose.HeaderLabelAlgorithm)
				msg.Headers.Unprotected[cose.HeaderLabelAlgorithm] = cose.AlgorithmEdDSA
			}
			binding, err := msg.MarshalCBOR()
			if err != nil {
				t.Fatal(err)
			}
			m := liveKeyFields(t, k)
			m["signerBinding"] = binding
			if _, err := decodeLiveSessionKeys(liveCBOR(t, map[string]any{"keys": []any{m}}), der); err == nil {
				t.Fatal("invalid binding accepted")
			}
		})
	}
}

func TestLiveSessionAssertionLimitsAndDuplicates(t *testing.T) {
	k, _, der := liveKeyFixture(t)
	data, err := encodeLiveSessionKeys([]liveSessionKey{k})
	if err != nil {
		t.Fatal(err)
	}
	array := liveCBOR(t, []any{liveKeyFields(t, k)})
	duplicate := []byte{0xa2}
	for i := 0; i < 2; i++ {
		duplicate = append(duplicate, liveCBOR(t, "keys")...)
		duplicate = append(duplicate, array...)
	}
	for _, bad := range [][]byte{nil, {0xf6}, {0xa0}, duplicate, append(bytes.Clone(data), 0), make([]byte, maxLiveSessionAssertion+1),
		liveCBOR(t, map[string]any{"keys": []any{}}), liveCBOR(t, map[string]any{"keys": nil}),
		liveCBOR(t, map[string]any{"keys": []any{liveKeyFields(t, k), liveKeyFields(t, k)}}),
		liveCBOR(t, map[string]any{"keys": make([]any, maxLiveSessionKeys+1)}),
	} {
		if keys, err := decodeLiveSessionKeys(bad, der); err == nil || keys != nil {
			t.Fatal("invalid assertion accepted")
		}
	}
	for _, cert := range [][]byte{nil, append(bytes.Clone(der), 0)} {
		if _, err := decodeLiveSessionKeys(data, cert); err == nil {
			t.Fatal("wrong signer accepted")
		}
	}
	if _, err := encodeLiveSessionKeys(nil); err == nil {
		t.Fatal("empty set authored")
	}
	if _, err := encodeLiveSessionKeys([]liveSessionKey{k, k}); err == nil {
		t.Fatal("duplicate kids authored")
	}
	for _, key := range []ed25519.PrivateKey{nil, make([]byte, 32), make([]byte, 64)} {
		if _, err := newLiveSessionKey(key, k.kid, der, k.created, 10, 0); err == nil {
			t.Fatal("invalid private key accepted")
		}
	}
}

func FuzzLiveSessionKeys(f *testing.F) {
	k, _, der := liveKeyFixture(f)
	data, err := encodeLiveSessionKeys([]liveSessionKey{k})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte{0xa0})
	f.Add([]byte{0xf6})
	f.Fuzz(func(t *testing.T, data []byte) {
		keys, err := decodeLiveSessionKeys(data, der)
		if err != nil && keys != nil {
			t.Fatal("partial key admission on failure")
		}
		if err == nil && len(keys) == 0 {
			t.Fatal("empty successful assertion")
		}
	})
}
