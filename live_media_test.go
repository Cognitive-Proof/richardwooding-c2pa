package c2pa

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"io"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func signedLiveInit(t *testing.T, s *Signer, sc signingChain, kind string) []byte {
	t.Helper()
	init := liveTimedInit(1, 1000, 2000)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	der := sc.chain[0].Raw
	if kind == "wrong binding" {
		der = append(bytes.Clone(der), 0)
	}
	k, err := newLiveSessionKey(private, []byte("session"), der, time.Unix(1760000042, 0), 10, 880000021)
	if err != nil {
		t.Fatal(err)
	}
	data, err := encodeLiveSessionKeys([]liveSessionKey{k})
	if err != nil {
		t.Fatal(err)
	}
	m := createdManifest("live initialization")
	if kind != "missing" {
		m.Assertions = append(m.Assertions, Assertion{Label: liveSessionKeysLabel, Value: cbor.RawMessage(data)})
	}
	if kind == "multiple" {
		m.Assertions = append(m.Assertions, Assertion{Label: liveSessionKeysLabel + "__1", Value: cbor.RawMessage(data)})
	}
	if kind == "json" {
		m.Assertions[0] = Assertion{Label: liveSessionKeysLabel, JSON: []byte(`{"keys":[]}`)}
	}
	if kind == "excluded moov" {
		out, err := s.sign(context.Background(), BMFF, init, m, liveUnboundInitBinding{bmffFlatBinding{alg: "sha256"}})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	return signBytes(t, s, BMFF, init, m)
}

// A genuinely signed manifest whose advertised digest deliberately omits moov.
// Generic BMFF validation accepts its digest; the live profile must reject it.
type liveUnboundInitBinding struct{ bmffFlatBinding }

func (b liveUnboundInitBinding) payload(_ []byteRange, digest []byte) ([]byte, error) {
	exclusions := append(bmffStandardExclusions(), map[string]any{"xpath": "/moov"})
	return encMode.Marshal(map[string]any{"alg": b.alg, "hash": digest, "exclusions": exclusions})
}

func (b liveUnboundInitBinding) digest(ctx context.Context, data []byte, _ []byteRange) ([]byte, error) {
	exclusions, _ := decodeBMFFExclusions(append(bmffStandardExclusions(), map[string]any{"xpath": "/moov"}))
	top := parseBMFFBoxes(ctx, data)
	ranges := bmffExclusionByteRanges(ctx, data, top, exclusions)
	h, _ := hashByName(b.alg)
	if err := hashBMFFTopLevel(ctx, data, top, ranges, h); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func TestLiveMediaInitialization(t *testing.T) {
	s, sc := newTestSigner(t)
	data := signedLiveInit(t, s, sc, "valid")
	live := NewLiveMediaValidator(WithSigningTrust(sc.roots))
	if live.Initialized() || live.ManifestID() != "" {
		t.Fatal("new session already initialized")
	}
	r := live.ValidateInitSegment(context.Background(), bytes.NewReader(data))
	if !r.Valid || r.Binding != BindingVerified {
		t.Fatalf("init failed: %+v", r.Statuses)
	}
	if !live.Initialized() || live.ManifestID() != r.ActiveManifestLabel || len(live.init.keys) != 1 {
		t.Fatal("authenticated keys not admitted")
	}
	k := live.init.keys["session"]
	if k.minSequence != 880000021 || !k.permits(880000021, time.Unix(1760000042, 0)) {
		t.Fatal("key metadata lost")
	}
	// Archived media key windows are not tested against the current clock at init.
	if k.permits(880000021, time.Now()) {
		t.Fatal("fixture should be expired by wall clock")
	}
	before := bytes.Clone(live.init.signerDER)
	r.SignerChain[0].Raw[0] ^= 1
	if !bytes.Equal(before, live.init.signerDER) {
		t.Fatal("result certificate aliases admitted state")
	}
	for _, code := range []StatusCode{StatusLiveVideoInitInvalid, StatusLiveVideoManifestInvalid, StatusLiveVideoSessionKeyInvalid} {
		if code.Severity() != SeverityFailure {
			t.Fatalf("%s does not fail validation", code)
		}
	}
}

func TestLiveMediaInitializationRollback(t *testing.T) {
	s, sc := newTestSigner(t)
	live := NewLiveMediaValidator(WithSigningTrust(sc.roots))
	data := signedLiveInit(t, s, sc, "valid")
	if r := live.ValidateInitSegment(context.Background(), bytes.NewReader(data)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	previous := live.init
	for _, kind := range []string{"missing", "multiple", "json", "wrong binding"} {
		t.Run(kind, func(t *testing.T) {
			bad := signedLiveInit(t, s, sc, kind)
			// General manifest validity alone does not authorize the session keys.
			if r := Validate(context.Background(), BMFF, bytes.NewReader(bad), WithSigningTrust(sc.roots)); !r.Valid {
				t.Fatalf("test manifest is not generally valid: %v", r.Statuses)
			}
			r := live.ValidateInitSegment(context.Background(), bytes.NewReader(bad))
			if r.Valid || !r.Has(StatusLiveVideoSessionKeyInvalid) || live.init != previous {
				t.Fatalf("bad update changed session: %+v", r.Statuses)
			}
		})
	}
	badBinding := signedLiveInit(t, s, sc, "excluded moov")
	if r := Validate(context.Background(), BMFF, bytes.NewReader(badBinding), WithSigningTrust(sc.roots)); !r.Valid || r.Binding != BindingVerified {
		t.Fatalf("test hash did not verify: %+v", r.Statuses)
	}
	if r := live.ValidateInitSegment(context.Background(), bytes.NewReader(badBinding)); r.Valid || !r.Has(StatusLiveVideoManifestInvalid) || live.init != previous {
		t.Fatalf("unbound moov admitted: %+v", r.Statuses)
	}
	tampered := bytes.Clone(data)
	moov := topBox(tampered, "moov")
	tampered[moov.end-1] ^= 1
	r := live.ValidateInitSegment(context.Background(), bytes.NewReader(tampered))
	if r.Valid || !r.Has(StatusLiveVideoManifestInvalid) || live.init != previous {
		t.Fatal("tampered init admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = live.ValidateInitSegment(ctx, bytes.NewReader(data))
	if r.Valid || live.init != previous {
		t.Fatal("cancellation changed session")
	}
	// A successful explicit reinitialization replaces rather than accumulates state.
	replacement := signedLiveInit(t, s, sc, "valid")
	r = live.ValidateInitSegment(context.Background(), bytes.NewReader(replacement))
	if !r.Valid || live.init == previous || live.ManifestID() == previous.manifestID || len(live.init.keys) != 1 {
		t.Fatalf("replacement failed: %+v", r.Statuses)
	}
}

func TestLiveMediaInitTrustAndInput(t *testing.T) {
	s, sc := newTestSigner(t)
	data := signedLiveInit(t, s, sc, "valid")
	untrusted := NewLiveMediaValidator(WithSigningTrust(x509.NewCertPool()))
	r := untrusted.ValidateInitSegment(context.Background(), bytes.NewReader(data))
	if r.Valid || !r.Has(StatusLiveVideoManifestInvalid) || untrusted.Initialized() {
		t.Fatal("untrusted signer admitted")
	}
	limited := NewLiveMediaValidator(WithSigningTrust(sc.roots), WithMaxScan(64))
	if r := limited.ValidateInitSegment(context.Background(), bytes.NewReader(data)); r.Valid || limited.Initialized() {
		t.Fatal("scan-capped init admitted")
	}
	for _, input := range []io.Reader{nil, bytes.NewReader(nil), bytes.NewReader(append(bytes.Clone(data), synthBox("mdat", []byte{})...)), bytes.NewReader(append(bytes.Clone(data), 1))} {
		live := NewLiveMediaValidator(WithSigningTrust(sc.roots))
		r := live.ValidateInitSegment(context.Background(), input)
		if r.Valid || !r.Has(StatusLiveVideoInitInvalid) || live.Initialized() {
			t.Fatalf("bad input admitted: %+v", r.Statuses)
		}
	}
	var zero LiveMediaValidator
	if zero.Initialized() || zero.ManifestID() != "" {
		t.Fatal("invalid zero value")
	}
	if r := zero.ValidateInitSegment(context.Background(), nil); r.Valid {
		t.Fatal("empty input passed zero value")
	}
	var absent *LiveMediaValidator
	if absent.Initialized() || absent.ManifestID() != "" {
		t.Fatal("invalid nil receiver")
	}
	if r := absent.ValidateInitSegment(context.Background(), nil); r.Valid {
		t.Fatal("nil receiver succeeded")
	}
}

func TestLiveInitRejectsUnboundMoov(t *testing.T) {
	init, _ := unsignedFragmentedSet(1, fragOpts{})
	top := parseBMFFBoxes(context.Background(), init)
	moov, err := liveInitStructure(context.Background(), init, top)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"whole moov", "child", "subset", "merkle null", "merkle empty", "v2", "unreferenced"} {
		t.Run(kind, func(t *testing.T) {
			fields := map[string]any{"hash": bytes.Repeat([]byte{1}, 32), "alg": "sha256"}
			switch kind {
			case "whole moov":
				fields["exclusions"] = []any{map[string]any{"xpath": "/moov"}}
			case "child":
				fields["exclusions"] = []any{map[string]any{"xpath": "/moov/mvhd"}}
			case "subset":
				fields["exclusions"] = []any{map[string]any{"xpath": "/moov", "subset": []any{map[string]any{"offset": 10, "length": 1}}}}
			case "merkle null":
				fields["merkle"] = nil
			case "merkle empty":
				fields["merkle"] = []any{}
			}
			label := "c2pa.hash.bmff.v3"
			if kind == "v2" {
				label = "c2pa.hash.bmff.v2"
			}
			m := &parsedManifest{assertions: []rawAssertion{{label: label, tbox: "cbor", data: liveCBOR(t, fields)}}, claim: map[string]any{"assertions": []any{map[string]any{"url": "self#jumbf=c2pa.assertions/" + label, "hash": []byte{1}}}}}
			if kind == "unreferenced" {
				m.claim = nil
			}
			if err := liveInitBinding(context.Background(), init, top, moov, m); err == nil {
				t.Fatal("unbound init accepted")
			}
		})
	}
}

func TestLiveInitRequiresSignedSessionAssertion(t *testing.T) {
	for _, refs := range []int{0, 1, 2} {
		m := &parsedManifest{assertions: []rawAssertion{{label: liveSessionKeysLabel, tbox: "cbor"}}, claim: map[string]any{}}
		entries := []any{}
		for i := 0; i < refs; i++ {
			entries = append(entries, map[string]any{"url": "self#jumbf=c2pa.assertions/" + liveSessionKeysLabel, "hash": []byte{1}})
		}
		m.claim["assertions"] = entries
		if _, err := liveInitSessionAssertion(m); (err == nil) != (refs == 1) {
			t.Fatalf("%d signed references: %v", refs, err)
		}
	}
}
