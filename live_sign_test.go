package c2pa

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"math"
	"testing"
	"time"
)

func liveSigningConfig() LiveMediaSignerConfig {
	return LiveMediaSignerConfig{SessionKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32)), KeyID: []byte("live-signing-test"), CreatedAt: time.Unix(int64(liveTestEpochSeconds), 0), ValidityPeriod: 10, MinSequenceNumber: liveTestSequence}
}

func newLiveSigningFixture(t testing.TB) (*LiveMediaSigner, signingChain, []byte) {
	t.Helper()
	s, sc := newTestSigner(t)
	live, err := NewLiveMediaSigner(s, liveSigningConfig())
	if err != nil {
		t.Fatal(err)
	}
	init, err := live.SignInitSegment(context.Background(), bytes.NewReader(liveTimedInit(7, 90000, 180000)), createdManifest("live stream"))
	if err != nil {
		t.Fatal(err)
	}
	return live, sc, init
}

func TestLiveSigningPublicRoundTrip(t *testing.T) {
	signer, sc, init := newLiveSigningFixture(t)
	receiver := NewLiveMediaValidator(WithSigningTrust(sc.roots))
	if r := receiver.ValidateInitSegment(context.Background(), bytes.NewReader(init)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	if signer.ManifestID() == "" || signer.ManifestID() != receiver.ManifestID() {
		t.Fatal("manifest identity lost")
	}
	for _, endpoint := range []interface{ SetMediaTimeOrigin(time.Time) error }{signer, receiver} {
		if err := endpoint.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
			t.Fatal(err)
		}
	}
	for i := uint64(0); i < 3; i++ {
		source := liveMediaSource(uint32(liveTestSequence+i), (liveTestEpochSeconds+2*i)*90000, 7, 180000, 0)
		// Keep a coexisting SCTE-35 event intact through the public API.
		moof := topBox(source, "moof")
		cue := synthBox("emsg", []byte{1, 0, 0, 0}, make([]byte, 20), []byte("urn:scte:scte35:2013:bin\x00\x00cue"))
		source = bytes.Join([][]byte{source[:moof.start], cue, source[moof.start:]}, nil)
		before := bytes.Clone(source)
		signed, err := signer.SignMediaSegment(context.Background(), bytes.NewReader(source))
		if err != nil {
			t.Fatal(err)
		}
		event, box := liveTestEvent(t, signed)
		if event.id != uint32(i) || event.timescale != 90000 || event.duration != 180000 {
			t.Fatal("event metadata was not derived correctly")
		}
		if !bytes.Equal(before, source) || !bytes.Equal(append(bytes.Clone(signed[:box.start]), signed[box.end:]...), source) {
			t.Fatal("source media/events changed")
		}
		r := receiver.ValidateMediaSegment(context.Background(), bytes.NewReader(signed))
		if !r.Valid || r.SequenceNumber != liveTestSequence+i || r.Binding != BindingVerified {
			t.Fatalf("receiver: %+v", r)
		}
	}
	if signer.nextEventID != 3 || len(signer.validator.init.eventIDs) != 3 {
		t.Fatal("signer continuity not committed")
	}
}

func TestLiveSigningConfigAndCopies(t *testing.T) {
	s, _ := newTestSigner(t)
	cfg := liveSigningConfig()
	live, err := NewLiveMediaSigner(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	private, kid := bytes.Clone(live.private), bytes.Clone(live.key.kid)
	for i := range cfg.SessionKey {
		cfg.SessionKey[i] = 0
	}
	for i := range cfg.KeyID {
		cfg.KeyID[i] = 0
	}
	if !bytes.Equal(live.private, private) || !bytes.Equal(live.key.kid, kid) {
		t.Fatal("caller owns live signing key buffers")
	}
	a, err := NewLiveMediaSigner(s, LiveMediaSignerConfig{ValidityPeriod: 60})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewLiveMediaSigner(s, LiveMediaSignerConfig{ValidityPeriod: 60})
	if err != nil {
		t.Fatal(err)
	}
	if a.key.created.IsZero() || len(a.private) != ed25519.PrivateKeySize || len(a.key.kid) == 0 || bytes.Equal(a.private, b.private) || bytes.Equal(a.key.kid, b.key.kid) {
		t.Fatal("automatic session metadata generation failed")
	}
	for _, manifestSigner := range []*Signer{nil, {}} {
		if _, err := NewLiveMediaSigner(manifestSigner, liveSigningConfig()); err == nil {
			t.Fatal("uninitialized manifest signer accepted")
		}
	}
	for _, kind := range []string{"short key", "inconsistent key", "overflow period", "unsupported sequence", "oversized kid"} {
		t.Run(kind, func(t *testing.T) {
			cfg := liveSigningConfig()
			switch kind {
			case "short key":
				cfg.SessionKey = make([]byte, 32)
			case "inconsistent key":
				cfg.SessionKey[len(cfg.SessionKey)-1] ^= 1
			case "overflow period":
				cfg.ValidityPeriod = math.MaxUint64
			case "unsupported sequence":
				cfg.MinSequenceNumber = uint64(math.MaxUint32) + 1
			case "oversized kid":
				cfg.KeyID = make([]byte, maxLiveSessionAssertion)
			}
			if _, err := NewLiveMediaSigner(s, cfg); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestLiveSigningInitializationFailureAndRetry(t *testing.T) {
	s, _ := newTestSigner(t)
	live, err := NewLiveMediaSigner(s, liveSigningConfig())
	if err != nil {
		t.Fatal(err)
	}
	if live.Initialized() || live.ManifestID() != "" {
		t.Fatal("new signer already initialized")
	}
	if err := live.SetMediaTimeOrigin(time.Unix(0, 0)); err == nil {
		t.Fatal("origin accepted before init")
	}
	if out, err := live.SignMediaSegment(context.Background(), bytes.NewReader([]byte{1})); out != nil || err == nil {
		t.Fatal("media accepted before init")
	}
	plain := liveTimedInit(7, 90000, 180000)
	for _, kind := range []string{"malformed", "missing actions", "caller session keys", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			input := plain
			m := createdManifest("live stream")
			ctx := context.Background()
			switch kind {
			case "malformed":
				input = []byte{1}
			case "missing actions":
				m.Actions = nil
			case "caller session keys":
				m.Assertions = []Assertion{{Label: liveSessionKeysLabel + "__1", Value: map[string]any{"keys": []any{}}}}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			out, err := live.SignInitSegment(ctx, bytes.NewReader(input), m)
			if out != nil || err == nil || live.Initialized() {
				t.Fatal("failed init changed state or returned output")
			}
			if kind == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
		})
	}
	// Assert that adding the session assertion does not reuse the caller's backing array.
	backing := make([]Assertion, 2)
	backing[0] = Assertion{Label: "org.example.note", Value: "note"}
	backing[1] = Assertion{Label: "untouched", Value: "sentinel"}
	m := createdManifest("live stream")
	m.Assertions = backing[:1]
	if _, err := live.SignInitSegment(context.Background(), bytes.NewReader(plain), m); err != nil {
		t.Fatal(err)
	}
	if backing[1].Label != "untouched" {
		t.Fatal("caller assertion array changed")
	}
	if out, err := live.SignInitSegment(context.Background(), bytes.NewReader(plain), createdManifest("second init")); out != nil || err == nil {
		t.Fatal("session reinitialized implicitly")
	}
}

func TestLiveSigningMediaFailureAndRetry(t *testing.T) {
	live, _, _ := newLiveSigningFixture(t)
	base := liveTestEpochSeconds * 90000
	source := liveMediaSource(uint32(liveTestSequence), base, 7, 180000, 0)
	if out, err := live.SignMediaSegment(context.Background(), bytes.NewReader(source)); out != nil || err == nil || live.nextEventID != 0 {
		t.Fatal("missing origin consumed event")
	}
	if err := live.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := live.SignMediaSegment(context.Background(), bytes.NewReader(source)); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"replay", "wrong track", "expired", "malformed", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			input := liveMediaSource(uint32(liveTestSequence+1), base+180000, 7, 180000, 0)
			ctx := context.Background()
			switch kind {
			case "replay":
				input = source
			case "wrong track":
				input = liveMediaSource(uint32(liveTestSequence+1), base+180000, 8, 180000, 0)
			case "expired":
				input = liveMediaSource(uint32(liveTestSequence+1), base+20*90000, 7, 180000, 0)
			case "malformed":
				input = []byte{1}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			out, err := live.SignMediaSegment(ctx, bytes.NewReader(input))
			if out != nil || err == nil || live.nextEventID != 1 || live.validator.init.lastSequence != liveTestSequence || len(live.validator.init.eventIDs) != 1 {
				t.Fatal("failed media changed state or returned output")
			}
		})
	}
	clean := liveMediaSource(uint32(liveTestSequence+1), base+180000, 7, 180000, 0)
	signed, err := live.SignMediaSegment(context.Background(), bytes.NewReader(clean))
	if err != nil {
		t.Fatal(err)
	}
	event, _ := liveTestEvent(t, signed)
	if event.id != 1 || live.nextEventID != 2 {
		t.Fatal("failed attempts consumed event ID")
	}
}

func TestLiveSigningCancellationPoints(t *testing.T) {
	s, _ := newTestSigner(t)
	newSigner := func() *LiveMediaSigner {
		live, err := NewLiveMediaSigner(s, liveSigningConfig())
		if err != nil {
			t.Fatal(err)
		}
		return live
	}
	plain := liveTimedInit(7, 90000, 180000)
	count := newCountingContext(0)
	if _, err := newSigner().SignInitSegment(count, bytes.NewReader(plain), createdManifest("init")); err != nil {
		t.Fatal(err)
	}
	for _, point := range sweepPoints(count.total(), 24) {
		live := newSigner()
		ctx := newCountingContext(point)
		out, err := live.SignInitSegment(ctx, bytes.NewReader(plain), createdManifest("init"))
		if out != nil || !errors.Is(err, context.Canceled) || live.Initialized() {
			t.Fatalf("init cancellation at %d: %v", point, err)
		}
	}
	newInitialized := func() *LiveMediaSigner {
		live := newSigner()
		if _, err := live.SignInitSegment(context.Background(), bytes.NewReader(plain), createdManifest("init")); err != nil {
			t.Fatal(err)
		}
		if err := live.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
			t.Fatal(err)
		}
		return live
	}
	source := liveMediaSource(uint32(liveTestSequence), liveTestEpochSeconds*90000, 7, 180000, 0)
	count = newCountingContext(0)
	if _, err := newInitialized().SignMediaSegment(count, bytes.NewReader(source)); err != nil {
		t.Fatal(err)
	}
	for _, point := range sweepPoints(count.total(), 24) {
		live := newInitialized()
		ctx := newCountingContext(point)
		out, err := live.SignMediaSegment(ctx, bytes.NewReader(source))
		if out != nil || !errors.Is(err, context.Canceled) || live.nextEventID != 0 || live.validator.init.seen {
			t.Fatalf("media cancellation at %d: %v", point, err)
		}
	}
}

func TestLiveSigningTimestampedInit(t *testing.T) {
	ta := liveTSA(t)
	srv := newTSAServer(t, ta, nil)
	s, sc := newTestSigner(t, WithTimestampAuthority(srv.URL))
	live, err := NewLiveMediaSigner(s, liveSigningConfig())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := live.SignInitSegment(context.Background(), bytes.NewReader(liveTimedInit(7, 90000, 180000)), createdManifest("timestamped init"))
	if err != nil {
		t.Fatal(err)
	}
	receiver := NewLiveMediaValidator(WithSigningTrust(sc.roots), WithTimestampTrust(ta.pool()))
	r := receiver.ValidateInitSegment(context.Background(), bytes.NewReader(signed))
	if !r.Valid || !r.Has(StatusTimeStampValidated) {
		t.Fatal(r.Statuses)
	}
}

func TestLiveSigningIndexedSegments(t *testing.T) {
	for _, opt := range []fragOpts{{sidxVersion: 0}, {sidxVersion: 1, emsg: true, tfhdBase: true}} {
		s, sc := newTestSigner(t)
		cfg := liveSigningConfig()
		cfg.MinSequenceNumber = 1
		live, err := NewLiveMediaSigner(s, cfg)
		if err != nil {
			t.Fatal(err)
		}
		init, err := live.SignInitSegment(context.Background(), bytes.NewReader(liveTimedInit(1, 1000, 2000)), createdManifest("indexed live"))
		if err != nil {
			t.Fatal(err)
		}
		receiver := NewLiveMediaValidator(WithSigningTrust(sc.roots))
		if r := receiver.ValidateInitSegment(context.Background(), bytes.NewReader(init)); !r.Valid {
			t.Fatal(r.Statuses)
		}
		for _, endpoint := range []interface{ SetMediaTimeOrigin(time.Time) error }{live, receiver} {
			if err := endpoint.SetMediaTimeOrigin(cfg.CreatedAt); err != nil {
				t.Fatal(err)
			}
		}
		_, media := unsignedFragmentedSet(1, opt)
		signed, err := live.SignMediaSegment(context.Background(), bytes.NewReader(media[0]))
		if err != nil {
			t.Fatal(err)
		}
		if r := receiver.ValidateMediaSegment(context.Background(), bytes.NewReader(signed)); !r.Valid {
			t.Fatal(r.Statuses)
		}
	}
}

func TestLiveSigningIdentityAndHashPolicy(t *testing.T) {
	s, sc, identity := identityTestSigner(t, nil, WithHashAlgorithm("sha384"))
	live, err := NewLiveMediaSigner(s, liveSigningConfig())
	if err != nil {
		t.Fatal(err)
	}
	init, err := live.SignInitSegment(context.Background(), bytes.NewReader(liveTimedInit(7, 90000, 180000)), identityManifest("live identity"))
	if err != nil {
		t.Fatal(err)
	}
	receiver := NewLiveMediaValidator(WithSigningTrust(sc.roots), WithIdentityTrust(identity.roots))
	if r := receiver.ValidateInitSegment(context.Background(), bytes.NewReader(init)); !r.Valid || !r.Has(StatusIdentityTrusted) {
		t.Fatal(r.Statuses)
	}
	for _, endpoint := range []interface{ SetMediaTimeOrigin(time.Time) error }{live, receiver} {
		if err := endpoint.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
			t.Fatal(err)
		}
	}
	media, err := live.SignMediaSegment(context.Background(), bytes.NewReader(liveMediaSource(uint32(liveTestSequence), liveTestEpochSeconds*90000, 7, 180000, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if r := receiver.ValidateMediaSegment(context.Background(), bytes.NewReader(media)); !r.Valid {
		t.Fatal(r.Statuses)
	}
}
