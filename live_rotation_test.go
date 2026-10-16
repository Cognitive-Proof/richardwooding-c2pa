package c2pa

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

func rotationConfig(seed byte, kid string, offset uint64) LiveMediaSignerConfig {
	c := liveSigningConfig()
	c.SessionKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	c.KeyID = []byte(kid)
	c.MinSequenceNumber += offset
	c.ValidityPeriod = 60
	return c
}
func rotationSource(offset uint64) []byte {
	return liveMediaSource(uint32(liveTestSequence+offset), (liveTestEpochSeconds+2*offset)*90000, 7, 180000, 0)
}
func rotationReceiver(t testing.TB, sc signingChain, init []byte) *LiveMediaValidator {
	t.Helper()
	v := NewLiveMediaValidator(WithSigningTrust(sc.roots))
	if r := v.ValidateInitSegment(context.Background(), bytes.NewReader(init)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	if err := v.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	return v
}
func TestLiveRotationScheduledOverlap(t *testing.T) {
	signer, sc := newTestSigner(t)
	s, err := NewLiveMediaSigner(signer, rotationConfig(1, "old", 0))
	if err != nil {
		t.Fatal(err)
	}
	cfg := rotationConfig(2, "new", 1)
	cfg.CreatedAt = cfg.CreatedAt.Add(2 * time.Second)
	if err := s.AddSessionKey(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.SessionKey[0] ^= 1
	cfg.KeyID[0] ^= 1 // Caller does not own the retained schedule.
	init, err := s.SignInitSegment(context.Background(), bytes.NewReader(liveTimedInit(7, 90000, 180000)), createdManifest("rotation"))
	if err != nil {
		t.Fatal(err)
	}
	s.SetMediaTimeOrigin(time.Unix(0, 0))
	v := rotationReceiver(t, sc, init)
	for i, kid := range []string{"old", "new", "new"} {
		out, err := s.SignMediaSegment(context.Background(), bytes.NewReader(rotationSource(uint64(i))))
		if err != nil {
			t.Fatal(err)
		}
		e, _ := liveTestEvent(t, out)
		key := v.init.keys[kid]
		if _, err := verifyLiveVSI(e.payload, key, v.ManifestID()); err != nil {
			t.Fatalf("wrong selected key: %v", err)
		}
		if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(out)); !r.Valid {
			t.Fatal(r.Statuses)
		}
	}
	// The older key remains valid within its overlapping window.
	out, err := buildLiveVSISegment(context.Background(), rotationSource(3), s.schedule[0].private, []byte("old"), s.ManifestID(), liveTestSequence+3, liveEvent{timescale: 90000, duration: 180000, id: 3})
	if err != nil {
		t.Fatal(err)
	}
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(out)); !r.Valid {
		t.Fatal(r.Statuses)
	}
}

func TestLiveRotationAnnouncementTransactional(t *testing.T) {
	s, sc, init := newLiveSigningFixture(t)
	s.SetMediaTimeOrigin(time.Unix(0, 0))
	first, err := s.SignMediaSegment(context.Background(), bytes.NewReader(rotationSource(0)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddSessionKey(rotationConfig(2, "rotated", 1)); err != nil {
		t.Fatal(err)
	}
	before := s.validator.init
	eventID := s.nextEventID
	if out, err := s.SignMediaSegment(context.Background(), bytes.NewReader(rotationSource(1))); err == nil || out != nil {
		t.Fatal("unannounced keys used")
	}
	// A failed sequence attempt does not consume pending keys or event IDs.
	if out, err := s.SignMediaSegmentWithManifest(context.Background(), bytes.NewReader(rotationSource(0)), createdManifest("replay")); err == nil || out != nil {
		t.Fatal("signed repeated sequence")
	}
	if s.validator.init != before || s.nextEventID != eventID || !s.needsAnnouncement {
		t.Fatal("failed authoring changed state")
	}
	announcement, err := s.SignMediaSegmentWithManifest(context.Background(), bytes.NewReader(rotationSource(1)), createdManifest("new keys"))
	if err != nil {
		t.Fatal(err)
	}
	if s.ManifestID() == before.manifestID || s.needsAnnouncement || len(s.validator.init.manifests) != 2 {
		t.Fatal("announcement not committed")
	}
	fresh := func() *LiveMediaValidator {
		v := rotationReceiver(t, sc, init)
		if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(first)); !r.Valid {
			t.Fatal(r.Statuses)
		}
		return v
	}
	for _, kind := range []string{"sample", "signature", "untrusted", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			v := fresh()
			state := v.init
			data := bytes.Clone(announcement)
			ctx := context.Background()
			switch kind {
			case "sample":
				data[len(data)-1] ^= 1
			case "signature":
				_, box := liveTestEvent(t, data)
				data[box.end-1] ^= 1
			case "untrusted":
				v.cfg.signingTrust = x509.NewCertPool()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if r := v.ValidateMediaSegment(ctx, bytes.NewReader(data)); r.Valid {
				t.Fatal("invalid announcement accepted")
			}
			if v.init != state || len(v.init.manifests) != 1 || v.init.lastSequence != liveTestSequence || len(v.init.eventIDs) != 1 {
				t.Fatal("failed announcement changed state")
			}
			v.cfg.signingTrust = sc.roots
			if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(announcement)); !r.Valid {
				t.Fatal(r.Statuses)
			}
		})
	}
	v := fresh()
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(announcement)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	if len(v.init.manifests) != 2 || !v.init.seen || v.init.origin == nil || len(v.init.eventIDs) != 2 {
		t.Fatal("history lost")
	}
	// Earlier keys retain their original authorizing manifest association.
	old, err := buildLiveVSISegment(context.Background(), rotationSource(2), s.schedule[0].private, s.schedule[0].key.kid, before.manifestID, liveTestSequence+2, liveEvent{timescale: 90000, duration: 180000, id: 2})
	if err != nil {
		t.Fatal(err)
	}
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(old)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	if v.ManifestID() != s.ManifestID() {
		t.Fatal("old key reference rolled back active announcement")
	}
	next, err := s.SignMediaSegment(context.Background(), bytes.NewReader(rotationSource(3)))
	if err != nil {
		t.Fatal(err)
	}
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(next)); r.Valid {
		t.Fatal("reused event ID accepted")
	}
	// A distinct fresh receiver accepts ordinary segments after the update.
	v = fresh()
	v.ValidateMediaSegment(context.Background(), bytes.NewReader(announcement))
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(next)); !r.Valid {
		t.Fatal(r.Statuses)
	}
}

func TestLiveRotationManifestKeyAssociation(t *testing.T) {
	manifestSigner, sc := newTestSigner(t)
	makeSigner := func(cfg LiveMediaSignerConfig) (*LiveMediaSigner, []byte) {
		s, err := NewLiveMediaSigner(manifestSigner, cfg)
		if err != nil {
			t.Fatal(err)
		}
		init, err := s.SignInitSegment(context.Background(), bytes.NewReader(liveTimedInit(7, 90000, 180000)), createdManifest("init"))
		if err != nil {
			t.Fatal(err)
		}
		s.SetMediaTimeOrigin(time.Unix(0, 0))
		return s, init
	}
	old, init := makeSigner(rotationConfig(1, "same-id", 0))
	replacement, _ := makeSigner(rotationConfig(2, "same-id", 1))
	v := rotationReceiver(t, sc, init)
	first, err := old.SignMediaSegment(context.Background(), bytes.NewReader(rotationSource(0)))
	if err != nil {
		t.Fatal(err)
	}
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(first)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	// IDs are scoped to a manifest, so the new manifest can authorize another key
	// with the same kid without overwriting the old manifest's association.
	replacement.nextEventID = 1
	update, err := replacement.SignMediaSegmentWithManifest(context.Background(), bytes.NewReader(rotationSource(1)), createdManifest("replacement"))
	if err != nil {
		t.Fatal(err)
	}
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(update)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	bad, err := buildLiveVSISegment(context.Background(), rotationSource(2), replacement.private, replacement.key.kid, old.ManifestID(), liveTestSequence+2, liveEvent{timescale: 90000, duration: 180000, id: 2})
	if err != nil {
		t.Fatal(err)
	}
	state := v.init
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(bad)); r.Valid {
		t.Fatal("key crossed manifest association")
	}
	if v.init != state {
		t.Fatal("failed association changed state")
	}
	good, err := buildLiveVSISegment(context.Background(), rotationSource(2), old.private, old.key.kid, old.ManifestID(), liveTestSequence+2, liveEvent{timescale: 90000, duration: 180000, id: 2})
	if err != nil {
		t.Fatal(err)
	}
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(good)); !r.Valid {
		t.Fatal(r.Statuses)
	}
}

func TestLiveRotationScheduleRejectsInvalid(t *testing.T) {
	s, _, _ := newLiveSigningFixture(t)
	if err := s.AddSessionKey(liveSigningConfig()); err == nil {
		t.Fatal("duplicate key accepted")
	}
	s.SetMediaTimeOrigin(time.Unix(0, 0))
	if _, err := s.SignMediaSegment(context.Background(), bytes.NewReader(rotationSource(0))); err != nil {
		t.Fatal(err)
	}
	if err := s.AddSessionKey(rotationConfig(2, "backdated", 0)); err == nil {
		t.Fatal("backdated key scheduled")
	}
	if len(s.schedule) != 1 || s.needsAnnouncement {
		t.Fatal("failed schedule mutation")
	}
	if err := s.AddSessionKey(rotationConfig(3, "new", 1)); err != nil {
		t.Fatal(err)
	}
	if out, err := s.SignMediaSegmentWithManifest(context.Background(), bytes.NewReader(rotationSource(2)), createdManifest("late")); err == nil || out != nil {
		t.Fatal("late new key announcement accepted")
	}
}

func TestLiveRotationTimestampedAnnouncement(t *testing.T) {
	ta := liveTSA(t)
	srv := newTSAServer(t, ta, nil)
	ms, sc := newTestSigner(t, WithTimestampAuthority(srv.URL))
	s, err := NewLiveMediaSigner(ms, liveSigningConfig())
	if err != nil {
		t.Fatal(err)
	}
	init, err := s.SignInitSegment(context.Background(), bytes.NewReader(liveTimedInit(7, 90000, 180000)), createdManifest("timestamped"))
	if err != nil {
		t.Fatal(err)
	}
	s.SetMediaTimeOrigin(time.Unix(0, 0))
	v := NewLiveMediaValidator(WithSigningTrust(sc.roots), WithTimestampTrust(ta.pool()))
	if r := v.ValidateInitSegment(context.Background(), bytes.NewReader(init)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	v.SetMediaTimeOrigin(time.Unix(0, 0))
	out, err := s.SignMediaSegmentWithManifest(context.Background(), bytes.NewReader(rotationSource(0)), createdManifest("timestamped update"))
	if err != nil {
		t.Fatal(err)
	}
	if r := Validate(context.Background(), BMFF, bytes.NewReader(out), WithSigningTrust(sc.roots), WithTimestampTrust(ta.pool())); !r.Valid || !r.Has(StatusTimeStampValidated) {
		t.Fatal(r.Statuses)
	}
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(out)); !r.Valid {
		t.Fatal(r.Statuses)
	}
}

func TestLiveRotationRejectsBackdatedAnnouncementAndReplay(t *testing.T) {
	s, sc, init := newLiveSigningFixture(t)
	s.SetMediaTimeOrigin(time.Unix(0, 0))
	first, err := s.SignMediaSegment(context.Background(), bytes.NewReader(rotationSource(0)))
	if err != nil {
		t.Fatal(err)
	}
	// Model a malicious publisher announcing an already-usable, previously
	// undisclosed key. Its own cache is pre-populated only to build this negative
	// vector; the receiver still must enforce the newly announced sequence floor.
	other, err := NewLiveMediaSigner(s.manifestSigner, rotationConfig(5, "backdated", 0))
	if err != nil {
		t.Fatal(err)
	}
	s.schedule = append(s.schedule, other.schedule[0])
	s.validator.init.keys[string(other.key.kid)] = other.key
	bad, err := s.SignMediaSegmentWithManifest(context.Background(), bytes.NewReader(rotationSource(1)), createdManifest("backdated"))
	if err != nil {
		t.Fatal(err)
	}
	v := rotationReceiver(t, sc, init)
	v.ValidateMediaSegment(context.Background(), bytes.NewReader(first))
	before := v.init
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(bad)); r.Valid || !r.Has(StatusLiveVideoSessionKeyInvalid) {
		t.Fatal(r.Statuses)
	}
	if v.init != before || len(v.init.keys) != 1 {
		t.Fatal("backdated key installed")
	}
	// A valid update can be retried after the failure. Replaying it after a
	// later announcement cannot reinstate its old active manifest or keys.
	s, sc, init = newLiveSigningFixture(t)
	s.SetMediaTimeOrigin(time.Unix(0, 0))
	v = rotationReceiver(t, sc, init)
	a, err := s.SignMediaSegmentWithManifest(context.Background(), bytes.NewReader(rotationSource(0)), createdManifest("A"))
	if err != nil {
		t.Fatal(err)
	}
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(a)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	b, err := s.SignMediaSegmentWithManifest(context.Background(), bytes.NewReader(rotationSource(1)), createdManifest("B"))
	if err != nil {
		t.Fatal(err)
	}
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(b)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	before = v.init
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(a)); r.Valid || !r.Has(StatusLiveVideoManifestInvalid) {
		t.Fatal(r.Statuses)
	}
	if v.init != before || v.ManifestID() != s.ManifestID() {
		t.Fatal("old announcement rolled back session")
	}
}

func TestLiveRotationAnnouncementLimitsAndLayouts(t *testing.T) {
	s, sc, init := newLiveSigningFixture(t)
	s.SetMediaTimeOrigin(time.Unix(0, 0))
	source := rotationSource(0)
	// Indexed announcements require an additional fixpoint rewrite and are
	// deliberately refused by this writer, even though ordinary VSI supports sidx.
	indexed := append(synthBox("sidx", make([]byte, 24)), source...)
	before := s.validator.init
	if out, err := s.SignMediaSegmentWithManifest(context.Background(), bytes.NewReader(indexed), createdManifest("indexed")); err == nil || out != nil {
		t.Fatal("indexed announcement accepted")
	}
	if s.validator.init != before || s.nextEventID != 0 {
		t.Fatal("failed layout consumed state")
	}
	out, err := s.SignMediaSegmentWithManifest(context.Background(), bytes.NewReader(source), createdManifest("limit"))
	if err != nil {
		t.Fatal(err)
	}
	v := rotationReceiver(t, sc, init)
	for i := len(v.init.manifests); i < maxLiveManifests; i++ {
		v.init.manifests[string(rune(i))] = liveKeyManifest{}
	}
	before = v.init
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(out)); r.Valid || !r.Has(StatusLiveVideoManifestInvalid) {
		t.Fatal(r.Statuses)
	}
	if v.init != before || v.init.seen {
		t.Fatal("limit failure changed state")
	}
}

func TestLiveRotationCancellationPoints(t *testing.T) {
	ms, sc := newTestSigner(t)
	initialized := func() (*LiveMediaSigner, []byte) {
		s, err := NewLiveMediaSigner(ms, liveSigningConfig())
		if err != nil {
			t.Fatal(err)
		}
		init, err := s.SignInitSegment(context.Background(), bytes.NewReader(liveTimedInit(7, 90000, 180000)), createdManifest("init"))
		if err != nil {
			t.Fatal(err)
		}
		s.SetMediaTimeOrigin(time.Unix(0, 0))
		if err := s.AddSessionKey(rotationConfig(9, "next", 0)); err != nil {
			t.Fatal(err)
		}
		return s, init
	}
	s, init := initialized()
	count := newCountingContext(0)
	announcement, err := s.SignMediaSegmentWithManifest(count, bytes.NewReader(rotationSource(0)), createdManifest("announcement"))
	if err != nil {
		t.Fatal(err)
	}
	for _, point := range sweepPoints(count.total(), 24) {
		s, _ := initialized()
		before := s.validator.init
		out, err := s.SignMediaSegmentWithManifest(newCountingContext(point), bytes.NewReader(rotationSource(0)), createdManifest("announcement"))
		if out != nil || !errors.Is(err, context.Canceled) || s.validator.init != before || !s.needsAnnouncement || s.nextEventID != 0 {
			t.Fatalf("sign cancellation at %d: %v", point, err)
		}
	}
	v := rotationReceiver(t, sc, init)
	count = newCountingContext(0)
	if r := v.ValidateMediaSegment(count, bytes.NewReader(announcement)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	for _, point := range sweepPoints(count.total(), 24) {
		v := rotationReceiver(t, sc, init)
		before := v.init
		r := v.ValidateMediaSegment(newCountingContext(point), bytes.NewReader(announcement))
		if r.Valid || v.init != before || len(v.init.manifests) != 1 || v.init.seen || len(v.init.eventIDs) != 0 {
			t.Fatalf("receiver cancellation at %d: %+v", point, r)
		}
	}
}

func TestLiveRotationAnnouncementExclusions(t *testing.T) {
	s, _, _ := newLiveSigningFixture(t)
	s.SetMediaTimeOrigin(time.Unix(0, 0))
	out, err := s.SignMediaSegmentWithManifest(context.Background(), bytes.NewReader(rotationSource(0)), createdManifest("binding"))
	if err != nil {
		t.Fatal(err)
	}
	m := parseStore(context.Background(), extractJUMBF(context.Background(), BMFF, out)).active()
	if err := liveAnnouncementBinding(m); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []any{
		map[string]any{"xpath": "/moof"}, map[string]any{"xpath": "/mdat"},
		map[string]any{"xpath": "/uuid"}, map[string]any{"xpath": "/emsg"},
		map[string]any{"xpath": "/emsg", "data": []any{map[string]any{"offset": 12, "value": []byte(liveVSIScheme)}}, "subset": []any{map[string]any{"offset": 0, "length": 8}}},
	} {
		candidate := *m
		candidate.assertions = append([]rawAssertion(nil), m.assertions...)
		for i := range candidate.assertions {
			a := &candidate.assertions[i]
			if a.label != "c2pa.hash.bmff.v3" {
				continue
			}
			a.data = liveCBOR(t, map[string]any{"alg": "sha256", "hash": make([]byte, 32), "exclusions": append(announcementExclusions(), extra)})
		}
		if err := liveAnnouncementBinding(&candidate); err == nil {
			t.Fatalf("unsafe announcement exclusion accepted: %+v", extra)
		}
	}
	// The legacy unterminated VSI scheme remains accepted during the transition.
	candidate := *m
	candidate.assertions = append([]rawAssertion(nil), m.assertions...)
	for i := range candidate.assertions {
		if a := &candidate.assertions[i]; a.label == "c2pa.hash.bmff.v3" {
			a.data = liveCBOR(t, map[string]any{"alg": "sha256", "hash": make([]byte, 32), "exclusions": append(bmffStandardExclusions(), liveVSIExclusionsFor(liveVSIScheme)...)})
		}
	}
	if err := liveAnnouncementBinding(&candidate); err != nil {
		t.Fatalf("legacy announcement exclusion rejected: %v", err)
	}
}
