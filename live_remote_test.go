package c2pa

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/ocsp"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type liveRemoteFixture struct {
	initial []byte
	remote  *LiveMediaSigner
	chain   signingChain
}

func newLiveRemoteFixture(t testing.TB) liveRemoteFixture {
	t.Helper()
	ms, sc := newTestSigner(t)
	initFor := func(seed byte) (*LiveMediaSigner, []byte) {
		s, err := NewLiveMediaSigner(ms, rotationConfig(seed, "remote-key", 0))
		if err != nil {
			t.Fatal(err)
		}
		init, err := s.SignInitSegment(context.Background(), bytes.NewReader(liveTimedInit(7, 90000, 180000)), createdManifest("remote init"))
		if err != nil {
			t.Fatal(err)
		}
		s.SetMediaTimeOrigin(time.Unix(0, 0))
		return s, init
	}
	_, initial := initFor(1)
	remote, second := initFor(2)
	if len(initial) != len(second) {
		t.Fatal("fixture init layouts differ")
	}
	return liveRemoteFixture{initial, remote, sc}
}
func (f liveRemoteFixture) receiver(t testing.TB, opts ...ValidateOption) *LiveMediaValidator {
	t.Helper()
	v := NewLiveMediaValidator(append([]ValidateOption{WithSigningTrust(f.chain.roots)}, opts...)...)
	if r := v.ValidateInitSegment(context.Background(), bytes.NewReader(f.initial)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	v.SetMediaTimeOrigin(time.Unix(0, 0))
	return v
}
func (f liveRemoteFixture) media(t testing.TB, offset uint64, ref *liveManifestReference) []byte {
	t.Helper()
	out, err := buildLiveVSISegmentWithReference(context.Background(), rotationSource(offset), f.remote.private, f.remote.key.kid, f.remote.ManifestID(), liveTestSequence+offset, liveEvent{timescale: 90000, duration: 180000, id: uint32(offset)}, ref)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLiveRemoteManifestAndCache(t *testing.T) {
	f := newLiveRemoteFixture(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Cookie") != "" {
			t.Error("cookies forwarded")
		}
		w.Write(f.remote.ManifestStore())
	}))
	defer server.Close()
	if err := f.remote.SetManifestURI(server.URL + "/store"); err != nil {
		t.Fatal(err)
	}
	first := f.media(t, 0, f.remote.manifestRef)
	disabled := f.receiver(t)
	if r := disabled.ValidateMediaSegment(context.Background(), bytes.NewReader(first)); r.Valid || calls.Load() != 0 {
		t.Fatal("default validator fetched remote manifest")
	}
	v := f.receiver(t, WithLiveRemoteManifests(LiveRemoteManifestPolicy{AllowedOrigins: []string{server.URL}}))
	for i := uint64(0); i < 3; i++ {
		out := f.media(t, i, f.remote.manifestRef)
		if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(out)); !r.Valid {
			t.Fatal(r.Statuses)
		}
	}
	if calls.Load() != 1 || len(v.init.manifests) != 2 {
		t.Fatal("verified cache was not reused")
	}
	// Cached pins are checked even when the signing key is already known.
	bad := *f.remote.manifestRef
	bad.hash = bytes.Clone(bad.hash)
	bad.hash[0] ^= 1
	prior := v.init
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(f.media(t, 3, &bad))); r.Valid {
		t.Fatal("cached digest mismatch accepted")
	}
	if v.init != prior || calls.Load() != 1 {
		t.Fatal("bad cached pin changed state or fetched")
	}
	exposed := f.remote.ManifestStore()
	exposed[0] ^= 1
	if bytes.Equal(exposed, f.remote.ManifestStore()) {
		t.Fatal("caller mutated store")
	}
	if err := f.remote.SetManifestURI("file:///manifest"); err == nil {
		t.Fatal("unsafe URI accepted")
	}
	if err := f.remote.SetManifestURI(""); err != nil || f.remote.manifestRef != nil {
		t.Fatal("reference not cleared")
	}
}

func TestLiveRemoteFailuresAreTransactional(t *testing.T) {
	f := newLiveRemoteFixture(t)
	for _, kind := range []string{"digest", "size", "body-limit", "length-limit", "redirect", "status", "timeout", "body-timeout", "untrusted", "wrong-id", "binding", "media-tamper", "signature-tamper", "canceled", "origin", "invalid-policy"} {
		t.Run(kind, func(t *testing.T) {
			f := f
			store := f.remote.ManifestStore()
			var requests atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("redirect followed") }))
			defer target.Close()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				switch kind {
				case "digest":
					w.Write([]byte("different store"))
					return
				case "redirect":
					http.Redirect(w, r, target.URL, http.StatusFound)
					return
				case "status":
					w.WriteHeader(http.StatusNotFound)
					return
				case "timeout":
					<-r.Context().Done()
					return
				case "body-timeout":
					w.Write([]byte{1})
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				case "length-limit":
					w.Header().Set("Content-Length", fmt.Sprint(len(store)+1000))
				case "body-limit":
					w.(http.Flusher).Flush()
					w.Write(bytes.Repeat([]byte{1}, 4096))
					return
				}
				w.Write(store)
			}))
			defer srv.Close()
			f.remote.SetManifestURI(srv.URL + "/store")
			ref := *f.remote.manifestRef
			p := LiveRemoteManifestPolicy{AllowedOrigins: []string{srv.URL}, Timeout: 50 * time.Millisecond}
			if kind == "size" {
				n := uint64(1)
				ref.size = &n
			}
			if kind == "body-limit" || kind == "length-limit" {
				p.MaxBytes = 1024
				ref.size = nil
			}
			if kind == "origin" {
				p.AllowedOrigins = []string{target.URL}
			}
			if kind == "invalid-policy" {
				p.MaxBytes = -1
			}
			v := f.receiver(t, WithLiveRemoteManifests(p))
			if kind == "untrusted" {
				v.cfg.signingTrust = x509.NewCertPool()
			}
			if kind == "wrong-id" { // Valid digest and signature, wrong manifest identity.
				f2 := *f.remote
				f2.validator = &LiveMediaValidator{init: cloneLiveState(f.remote.validator.init)}
				f2.validator.init.manifestID = "urn:c2pa:00000000-0000-0000-0000-000000000000"
				f.remote = &f2
			}
			if kind == "binding" {
				v.init.initData = bytes.Clone(v.init.initData)
				v.init.initData[len(v.init.initData)-1] ^= 1
			}
			out := f.media(t, 0, &ref)
			if kind == "media-tamper" {
				out[len(out)-1] ^= 1
			}
			if kind == "signature-tamper" {
				_, b := liveTestEvent(t, out)
				out[b.end-1] ^= 1
			}
			ctx := context.Background()
			if kind == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			before := v.init
			if r := v.ValidateMediaSegment(ctx, bytes.NewReader(out)); r.Valid {
				t.Fatal("bad remote segment accepted")
			}
			if v.init != before || len(v.init.manifests) != 1 || v.init.seen || len(v.init.eventIDs) != 0 {
				t.Fatal("failed resolution committed state")
			}
			if (kind == "origin" || kind == "invalid-policy" || kind == "canceled") && requests.Load() != 0 {
				t.Fatal("policy failed after network call")
			}
		})
	}
}

func TestLiveCredentialRevocationRecheck(t *testing.T) {
	issuer, issuerKey := newTestCA(t)
	var status atomic.Int32
	var calls atomic.Int32
	var leaf *x509.Certificate
	var stale atomic.Bool
	now := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		next := now.Add(time.Hour)
		if stale.Load() {
			next = now.Add(-time.Minute)
		}
		answer, err := ocsp.CreateResponse(issuer, issuer, ocsp.Response{SerialNumber: leaf.SerialNumber, Status: int(status.Load()), ThisUpdate: now.Add(-2 * time.Minute), NextUpdate: next, RevokedAt: now.Add(-time.Minute)}, issuerKey)
		if err != nil {
			t.Error(err)
			return
		}
		w.Write(answer)
	}))
	defer srv.Close()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(123), Subject: pkix.Name{CommonName: "live test signer", Organization: []string{"live tests"}}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, BasicConstraintsValid: true, OCSPServer: []string{srv.URL}}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := NewSigner(key, []*x509.Certificate{leaf, issuer})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewLiveMediaSigner(ms, rotationConfig(1, "ocsp", 0))
	if err != nil {
		t.Fatal(err)
	}
	init, err := s.SignInitSegment(context.Background(), bytes.NewReader(liveTimedInit(7, 90000, 180000)), createdManifest("revocation"))
	if err != nil {
		t.Fatal(err)
	}
	s.SetMediaTimeOrigin(time.Unix(0, 0))
	pool := x509.NewCertPool()
	pool.AddCert(issuer)
	clock := now
	v := NewLiveMediaValidator(WithSigningTrust(pool), WithClock(func() time.Time { return clock }), WithOnlineRevocation(true), WithLiveSessionPolicy(LiveSessionPolicy{RevocationRecheckInterval: time.Minute}))
	if r := v.ValidateInitSegment(context.Background(), bytes.NewReader(init)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	v.SetMediaTimeOrigin(time.Unix(0, 0))
	first, err := s.SignMediaSegment(context.Background(), bytes.NewReader(rotationSource(0)))
	if err != nil {
		t.Fatal(err)
	}
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(first)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	checked := calls.Load()
	status.Store(int32(ocsp.Revoked))
	second, err := s.SignMediaSegment(context.Background(), bytes.NewReader(rotationSource(1)))
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(30 * time.Second)
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(second)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	if calls.Load() != checked {
		t.Fatal("revocation rechecked before configured interval")
	}
	third, err := s.SignMediaSegment(context.Background(), bytes.NewReader(rotationSource(2)))
	if err != nil {
		t.Fatal(err)
	}
	before := v.init
	clock = clock.Add(31 * time.Second)
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(third)); r.Valid || !r.Has(StatusSigningCredentialRevoked) || !r.Has(StatusLiveVideoSessionKeyInvalid) {
		t.Fatal(r.Statuses)
	}
	if calls.Load() != checked+1 || v.init != before {
		t.Fatal("revocation failure changed state or skipped recheck")
	}
	// A network/parse failure retains the existing informational unknown policy.
	status.Store(int32(ocsp.Unknown))
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(third)); !r.Valid || !r.Has(StatusRevocationUnknown) {
		t.Fatal(r.Statuses)
	}
	stale.Store(true)
	status.Store(int32(ocsp.Revoked))
	clock = clock.Add(61 * time.Second)
	fourth, err := s.SignMediaSegment(context.Background(), bytes.NewReader(rotationSource(3)))
	if err != nil {
		t.Fatal(err)
	}
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(fourth)); !r.Valid || !r.Has(StatusRevocationUnknown) || r.Has(StatusSigningCredentialRevoked) {
		t.Fatal("stale OCSP answer was authoritative", r.Statuses)
	}
}

func TestLiveMonotonicEventsAndCredentialExpiry(t *testing.T) {
	s, sc, init := newLiveSigningFixture(t)
	s.SetMediaTimeOrigin(time.Unix(0, 0))
	now := time.Now()
	v := NewLiveMediaValidator(WithSigningTrust(sc.roots), WithClock(func() time.Time { return now }), WithLiveSessionPolicy(LiveSessionPolicy{MonotonicEventIDs: true}))
	if r := v.ValidateInitSegment(context.Background(), bytes.NewReader(init)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	v.SetMediaTimeOrigin(time.Unix(0, 0))
	makeSegment := func(n uint64, id uint32) []byte {
		out, err := buildLiveVSISegment(context.Background(), rotationSource(n), s.private, s.key.kid, s.ManifestID(), liveTestSequence+n, liveEvent{timescale: 90000, duration: 180000, id: id})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for n, id := range []uint32{0, 65536, 0xfffffffe} {
		if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(makeSegment(uint64(n), id))); !r.Valid {
			t.Fatal(r.Statuses)
		}
	}
	if len(v.init.eventIDs) != 0 {
		t.Fatal("monotonic policy retained exact history")
	}
	before := v.init
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(makeSegment(3, 1))); r.Valid {
		t.Fatal("wrapped event ID accepted")
	}
	if v.init != before {
		t.Fatal("event failure advanced")
	}
	now = sc.chain[0].NotAfter.Add(time.Second)
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(makeSegment(3, 0xffffffff))); r.Valid || !r.Has(StatusLiveVideoSessionKeyInvalid) {
		t.Fatal(r.Statuses)
	}
	if v.init != before {
		t.Fatal("credential expiry advanced state")
	}
	now = time.Now()
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(makeSegment(3, 0xffffffff))); !r.Valid {
		t.Fatal(r.Statuses)
	}
}

func TestLiveRemoteReferenceSchema(t *testing.T) {
	for _, value := range []any{nil, map[string]any{}, map[string]any{"url": "https://example.org/a", "hash": make([]byte, 32)}, map[string]any{"url": "file:///a", "alg": "sha256", "hash": make([]byte, 32)}, map[string]any{"url": "https://user:secret@example.org/a", "alg": "sha256", "hash": make([]byte, 32)}, map[string]any{"url": "https://example.org/a#fragment", "alg": "sha256", "hash": make([]byte, 32)}, map[string]any{"url": "https://example.org/a", "alg": "sha256", "hash": make([]byte, 31)}, map[string]any{"url": "https://example.org/a", "alg": "sha256", "hash": make([]byte, 32), "size": -1}} {
		if _, err := decodeLiveManifestReference(liveCBOR(t, value)); err == nil {
			t.Fatalf("invalid reference accepted: %+v", value)
		}
	}
}

// A detached writer for independent media-binding vectors: use the normal
// signing pipeline, placing the store in an excluded trailing box so removing
// that box afterwards leaves all hashed media coordinates unchanged.
type liveDetachedTestWriter struct {
	liveAnnouncementBindingWriter
	store []byte
}

func (b *liveDetachedTestWriter) embedder() embedder { return b }
func (b *liveDetachedTestWriter) embed(ctx context.Context, asset, store []byte) ([]byte, []byteRange, error) {
	b.store = bytes.Clone(store)
	box, err := c2paBoxBytes("manifest", store)
	if err != nil {
		return nil, nil, err
	}
	return append(bytes.Clone(asset), box...), nil, ctx.Err()
}
func (b *liveDetachedTestWriter) validateOutput(ctx context.Context, asset []byte, opts []ValidateOption) ValidationResult {
	return NewLiveMediaValidator(opts...).validateLiveDetached(ctx, b.store, asset)
}

func TestLiveRemoteMediaBinding(t *testing.T) {
	f := newLiveRemoteFixture(t)
	var store []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(store) }))
	defer srv.Close()
	s := f.remote
	ref := &liveManifestReference{url: srv.URL + "/store", alg: "sha256", hash: make([]byte, 32)}
	placeholder, _ := newManifestLabel("")
	source := rotationSource(1)
	draft, err := buildLiveVSISegmentWithReference(context.Background(), source, s.private, s.key.kid, placeholder, liveTestSequence+1, liveEvent{timescale: 90000, duration: 180000, id: 1}, ref)
	if err != nil {
		t.Fatal(err)
	}
	m := createdManifest("detached media binding")
	// Newly announced media-bound key must start at this segment, not earlier.
	key := s.key
	key.minSequence = liveTestSequence + 1
	keys, err := encodeLiveSessionKeys([]liveSessionKey{key})
	if err != nil {
		t.Fatal(err)
	}
	m.Assertions = []Assertion{{Label: liveSessionKeysLabel, Value: cbor.RawMessage(keys)}}
	writer := &liveDetachedTestWriter{liveAnnouncementBindingWriter: liveAnnouncementBindingWriter{bmffFlatBinding: bmffFlatBinding{alg: "sha256"}}}
	asset, err := s.manifestSigner.sign(context.Background(), BMFF, draft, m, writer)
	if err != nil {
		t.Fatal(err)
	}
	store = writer.store
	boxes := parseBMFFBoxes(context.Background(), asset)
	last := boxes[len(boxes)-1]
	if last.typ != "uuid" || last.usertype != c2paBoxUUID {
		t.Fatal("missing trailing test store")
	}
	asset = asset[:last.start]
	manifest := parseStore(context.Background(), store).active()
	h, _ := hashByName("sha256")
	h.Write(store)
	ref.hash = h.Sum(nil)
	event, box := liveTestEvent(t, asset)
	ex, _ := decodeBMFFExclusions(liveVSIExclusions())
	digest, err := liveVSIHash(context.Background(), asset, "sha256", ex)
	if err != nil {
		t.Fatal(err)
	}
	hash := liveCBOR(t, map[string]any{"alg": "sha256", "hash": digest, "exclusions": liveVSIExclusions()})
	event.payload, err = signLiveVSI(s.private, s.key.kid, liveVSIInfo{sequence: liveTestSequence + 1, manifestID: manifest.label, bmffHash: hash, manifestRef: ref})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeLiveEMSG(event)
	if err != nil || len(encoded) != box.end-box.start {
		t.Fatal("detached vector layout changed", err)
	}
	copy(asset[box.start:box.end], encoded)
	v := f.receiver(t, WithLiveRemoteManifests(LiveRemoteManifestPolicy{AllowedOrigins: []string{srv.URL}}))
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(asset)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	if v.ManifestID() != manifest.label || len(v.init.manifests) != 2 {
		t.Fatal("media-bound remote manifest not admitted")
	}
}

func TestLiveSignerRemoteReferenceAndSessionPolicy(t *testing.T) {
	ms, sc := newTestSigner(t)
	cfg := rotationConfig(1, "long", 0)
	cfg.SessionPolicy = LiveSessionPolicy{MonotonicEventIDs: true, MaxManifests: 128}
	s, err := NewLiveMediaSigner(ms, cfg)
	if err != nil {
		t.Fatal(err)
	}
	init, err := s.SignInitSegment(context.Background(), bytes.NewReader(liveTimedInit(7, 90000, 180000)), createdManifest("long session"))
	if err != nil {
		t.Fatal(err)
	}
	s.SetMediaTimeOrigin(time.Unix(0, 0))
	if err := s.SetManifestURI("https://example.invalid/store"); err != nil {
		t.Fatal(err)
	}
	v := NewLiveMediaValidator(WithSigningTrust(sc.roots), WithLiveSessionPolicy(cfg.SessionPolicy))
	if r := v.ValidateInitSegment(context.Background(), bytes.NewReader(init)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	v.SetMediaTimeOrigin(time.Unix(0, 0))
	s.nextEventID = maxLiveEventIDs + 1
	out, err := s.SignMediaSegment(context.Background(), bytes.NewReader(rotationSource(0)))
	if err != nil {
		t.Fatal(err)
	}
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(out)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	if len(v.init.eventIDs) != 0 || len(s.validator.init.eventIDs) != 0 {
		t.Fatal("signer or receiver retained event history")
	}
	old := s.ManifestStore()
	_, err = s.SignMediaSegmentWithManifest(context.Background(), bytes.NewReader(rotationSource(1)), createdManifest("new store"))
	if err != nil {
		t.Fatal(err)
	}
	if s.manifestRef != nil || bytes.Equal(old, s.ManifestStore()) {
		t.Fatal("stale remote reference survived announcement")
	}
}

func TestLiveSessionPolicyLimits(t *testing.T) {
	s, sc, init := newLiveSigningFixture(t)
	s.SetMediaTimeOrigin(time.Unix(0, 0))
	out, err := s.SignMediaSegmentWithManifest(context.Background(), bytes.NewReader(rotationSource(0)), createdManifest("expanded history"))
	if err != nil {
		t.Fatal(err)
	}
	v := NewLiveMediaValidator(WithSigningTrust(sc.roots), WithLiveSessionPolicy(LiveSessionPolicy{MaxManifests: 128}))
	if r := v.ValidateInitSegment(context.Background(), bytes.NewReader(init)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	v.SetMediaTimeOrigin(time.Unix(0, 0))
	for i := len(v.init.manifests); i < maxLiveManifests; i++ {
		v.init.manifests[fmt.Sprint(i)] = liveKeyManifest{}
	}
	if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(out)); !r.Valid {
		t.Fatal(r.Statuses)
	}
	if len(v.init.manifests) != maxLiveManifests+1 {
		t.Fatal("expanded history policy ignored")
	}
	for _, p := range []LiveSessionPolicy{{MaxManifests: -1}, {MaxManifests: 1025}, {RevocationRecheckInterval: -time.Second}, {RevocationRecheckInterval: 2 * time.Hour}} {
		v := NewLiveMediaValidator(WithLiveSessionPolicy(p))
		if _, err := v.sessionPolicy(); err == nil {
			t.Fatalf("invalid policy accepted: %+v", p)
		}
	}
}

func FuzzLiveManifestReference(f *testing.F) {
	f.Add([]byte{0xf6})
	f.Add([]byte(liveCBOR(f, map[string]any{"url": "https://example.org/store", "alg": "sha256", "hash": make([]byte, 32)})))
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, err := decodeLiveManifestReference(raw)
		if err == nil && r != nil {
			h, ok := hashByName(r.alg)
			if !ok || len(r.hash) != h.Size() {
				t.Fatal("accepted invalid reference")
			}
		}
	})
}
