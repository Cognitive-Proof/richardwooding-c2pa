package c2pa

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// LiveRemoteManifestPolicy enables manifestUri retrieval only from explicitly
// listed HTTP(S) origins (scheme://host[:port]). Redirects are never followed.
// Defaults: 4 MiB per store and 10 seconds per request. Hard maxima are 16 MiB
// and one minute. The caller remains responsible for allowed origins and its
// HTTP transport's DNS/proxy policy. No cookies or caller headers are forwarded.
type LiveRemoteManifestPolicy struct {
	AllowedOrigins []string
	MaxBytes       int
	Timeout        time.Duration
}

func WithLiveRemoteManifests(p LiveRemoteManifestPolicy) ValidateOption {
	p.AllowedOrigins = append([]string(nil), p.AllowedOrigins...)
	return func(c *validateConfig) {
		q := p
		q.AllowedOrigins = append([]string(nil), p.AllowedOrigins...)
		c.liveRemote = &q
	}
}

// LiveSessionPolicy bounds retained manifests and selects event-ID history.
// MonotonicEventIDs requires strictly increasing IDs, retaining only a high-water
// mark instead of the default 65,536-entry exact history. MaxManifests defaults
// to 64 (maximum 1024); no manifest is evicted. RevocationRecheckInterval defaults
// to five minutes (maximum one hour). Certificate path/expiry is checked for every
// segment against WithClock, independently of any manifest timestamp. Revocation
// uses WithOnlineRevocation and its existing soft-fail policy.
type LiveSessionPolicy struct {
	MonotonicEventIDs         bool
	MaxManifests              int
	RevocationRecheckInterval time.Duration
}

func WithLiveSessionPolicy(p LiveSessionPolicy) ValidateOption {
	return func(c *validateConfig) { c.liveSession = p }
}

func (l *LiveMediaValidator) sessionPolicy() (LiveSessionPolicy, error) {
	var p LiveSessionPolicy
	if l.cfg != nil {
		p = l.cfg.liveSession
	}
	if p.MaxManifests == 0 {
		p.MaxManifests = maxLiveManifests
	}
	if p.RevocationRecheckInterval == 0 {
		p.RevocationRecheckInterval = 5 * time.Minute
	}
	if p.MaxManifests < 1 || p.MaxManifests > 1024 || p.RevocationRecheckInterval < time.Second || p.RevocationRecheckInterval > time.Hour {
		return p, errors.New("invalid live session policy")
	}
	return p, nil
}

type liveManifestReference struct {
	url, alg string
	hash     []byte
	size     *uint64
}

func decodeLiveManifestReference(raw []byte) (*liveManifestReference, error) {
	if raw == nil {
		return nil, nil
	}
	if len(raw) > maxLiveSessionAssertion {
		return nil, errors.New("manifestUri exceeds metadata limit")
	}
	f, err := liveMap(raw, "url", "alg", "hash")
	if err != nil {
		return nil, err
	}
	r := &liveManifestReference{}
	if liveDecMode.Unmarshal(f["url"], &r.url) != nil || liveDecMode.Unmarshal(f["alg"], &r.alg) != nil || !isCBORByteString(f["hash"]) || liveDecMode.Unmarshal(f["hash"], &r.hash) != nil {
		return nil, errors.New("invalid manifestUri fields")
	}
	u, err := url.Parse(r.url)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || len(r.url) > 4096 {
		return nil, errors.New("manifestUri requires absolute HTTP(S) URL without credentials or fragment")
	}
	h, ok := hashByName(r.alg)
	if !ok || len(r.hash) != h.Size() {
		return nil, errors.New("manifestUri requires explicit supported algorithm and matching digest")
	}
	if raw, present := f["size"]; present {
		var n uint64
		if len(raw) == 0 || raw[0]>>5 != 0 || liveDecMode.Unmarshal(raw, &n) != nil {
			return nil, errors.New("invalid manifestUri size")
		}
		r.size = &n
	}
	return r, nil
}

func (r *liveManifestReference) matches(m liveKeyManifest) bool {
	return subtle.ConstantTimeCompare(r.hash, m.hashes[strings.ToLower(r.alg)]) == 1 && (r.size == nil || *r.size == uint64(m.size))
}

func (l *LiveMediaValidator) fetchLiveManifest(ctx context.Context, r *liveManifestReference) ([]byte, error) {
	if l.cfg == nil || l.cfg.liveRemote == nil {
		return nil, errors.New("remote live manifests are disabled")
	}
	p := *l.cfg.liveRemote
	if p.MaxBytes == 0 {
		p.MaxBytes = 4 << 20
	}
	if p.Timeout == 0 {
		p.Timeout = 10 * time.Second
	}
	if p.MaxBytes < 1 || p.MaxBytes > 16<<20 || p.Timeout < time.Millisecond || p.Timeout > time.Minute {
		return nil, errors.New("invalid remote manifest policy")
	}
	u, _ := url.Parse(r.url)
	allowed := false
	for _, origin := range p.AllowedOrigins {
		a, err := url.Parse(origin)
		if err != nil || a.User != nil || a.RawQuery != "" || a.Fragment != "" || (a.Path != "" && a.Path != "/") || a.Host == "" || (a.Scheme != "http" && a.Scheme != "https") {
			return nil, errors.New("invalid allowed manifest origin")
		}
		if a.Scheme == u.Scheme && strings.EqualFold(a.Host, u.Host) {
			allowed = true
		}
	}
	if !allowed {
		return nil, errors.New("manifestUri origin is not allowed")
	}
	if r.size != nil && *r.size > uint64(p.MaxBytes) {
		return nil, errors.New("remote store exceeds size policy")
	}
	requestCtx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/c2pa")
	baseClient := l.cfg.httpClient
	if baseClient == nil {
		baseClient = defaultConfig().httpClient
	}
	client := *baseClient
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest response status %d", response.StatusCode)
	}
	if response.ContentLength > int64(p.MaxBytes) {
		return nil, errors.New("remote store Content-Length exceeds policy")
	}
	data, err := readAllCtx(requestCtx, response.Body, p.MaxBytes+1)
	if err != nil {
		return nil, err
	}
	if err := requestCtx.Err(); err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > p.MaxBytes || (r.size != nil && uint64(len(data)) != *r.size) {
		return nil, errors.New("remote store size mismatch or limit exceeded")
	}
	h, _ := hashByName(r.alg)
	h.Write(data)
	if subtle.ConstantTimeCompare(h.Sum(nil), r.hash) != 1 {
		return nil, errors.New("downloaded manifest digest mismatch")
	}
	return data, nil
}

// Validate a detached store against the exact original asset coordinates. Do
// not insert a new uuid box: that would move the bytes the binding authenticates.
func (l *LiveMediaValidator) validateLiveDetached(ctx context.Context, store, asset []byte) ValidationResult {
	v := newValidator(ctx, BMFF, nil)
	if l.cfg != nil {
		v.cfg = *l.cfg
	}
	v.data = asset
	parsed := parseStore(ctx, store)
	m := parsed.active()
	if m == nil {
		v.add(StatusClaimMissing, "", "remote store has no active manifest", nil)
		return v.finish()
	}
	v.res.Info = parseManifest(ctx, store)
	v.res.ActiveManifestLabel = m.label
	v.validateManifest(m, parsed, 0)
	return v.finish()
}

func (l *LiveMediaValidator) resolveLiveManifest(ctx context.Context, prior *liveMediaInit, data []byte, id string, sequence uint64, r *liveManifestReference, limit int) (*liveMediaInit, error) {
	if known, ok := prior.manifests[id]; ok {
		if !r.matches(known) {
			return nil, errors.New("manifestUri does not match cached authorizing store")
		}
		return prior, nil
	}
	if len(prior.manifests) >= limit {
		return nil, errors.New("manifest history limit reached")
	}
	store, err := l.fetchLiveManifest(ctx, r)
	if err != nil {
		return nil, err
	}
	m := parseStore(ctx, store).active()
	if m == nil || m.label != id || m.update {
		return nil, errors.New("remote store identifier or manifest type mismatch")
	}
	var result ValidationResult
	announcement := false
	if err := liveAnnouncementBinding(m); err == nil {
		result = l.validateLiveDetached(ctx, store, data)
		announcement = result.Valid && result.Binding == BindingVerified
	}
	if !announcement {
		top := parseBMFFBoxes(ctx, prior.initData)
		moov, err := liveInitStructure(ctx, prior.initData, top)
		if err != nil {
			return nil, err
		}
		if err := liveInitBinding(ctx, prior.initData, top, moov, m); err != nil {
			return nil, err
		}
		result = l.validateLiveDetached(ctx, store, prior.initData)
	}
	next, _, err := stageLiveStoreResult(ctx, store, prior, id, sequence, result, announcement, limit)
	return next, err
}

func (l *LiveMediaValidator) recheckLiveCredential(ctx context.Context, s *liveMediaInit, id string, p LiveSessionPolicy) (*liveMediaInit, []StatusEntry, error) {
	m, ok := s.manifests[id]
	if !ok || len(m.chainDER) == 0 {
		return nil, nil, errors.New("authorizing credential is unavailable")
	}
	v := newValidator(ctx, BMFF, nil)
	if l.cfg != nil {
		v.cfg = *l.cfg
	}
	chain := make([]*x509.Certificate, len(m.chainDER))
	for i, der := range m.chainDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, err
		}
		chain[i] = cert
	}
	now := v.cfg.clock()
	valid := v.verifyChain(chain, v.signingTrustPool(), now, signingEKUOK, id)
	due := m.checkedAt.IsZero() || now.Before(m.checkedAt) || now.Sub(m.checkedAt) >= p.RevocationRecheckInterval
	if valid && due {
		checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		v.ctx = checkCtx
		v.cfg.liveRevocationFresh = true
		v.checkRevocation(chain, id, StatusSigningCredentialRevoked)
		v.ctx = ctx
		cancel()
	}
	report := v.finish()
	if !valid || !report.Valid {
		return nil, report.Statuses, errors.New("authorizing credential is no longer valid")
	}
	if due {
		s = cloneLiveState(s)
		m.checkedAt = now
		s.manifests[id] = m
	}
	return s, report.Statuses, nil
}

// SetManifestURI attaches a digest-pinned reference to this signer's current
// store. Serve the exact bytes returned by ManifestStore for the stream lifetime.
// Passing an empty URL clears it. It does not publish or fetch any data.
func (s *LiveMediaSigner) SetManifestURI(rawURL string) error {
	if !s.Initialized() {
		return errors.New("live signer is not initialized")
	}
	if rawURL == "" {
		s.manifestRef = nil
		return nil
	}
	store := s.manifestStore
	if len(store) == 0 {
		return errors.New("no current manifest store")
	}
	h, _ := hashByName("sha256")
	h.Write(store)
	raw, _ := encMode.Marshal(map[string]any{"url": rawURL, "alg": "sha256", "hash": h.Sum(nil), "size": uint64(len(store))})
	ref, err := decodeLiveManifestReference(raw)
	if err != nil {
		return err
	}
	s.manifestRef = ref
	return nil
}

// ManifestStore returns a copied raw store for the latest signed init or
// announcement, or nil before initialization. The caller hosts these exact bytes
// when using SetManifestURI; this method performs no publication.
func (s *LiveMediaSigner) ManifestStore() []byte {
	if s == nil {
		return nil
	}
	return bytes.Clone(s.manifestStore)
}
