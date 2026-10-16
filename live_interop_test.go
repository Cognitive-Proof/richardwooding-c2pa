package c2pa

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const rustInteropDir = "testdata/live_video/interop/rust"

func TestLiveInteropFixtureChecksums(t *testing.T) {
	const dir = "testdata/live_video/interop"
	lines := strings.Split(strings.TrimSpace(string(interopRead(t, dir, "SHA256SUMS"))), "\n")
	if len(lines) != 12 {
		t.Fatal("expected two sets of six signed fixture files")
	}
	seen := make(map[string]bool)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 || seen[fields[1]] {
			t.Fatal("invalid checksum entry")
		}
		name := fields[1]
		parts := strings.Split(name, "/")
		if len(parts) != 2 || (parts[0] != "go" && parts[0] != "rust") {
			t.Fatal("invalid fixture path")
		}
		switch parts[1] {
		case "init.mp4", "880000021.m4s", "880000022.m4s", "880000023.m4s", "root.pem", "validation-time.txt":
		default:
			t.Fatal("unexpected fixture name")
		}
		digest := sha256.Sum256(interopRead(t, dir, filepath.FromSlash(name)))
		if hex.EncodeToString(digest[:]) != fields[0] {
			t.Fatalf("%s differs from the verified fixture", name)
		}
		seen[name] = true
	}
}

func interopRead(t testing.TB, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLiveInteropRustToGo(t *testing.T) {
	dir := rustInteropDir
	if generated := os.Getenv("C2PA_INTEROP_RUST"); generated != "" {
		dir = generated
	}
	root := x509.NewCertPool()
	if !root.AppendCertsFromPEM(interopRead(t, dir, "root.pem")) {
		block, _ := pem.Decode(interopRead(t, dir, "root.pem"))
		if block == nil {
			t.Fatal("invalid PEM")
		}
		_, err := x509.ParseCertificate(block.Bytes)
		t.Fatalf("invalid fixture root: %v", err)
	}
	at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(interopRead(t, dir, "validation-time.txt"))))
	if err != nil {
		t.Fatal(err)
	}
	newReceiver := func() *LiveMediaValidator {
		v := NewLiveMediaValidator(WithSigningTrust(root), WithClock(func() time.Time { return at }))
		r := v.ValidateInitSegment(context.Background(), bytes.NewReader(interopRead(t, dir, "init.mp4")))
		if !r.Valid {
			t.Fatalf("Rust init: %+v", r)
		}
		if err := v.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
			t.Fatal(err)
		}
		return v
	}
	v := newReceiver()
	for n := 880000021; n <= 880000023; n++ {
		media := interopRead(t, dir, fmt.Sprintf("%d.m4s", n))
		r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(media))
		if !r.Valid || r.Binding != BindingVerified || r.SequenceNumber != uint64(n) {
			t.Fatalf("Rust media: %+v", r)
		}
		media[len(media)-1] ^= 1
		if r := newReceiver().ValidateMediaSegment(context.Background(), bytes.NewReader(media)); r.Valid {
			t.Fatal("tampered Rust media accepted")
		}
	}
	// Explicit roots are mandatory; the fixture CA is not system trusted.
	if r := NewLiveMediaValidator(WithSigningTrust(x509.NewCertPool()), WithClock(func() time.Time { return at })).ValidateInitSegment(context.Background(), bytes.NewReader(interopRead(t, dir, "init.mp4"))); r.Valid {
		t.Fatal("untrusted Rust init accepted")
	}
}

// Generation is opt-in and does not run in ordinary offline CI. The Rust
// harness independently validates the resulting files with their explicit CA.
func TestLiveInteropGenerateGo(t *testing.T) {
	dir := os.Getenv("C2PA_INTEROP_GO")
	if dir == "" {
		t.Skip("set C2PA_INTEROP_GO to generate cross-language fixtures")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), b, 0644); err != nil {
			t.Fatal(err)
		}
	}
	signer, sc := newTestSigner(t)
	// Rust's ephemeral certificates have an SKI encoding rejected by Go x509.
	// Supply ordinary test credentials; Rust performs all C2PA signing itself.
	credentials := os.Getenv("C2PA_INTEROP_CREDENTIALS")
	if credentials == "" {
		t.Fatal("set C2PA_INTEROP_CREDENTIALS to a temporary credential directory")
	}
	if err := os.MkdirAll(credentials, 0700); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := newSigningChainFor(t, key)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var certPEM []byte
	for _, cert := range chain.chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	for name, b := range map[string][]byte{"chain.pem": certPEM, "key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), "root.pem": chain.rootPEM} {
		if err := os.WriteFile(filepath.Join(credentials, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := liveSigningConfig()
	cfg.CreatedAt = time.Unix(livesim2FirstSeconds, 0)
	cfg.ValidityPeriod = 60
	cfg.MinSequenceNumber = livesim2FirstSequence
	live, err := NewLiveMediaSigner(signer, cfg)
	if err != nil {
		t.Fatal(err)
	}
	init, err := live.SignInitSegment(context.Background(), bytes.NewReader(livesim2Read(t, "init.mp4")), createdManifest("Go Rust live interoperability"))
	if err != nil {
		t.Fatal(err)
	}
	write("init.mp4", init)
	write("root.pem", sc.rootPEM)
	write("validation-time.txt", []byte(time.Now().UTC().Format(time.RFC3339Nano)))
	if err := live.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	for n := 880000021; n <= 880000023; n++ {
		name := fmt.Sprintf("%d.m4s", n)
		media, err := live.SignMediaSegment(context.Background(), bytes.NewReader(livesim2Read(t, name)))
		if err != nil {
			t.Fatal(err)
		}
		write(name, media)
	}
}

// Optional independent Rust regression for a stream rotating on segment two.
func TestLiveInteropGenerateRotation(t *testing.T) {
	dir := os.Getenv("C2PA_INTEROP_ROTATION")
	if dir == "" {
		t.Skip("set C2PA_INTEROP_ROTATION for independent Rust rotation validation")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	ms, sc := newTestSigner(t)
	cfg := rotationConfig(0x42, "initial", 0)
	s, err := NewLiveMediaSigner(ms, cfg)
	if err != nil {
		t.Fatal(err)
	}
	init, err := s.SignInitSegment(context.Background(), bytes.NewReader(livesim2Read(t, "init.mp4")), createdManifest("rotation init"))
	if err != nil {
		t.Fatal(err)
	}
	write("init.mp4", init)
	write("root.pem", sc.rootPEM)
	s.SetMediaTimeOrigin(time.Unix(0, 0))
	v := rotationReceiver(t, sc, init)
	for n := 880000021; n <= 880000023; n++ {
		name := fmt.Sprintf("%d.m4s", n)
		source := bytes.NewReader(livesim2Read(t, name))
		var signed []byte
		if n == 880000022 {
			if err := s.AddSessionKey(rotationConfig(0x43, "rotated", 1)); err != nil {
				t.Fatal(err)
			}
			signed, err = s.SignMediaSegmentWithManifest(context.Background(), source, createdManifest("rotation announcement"))
		} else {
			signed, err = s.SignMediaSegment(context.Background(), source)
		}
		if err != nil {
			t.Fatal(err)
		}
		if r := v.ValidateMediaSegment(context.Background(), bytes.NewReader(signed)); !r.Valid {
			t.Fatal(r.Statuses)
		}
		write(name, signed)
	}
}
