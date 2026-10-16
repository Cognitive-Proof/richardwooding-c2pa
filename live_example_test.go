package c2pa_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/richardwooding/c2pa"
)

func liveExampleFile(dir, name string) []byte {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		panic(err)
	}
	return b
}

// ExampleLiveMediaValidator_ValidateMediaSegment independently validates the
// retained Rust-authored stream with its explicit test CA. The recorded clock
// keeps this archived example independent of certificate expiration in CI.
// Applications use their own trust anchors and normally use the current clock.
func ExampleLiveMediaValidator_ValidateMediaSegment() {
	const dir = "testdata/live_video/interop/rust"
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(liveExampleFile(dir, "root.pem")) {
		panic("invalid example root")
	}
	at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(liveExampleFile(dir, "validation-time.txt"))))
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	live := c2pa.NewLiveMediaValidator(c2pa.WithSigningTrust(pool), c2pa.WithClock(func() time.Time { return at }))
	init := live.ValidateInitSegment(ctx, bytes.NewReader(liveExampleFile(dir, "init.mp4")))
	if !init.Valid {
		panic(fmt.Sprint(init.Statuses))
	}
	if err := live.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
		panic(err)
	}
	for _, name := range []string{"880000021.m4s", "880000022.m4s", "880000023.m4s"} {
		segment := live.ValidateMediaSegment(ctx, bytes.NewReader(liveExampleFile(dir, name)))
		fmt.Printf("sequence %d: valid=%t bound=%t\n", segment.SequenceNumber, segment.Valid, segment.Binding == c2pa.BindingVerified)
	}
	// Output:
	// sequence 880000021: valid=true bound=true
	// sequence 880000022: valid=true bound=true
	// sequence 880000023: valid=true bound=true
}

// ExampleLiveMediaSigner_rotation signs archived livesim2 media and announces a
// new session key in segment two. The example certificate is generated locally;
// deployments load a CA-issued credential as shown in the README. No data is
// published here. Retain successful output bytes when retrying publication.
func ExampleLiveMediaSigner_rotation() {
	const dir = "testdata/live_video/livesim2"
	ctx := context.Background()
	manifestSigner, pool := exampleSigner()
	policy := c2pa.LiveSessionPolicy{MonotonicEventIDs: true}
	signer, err := c2pa.NewLiveMediaSigner(manifestSigner, c2pa.LiveMediaSignerConfig{
		CreatedAt: time.Unix(1760000042, 0), ValidityPeriod: 60, MinSequenceNumber: 880000021, SessionPolicy: policy,
	})
	if err != nil {
		panic(err)
	}
	manifest := func(title string) c2pa.Manifest {
		return c2pa.Manifest{Title: title, Actions: []c2pa.Action{{Action: c2pa.ActionCreated, DigitalSourceType: c2pa.DigitalSourceTypeDigitalCapture}}}
	}
	init, err := signer.SignInitSegment(ctx, bytes.NewReader(liveExampleFile(dir, "init.mp4")), manifest("Live stream"))
	if err != nil {
		panic(err)
	}
	receiver := c2pa.NewLiveMediaValidator(c2pa.WithSigningTrust(pool), c2pa.WithLiveSessionPolicy(policy))
	if r := receiver.ValidateInitSegment(ctx, bytes.NewReader(init)); !r.Valid {
		panic(fmt.Sprint(r.Statuses))
	}
	for _, endpoint := range []interface{ SetMediaTimeOrigin(time.Time) error }{signer, receiver} {
		if err := endpoint.SetMediaTimeOrigin(time.Unix(0, 0)); err != nil {
			panic(err)
		}
	}
	for i, name := range []string{"880000021.m4s", "880000022.m4s", "880000023.m4s"} {
		source := bytes.NewReader(liveExampleFile(dir, name))
		var signed []byte
		if i == 1 {
			if err := signer.AddSessionKey(c2pa.LiveMediaSignerConfig{CreatedAt: time.Unix(1760000044, 0), ValidityPeriod: 60, MinSequenceNumber: 880000022}); err != nil {
				panic(err)
			}
			signed, err = signer.SignMediaSegmentWithManifest(ctx, source, manifest("Key rotation"))
		} else {
			signed, err = signer.SignMediaSegment(ctx, source)
		}
		if err != nil {
			panic(err)
		}
		r := receiver.ValidateMediaSegment(ctx, bytes.NewReader(signed))
		fmt.Printf("sequence %d: valid=%t\n", r.SequenceNumber, r.Valid)
	}
	// Output:
	// sequence 880000021: valid=true
	// sequence 880000022: valid=true
	// sequence 880000023: valid=true
}
