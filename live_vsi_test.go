package c2pa

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

const testLiveManifestID = "urn:uuid:10000000-0000-4000-8000-000000000001"

func liveTestSegment(t testing.TB, source []byte, sequence uint64) ([]byte, liveSessionKey) {
	t.Helper()
	k, private, _ := liveKeyFixture(t)
	out, err := buildLiveVSISegment(context.Background(), source, private, k.kid, testLiveManifestID, sequence, liveEvent{timescale: 1000, duration: 2000, id: 123})
	if err != nil {
		t.Fatal(err)
	}
	return out, k
}

func liveTestEvent(t testing.TB, data []byte) (liveEvent, *bmffBox) {
	t.Helper()
	top, err := liveSegmentBoxes(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range top {
		event, yes, err := parseLiveEMSG(data, b)
		if err != nil {
			t.Fatal(err)
		}
		if yes {
			return event, b
		}
	}
	t.Fatal("no VSI event")
	return liveEvent{}, nil
}

func TestLiveVSIAttachedSignature(t *testing.T) {
	_, fragments := unsignedFragmentedSet(1, fragOpts{sidxVersion: -1})
	data, key := liveTestSegment(t, fragments[0], math.MaxUint64)
	event, _ := liveTestEvent(t, data)
	info, err := verifyLiveVSI(event.payload, key, testLiveManifestID)
	if err != nil || info.sequence != math.MaxUint64 {
		t.Fatalf("VSI: %+v, %v", info, err)
	}
	if err := verifyLiveVSIHash(context.Background(), data, info); err != nil {
		t.Fatal(err)
	}
	// Independently hash delivered top-level offsets and bytes, omitting only
	// the VSI box. This catches a shared signer/verifier layout mistake.
	h := sha256.New()
	for _, b := range parseBMFFBoxes(context.Background(), data) {
		if b.typ == "emsg" {
			continue
		}
		_, _ = h.Write(binary.BigEndian.AppendUint64(nil, uint64(b.start)))
		_, _ = h.Write(data[b.start:b.end])
	}
	_, digest, _, err := decodeLiveVSIHash(info.bmffHash)
	if err != nil || !bytes.Equal(h.Sum(nil), digest) {
		t.Fatal("VSI digest does not cover delivered box offsets and bytes")
	}
	var tag cbor.RawTag
	if err := liveDecMode.Unmarshal(event.payload, &tag); err != nil {
		t.Fatal(err)
	}
	var parts []cbor.RawMessage
	if err := liveDecMode.Unmarshal(tag.Content, &parts); err != nil {
		t.Fatal(err)
	}
	var protected, payload, signature []byte
	for i, dst := range map[int]*[]byte{0: &protected, 2: &payload, 3: &signature} {
		if err := liveDecMode.Unmarshal(parts[i], dst); err != nil {
			t.Fatal(err)
		}
	}
	if tag.Number != 18 || len(payload) == 0 || !ed25519.Verify(key.public, liveCBOR(t, []any{"Signature1", protected, []byte{}, payload}), signature) {
		t.Fatal("independent attached COSE verification failed")
	}
	if _, err := verifyLiveVSI(event.payload, key, "another-manifest"); err == nil {
		t.Fatal("wrong manifest accepted")
	}
	wrong := key
	wrong.kid = []byte("another-key")
	if _, err := verifyLiveVSI(event.payload, wrong, testLiveManifestID); err == nil {
		t.Fatal("wrong kid accepted")
	}
	bad := bytes.Clone(event.payload)
	bad[len(bad)-1] ^= 1
	if _, err := verifyLiveVSI(bad, key, testLiveManifestID); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

func TestLiveVSIRejectsSignedMalformedPayload(t *testing.T) {
	_, fragments := unsignedFragmentedSet(1, fragOpts{sidxVersion: -1})
	data, key := liveTestSegment(t, fragments[0], 1)
	event, _ := liveTestEvent(t, data)
	_, private, _ := liveKeyFixture(t)
	for _, kind := range []string{"detached", "protected kid", "missing kid", "negative sequence", "missing manifest", "manifestUri", "merkle null", "unknown critical"} {
		t.Run(kind, func(t *testing.T) {
			var original cose.Sign1Message
			if err := original.UnmarshalCBOR(event.payload); err != nil {
				t.Fatal(err)
			}
			fields, err := liveMap(original.Payload, "bmffHash")
			if err != nil {
				t.Fatal(err)
			}
			msg := cose.NewSign1Message()
			msg.Headers.Protected[cose.HeaderLabelAlgorithm] = cose.AlgorithmEdDSA
			msg.Headers.Unprotected[cose.HeaderLabelKeyID] = key.kid
			switch kind {
			case "protected kid":
				delete(msg.Headers.Unprotected, cose.HeaderLabelKeyID)
				msg.Headers.Protected[cose.HeaderLabelKeyID] = key.kid
			case "missing kid":
				delete(msg.Headers.Unprotected, cose.HeaderLabelKeyID)
			case "negative sequence":
				fields["sequenceNumber"] = liveCBOR(t, -1)
			case "missing manifest":
				delete(fields, "manifestId")
			case "manifestUri":
				fields["manifestUri"] = liveCBOR(t, map[string]any{"url": "https://example.invalid/manifest"})
			case "merkle null":
				hash, err := liveMap(fields["bmffHash"])
				if err != nil {
					t.Fatal(err)
				}
				hash["merkle"] = liveCBOR(t, nil)
				fields["bmffHash"] = liveCBOR(t, hash)
			case "unknown critical":
				msg.Headers.Protected[int64(99)] = true
				msg.Headers.Protected[cose.HeaderLabelCritical] = []any{int64(99)}
			}
			msg.Payload = liveCBOR(t, fields)
			signer, err := cose.NewSigner(cose.AlgorithmEdDSA, private)
			if err != nil {
				t.Fatal(err)
			}
			if err := msg.Sign(rand.Reader, nil, signer); err != nil {
				t.Fatal(err)
			}
			if kind == "detached" {
				msg.Payload = nil
			}
			encoded, err := msg.MarshalCBOR()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifyLiveVSI(encoded, key, testLiveManifestID); err == nil {
				t.Fatal("invalid but correctly signed VSI accepted")
			}
		})
	}
}

func TestLiveVSIHashProtectsOtherEvents(t *testing.T) {
	_, fragments := unsignedFragmentedSet(1, fragOpts{sidxVersion: -1})
	source := fragments[0]
	// A genuine v1 SCTE-35-shaped event: timing precedes scheme/value.
	scte := synthBox("emsg", []byte{1, 0, 0, 0}, make([]byte, 20), []byte("urn:scte:scte35:2013:bin\x00\x00cue-payload"))
	moof := topBox(source, "moof")
	source = bytes.Join([][]byte{source[:moof.start], scte, source[moof.start:]}, nil)
	data, key := liveTestSegment(t, source, 1)
	event, vsi := liveTestEvent(t, data)
	info, err := verifyLiveVSI(event.payload, key, testLiveManifestID)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyLiveVSIHash(context.Background(), data, info); err != nil {
		t.Fatal(err)
	}
	retained := append(bytes.Clone(data[:vsi.start]), data[vsi.end:]...)
	if !bytes.Equal(retained, source) {
		t.Fatal("source boxes changed")
	}
	var cue *bmffBox
	for _, b := range parseBMFFBoxes(context.Background(), data) {
		if b.typ == "emsg" && b.start != vsi.start {
			cue = b
		}
	}
	if cue == nil {
		t.Fatal("SCTE-35 event lost")
	}
	for _, kind := range []string{"cue tamper", "cue removal", "media tamper", "URI lookalike", "VSI value lookalike"} {
		t.Run(kind, func(t *testing.T) {
			bad := bytes.Clone(data)
			switch kind {
			case "cue tamper":
				bad[cue.end-1] ^= 1
			case "cue removal":
				bad = append(bad[:cue.start], bad[cue.end:]...)
			case "media tamper":
				bad[len(bad)-1] ^= 1
			case "URI lookalike":
				bad = append(bad, synthBox("emsg", []byte{0, 0, 0, 0}, []byte(liveVSIScheme+"-extra\x00fseg\x00"), make([]byte, 16), []byte{1})...)
			case "VSI value lookalike":
				bad = append(bad, synthBox("emsg", []byte{0, 0, 0, 0}, []byte(liveVSIScheme+"\x00other\x00"), make([]byte, 16), []byte{1})...)
			}
			if err := verifyLiveVSIHash(context.Background(), bad, info); err == nil {
				t.Fatal("unverified event or altered media accepted")
			}
		})
	}
	// A raw v1 event can also imitate the prescribed URI prefix at offset 12
	// using timing bytes; it must never get an unverified hash exclusion.
	lookalike := synthBox("emsg", []byte{1, 0, 0, 0}, []byte(liveVSIScheme), []byte{0}, []byte("unverified"))
	badLookalike := append(bytes.Clone(data), lookalike...)
	if err := verifyLiveVSIHash(context.Background(), badLookalike, info); err == nil {
		t.Fatal("v1 prefix lookalike accepted")
	}
	// VSI is excluded from the media hash, but its payload has a separate signature.
	bad := bytes.Clone(data)
	bad[vsi.end-1] ^= 1
	if err := verifyLiveVSIHash(context.Background(), bad, info); err != nil {
		t.Fatalf("VSI unexpectedly hashed: %v", err)
	}
	changed, _ := liveTestEvent(t, bad)
	if _, err := verifyLiveVSI(changed.payload, key, testLiveManifestID); err == nil {
		t.Fatal("altered VSI signature accepted")
	}
}

func TestLiveEMSGRejectsInvalidTiming(t *testing.T) {
	_, fragments := unsignedFragmentedSet(1, fragOpts{sidxVersion: -1})
	data, _ := liveTestSegment(t, fragments[0], 1)
	_, box := liveTestEvent(t, data)
	timing := box.start + 12 + len(liveVSIScheme) + 1 + len("fseg") + 1
	for _, at := range []int{box.start + 9, timing, timing + 4, timing + 8} {
		bad := bytes.Clone(data)
		if at == box.start+9 {
			bad[at] = 1
		} else {
			binary.BigEndian.PutUint32(bad[at:], 0)
			if at == timing+4 {
				binary.BigEndian.PutUint32(bad[at:], 1)
			}
		}
		b := topBox(bad, "emsg")
		if _, _, err := parseLiveEMSG(bad, b); err == nil {
			t.Fatalf("accepted invalid metadata at %d", at)
		}
	}
	v1 := synthBox("emsg", []byte{1, 0, 0, 0}, make([]byte, 20), []byte(liveVSIScheme+"\x00fseg\x00payload"))
	if _, yes, err := parseLiveEMSG(v1, topBox(v1, "emsg")); !yes || err == nil {
		t.Fatal("VSI version 1 accepted")
	}
}

func TestLiveVSIPlacementAfterProducerTime(t *testing.T) {
	_, fragments := unsignedFragmentedSet(1, fragOpts{sidxVersion: 0})
	source := fragments[0]
	index := topBox(source, "sidx")
	prft := synthBox("prft", []byte{0, 0, 0, 0}, make([]byte, 16))
	source = bytes.Join([][]byte{source[:index.end], prft, source[index.end:]}, nil)
	// The index still names the moof as the first old subsegment.
	binary.BigEndian.PutUint32(source[index.start+index.headerLen+16:], uint32(len(prft)))
	data, _ := liveTestSegment(t, source, 1)
	top := parseBMFFBoxes(context.Background(), data)
	for i, typ := range []string{"styp", "sidx", "prft", "emsg", "moof", "mdat"} {
		if top[i].typ != typ {
			t.Fatalf("box %d = %s", i, top[i].typ)
		}
	}
	if !bytes.Equal(data[top[2].start:top[2].end], prft) {
		t.Fatal("producer time changed")
	}
	first := binary.BigEndian.Uint32(data[index.start+index.headerLen+16:])
	if index.end+int(first) != top[3].start {
		t.Fatal("sidx no longer begins at inserted VSI")
	}
}

func TestLiveVSIHashExclusionPolicy(t *testing.T) {
	for _, kind := range []string{"offset zero", "all emsg", "media exclusion", "merkle", "short digest"} {
		t.Run(kind, func(t *testing.T) {
			fields := map[string]any{"alg": "sha256", "hash": make([]byte, 32), "exclusions": liveVSIExclusions()}
			switch kind {
			case "offset zero":
				fields["exclusions"] = []any{map[string]any{"xpath": "/emsg", "data": []any{map[string]any{"offset": 0, "value": []byte(liveVSIScheme)}}}}
			case "all emsg":
				fields["exclusions"] = []any{map[string]any{"xpath": "/emsg"}}
			case "media exclusion":
				fields["exclusions"] = append(liveVSIExclusions(), map[string]any{"xpath": "/mdat"})
			case "merkle":
				fields["merkle"] = []any{}
			case "short digest":
				fields["hash"] = []byte{1}
			}
			if _, _, _, err := decodeLiveVSIHash(liveCBOR(t, fields)); err == nil {
				t.Fatal("unsafe hash binding accepted")
			}
		})
	}
}

func TestLiveVSIInsertionAndIndexes(t *testing.T) {
	for _, opt := range []fragOpts{{sidxVersion: -1}, {sidxVersion: 0}, {sidxVersion: 1}, {sidxVersion: 0, emsg: true}, {sidxVersion: 1, emsg: true, tfhdBase: true}, {sidxVersion: -1, noStyp: true, tfhdBase: true}} {
		_, fragments := unsignedFragmentedSet(1, opt)
		source := fragments[0]
		data, key := liveTestSegment(t, source, 1)
		event, vsi := liveTestEvent(t, data)
		info, err := verifyLiveVSI(event.payload, key, testLiveManifestID)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyLiveVSIHash(context.Background(), data, info); err != nil {
			t.Fatal(err)
		}
		if !opt.noStyp && string(data[4:8]) != "styp" {
			t.Fatal("styp no longer first")
		}
		if vsi.start >= topBox(data, "moof").start {
			t.Fatal("VSI must precede moof")
		}
		if opt.sidxVersion >= 0 {
			oldIndex, newIndex := topBox(source, "sidx"), topBox(data, "sidx")
			p := oldIndex.start + oldIndex.headerLen
			offset, width := p+16, 4
			if opt.sidxVersion == 1 {
				offset, width = p+20, 8
			}
			first := uint64(binary.BigEndian.Uint32(data[offset:]))
			if width == 8 {
				first = binary.BigEndian.Uint64(data[offset:])
			}
			target := newIndex.end + int(first)
			refSize := int(binary.BigEndian.Uint32(data[offset+width+4:]) & 0x7fffffff)
			if opt.emsg {
				if target != topBox(data, "moof").start || refSize != len(source)-topBox(source, "moof").start {
					t.Fatal("sidx target/range not preserved")
				}
			} else if target != vsi.start || refSize != len(data)-vsi.start {
				t.Fatal("VSI not included in indexed subsegment")
			}
		}
		if opt.tfhdBase {
			tfhd := matchBMFFXPath(context.Background(), parseBMFFBoxes(context.Background(), data), "/moof/traf/tfhd")[0]
			base := binary.BigEndian.Uint64(data[tfhd.start+tfhd.headerLen+8:])
			if base != uint64(topBox(data, "moof").start) {
				t.Fatal("absolute tfhd base was not repaired")
			}
		}
	}
}

func TestLiveVSIRejectsUnsupportedSource(t *testing.T) {
	_, fragments := unsignedFragmentedSet(1, fragOpts{sidxVersion: 0})
	source := fragments[0]
	hierarchical := bytes.Clone(source)
	index := topBox(hierarchical, "sidx")
	hierarchical[index.end-12] |= 0x80
	already, _ := liveTestSegment(t, source, 1)
	for _, bad := range [][]byte{nil, append(bytes.Clone(source), 1), append(synthBox("ssix"), source...), hierarchical, already, append(bytes.Clone(source), synthBox("moof")...)} {
		_, private, _ := liveKeyFixture(t)
		before := bytes.Clone(bad)
		if _, err := buildLiveVSISegment(context.Background(), bad, private, []byte("kid"), testLiveManifestID, 1, liveEvent{timescale: 1000, duration: 2000}); err == nil {
			t.Fatal("unsupported source accepted")
		}
		if !bytes.Equal(before, bad) {
			t.Fatal("failed signing changed input")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, private, _ := liveKeyFixture(t)
	if _, err := buildLiveVSISegment(ctx, source, private, []byte("kid"), testLiveManifestID, 1, liveEvent{timescale: 1000, duration: 2000}); err != context.Canceled {
		t.Fatalf("cancellation: %v", err)
	}
}

func FuzzLiveVSICarriage(f *testing.F) {
	_, fragments := unsignedFragmentedSet(1, fragOpts{sidxVersion: -1})
	data, key := liveTestSegment(f, fragments[0], 1)
	f.Add(data)
	f.Add(fragments[0])
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, segment []byte) {
		if len(segment) > maxLiveSessionAssertion {
			return
		}
		top, err := liveSegmentBoxes(context.Background(), segment)
		if err != nil {
			return
		}
		for _, b := range top {
			event, yes, err := parseLiveEMSG(segment, b)
			if err != nil || !yes {
				continue
			}
			info, err := verifyLiveVSI(event.payload, key, testLiveManifestID)
			if err == nil {
				_ = verifyLiveVSIHash(context.Background(), segment, info)
			}
		}
	})
}

func FuzzLiveVSIEnvelope(f *testing.F) {
	_, fragments := unsignedFragmentedSet(1, fragOpts{sidxVersion: -1})
	data, key := liveTestSegment(f, fragments[0], 1)
	event, _ := liveTestEvent(f, data)
	f.Add(event.payload)
	f.Add([]byte{0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x40})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		_, _ = verifyLiveVSI(encoded, key, testLiveManifestID)
	})
}
