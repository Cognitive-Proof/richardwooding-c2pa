package c2pa

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/veraison/go-cose"
)

// Default exact event-ID history is bounded rather than evicted: forgetting
// accepted IDs would allow their reuse. The monotonic policy keeps a high-water
// mark instead.
const maxLiveEventIDs = 1 << 16

// LiveMediaSegmentResult describes one supplied media segment. Valid means all
// supported live checks passed. Binding describes the narrower signature-checked
// media hash; it may be verified even when a later timing/continuity check fails.
// PresentationTime is rounded down to nanoseconds for reporting; validity-window
// comparisons also account for any positive subnanosecond remainder.
type LiveMediaSegmentResult struct {
	Valid            bool
	Binding          BindingState
	Statuses         []StatusEntry
	ManifestID       string
	SequenceNumber   uint64
	PresentationTime time.Time
}

// Has reports whether a status code was recorded for this segment.
func (r LiveMediaSegmentResult) Has(code StatusCode) bool {
	for _, s := range r.Statuses {
		if s.Code == code {
			return true
		}
	}
	return false
}

// SetMediaTimeOrigin sets the wall-clock instant corresponding to media time 0
// for the authenticated track. Call after a successful ValidateInitSegment and
// before accepting media. For DASH, derive this from availabilityStartTime +
// Period.start - presentationTimeOffset/timescale. Epoch-based streams use
// time.Unix(0,0). Init replacement clears the origin and all continuity history.
// This mapping cannot change after a segment has been accepted.
func (l *LiveMediaValidator) SetMediaTimeOrigin(origin time.Time) error {
	if !l.Initialized() {
		return errors.New("live initialization is required before setting the media-time origin")
	}
	if l.init.seen {
		return errors.New("cannot change the media-time origin after accepting a segment")
	}
	if origin.Year() < 0 || origin.Year() > 9999 {
		return errors.New("media-time origin outside RFC3339 range")
	}
	utc := origin.UTC()
	if utc.Year() < 0 || utc.Year() > 9999 {
		return errors.New("media-time origin outside UTC RFC3339 range")
	}
	l.init.origin = &utc
	return nil
}

// ValidateMediaSegment validates one complete BMFF/CMAF VSI segment using the
// authenticated init and an explicit time origin. This profile supports one
// moof/mdat pair and one traf for the init's single track, without edit lists.
// Composition offsets determine the earliest sample PTS and full presentation
// span. VSI sequenceNumber must match mfhd.sequence_number;
// forward gaps are allowed, while repeated/decreasing values fail.
//
// The event's timescale and duration must equal the track scale and full sample
// presentation span. Key validity is checked at the earliest sample PTS, never against
// iat/current time. Event IDs must be session-unique; the default exact history
// fails closed at 65,536 events. WithLiveSessionPolicy can instead require strictly
// increasing IDs with constant memory. Authorizing credentials are checked against
// the validation clock. Remote retrieval requires WithLiveRemoteManifests.
// State changes only on
// success. Methods must not be used concurrently.
func (l *LiveMediaValidator) ValidateMediaSegment(ctx context.Context, r io.Reader) LiveMediaSegmentResult {
	return l.validateMediaSegment(ctx, r, nil)
}

// locallyVerified is used only by the author after the normal manifest signing
// pipeline has verified this exact output, with its own TSA/identity policy.
func (l *LiveMediaValidator) validateMediaSegment(ctx context.Context, r io.Reader, locallyVerified *ValidationResult) LiveMediaSegmentResult {
	result := LiveMediaSegmentResult{Binding: BindingUnevaluated}
	add := func(code StatusCode, message string, err error) {
		result.Statuses = append(result.Statuses, StatusEntry{Code: code, Severity: code.Severity(), URI: result.ManifestID, Explanation: message, Err: err})
	}
	fail := func(code StatusCode, message string, err error) LiveMediaSegmentResult {
		add(code, message, err)
		return result
	}
	if err := ctx.Err(); err != nil {
		return fail(StatusGeneralError, "live media validation canceled", err)
	}
	if !l.Initialized() {
		return fail(StatusLiveVideoInitInvalid, "no authenticated live initialization", nil)
	}
	state := l.init
	policy, err := l.sessionPolicy()
	if err != nil {
		return fail(StatusGeneralError, "invalid live session policy", err)
	}
	result.ManifestID = state.manifestID
	if r == nil {
		return fail(StatusLiveVideoSegmentInvalid, "no readable media segment", nil)
	}
	limit := ValidateMaxScan
	if l.cfg != nil {
		limit = l.cfg.maxScan
	}
	data, err := readAllCtx(ctx, r, limit)
	if err := ctx.Err(); err != nil {
		return fail(StatusGeneralError, "live media validation canceled", err)
	}
	if err != nil {
		return fail(StatusLiveVideoSegmentInvalid, "cannot read complete media segment", err)
	}
	if len(data) >= limit {
		return fail(StatusLiveVideoSegmentInvalid, "media segment reached scan cap", nil)
	}
	top, err := liveSegmentBoxes(ctx, data)
	if err != nil {
		return fail(StatusLiveVideoSegmentInvalid, "invalid media segment structure", err)
	}
	var event liveEvent
	count := 0
	moofAt := len(data)
	eventAt := -1
	manifestCount := 0
	for i, b := range top {
		if b.typ == "ftyp" || b.typ == "moov" || (b.typ == "styp" && i != 0) {
			return fail(StatusLiveVideoSegmentInvalid, "invalid media segment box placement", nil)
		}
		if b.typ == "uuid" && b.usertype == c2paBoxUUID {
			manifestCount++
			if eventAt >= 0 {
				return fail(StatusLiveVideoManifestInvalid, "manifest announcement must precede VSI", nil)
			}
		}
		if b.typ == "moof" && b.start < moofAt {
			moofAt = b.start
		}
		if (b.typ == "sidx" || b.typ == "prft") && eventAt >= 0 {
			return fail(StatusLiveVideoSegmentInvalid, "index/producer-time boxes must precede VSI", nil)
		}
		e, yes, err := parseLiveEMSG(data, b)
		if err != nil {
			return fail(StatusLiveVideoSegmentInvalid, "invalid VSI event", err)
		}
		if yes {
			event, eventAt = e, b.start
			count++
		}
	}
	if count != 1 || eventAt >= moofAt {
		return fail(StatusLiveVideoSegmentInvalid, "segment requires one VSI before moof", nil)
	}
	if manifestCount > 1 {
		return fail(StatusLiveVideoManifestInvalid, "multiple manifest announcements", nil)
	}
	// kid is only a lookup hint. verifyLiveVSI checks it again and authenticates
	// the attached payload against this key and its authorizing manifest.
	var envelope cose.Sign1Message
	if err := envelope.UnmarshalCBOR(event.payload); err != nil {
		return fail(StatusLiveVideoSegmentInvalid, "invalid VSI COSE envelope", err)
	}
	kid, ok := envelope.Headers.Unprotected[cose.HeaderLabelKeyID].([]byte)
	if !ok {
		return fail(StatusLiveVideoSegmentInvalid, "VSI has no byte-string kid", nil)
	}
	// Unverified fields are lookup hints only. Signature verification below binds
	// the selected key to this exact authorizing manifest.
	fields, err := liveMap(envelope.Payload, "manifestId", "sequenceNumber", "bmffHash")
	if err != nil {
		return fail(StatusLiveVideoSegmentInvalid, "invalid VSI payload", err)
	}
	var manifestID string
	var sequence uint64
	if liveDecMode.Unmarshal(fields["manifestId"], &manifestID) != nil || manifestID == "" || len(fields["sequenceNumber"]) == 0 || fields["sequenceNumber"][0]>>5 != 0 || liveDecMode.Unmarshal(fields["sequenceNumber"], &sequence) != nil {
		return fail(StatusLiveVideoSegmentInvalid, "invalid VSI lookup fields", nil)
	}
	ref, err := decodeLiveManifestReference(fields["manifestUri"])
	if err != nil {
		return fail(StatusLiveVideoManifestInvalid, "invalid manifestUri", err)
	}
	if manifestCount == 1 {
		var code StatusCode
		if locallyVerified != nil {
			state, code, err = stageLiveAnnouncementResult(ctx, data, state, manifestID, sequence, *locallyVerified, policy.MaxManifests)
		} else {
			state, code, err = l.stageLiveAnnouncement(ctx, data, state, manifestID, sequence)
		}
		if err != nil {
			if canceled := ctx.Err(); canceled != nil {
				return fail(StatusGeneralError, "manifest announcement canceled", canceled)
			}
			return fail(code, "manifest announcement rejected", err)
		}
	}
	if ref != nil {
		state, err = l.resolveLiveManifest(ctx, state, data, manifestID, sequence, ref, policy.MaxManifests)
		if err != nil {
			if canceled := ctx.Err(); canceled != nil {
				return fail(StatusGeneralError, "remote manifest canceled", canceled)
			}
			return fail(StatusLiveVideoManifestInvalid, "remote manifest rejected", err)
		}
	}
	key, ok := state.keyForManifest(manifestID, string(kid))
	if !ok {
		return fail(StatusLiveVideoSegmentInvalid, "VSI session key is unknown", nil)
	}
	info, err := verifyLiveVSI(event.payload, key, manifestID)
	if err != nil {
		return fail(StatusLiveVideoSegmentInvalid, "VSI signature or payload is invalid", err)
	}
	result.SequenceNumber = info.sequence
	result.ManifestID = info.manifestID
	if err := verifyLiveVSIHash(ctx, data, info); err != nil {
		if cancelErr := ctx.Err(); cancelErr != nil {
			return fail(StatusGeneralError, "live media validation canceled", cancelErr)
		}
		result.Binding = BindingFailed
		return fail(StatusLiveVideoSegmentInvalid, "VSI media hash is invalid", err)
	}
	result.Binding = BindingVerified
	add(StatusAssertionBMFFHashMatch, "VSI media hash matches the signature-verified payload", nil)
	timing, err := liveSegmentTiming(ctx, data, top, state.track)
	if err != nil {
		return fail(StatusLiveVideoSegmentInvalid, "unsupported or malformed segment timing", err)
	}
	if info.sequence != uint64(timing.sequence) {
		return fail(StatusLiveVideoSegmentInvalid, "VSI sequence does not match mfhd sequence", nil)
	}
	if state.seen && info.sequence <= state.lastSequence {
		return fail(StatusLiveVideoSegmentInvalid, "repeated or decreasing VSI sequence number", nil)
	}
	if info.sequence < key.minSequence {
		return fail(StatusLiveVideoSegmentInvalid, "VSI sequence is below the session key minimum", nil)
	}
	if event.timescale != state.track.timescale || uint64(event.duration) != timing.duration {
		return fail(StatusLiveVideoSegmentInvalid, "VSI event timing does not cover the authenticated track segment", nil)
	}
	if state.origin == nil {
		return fail(StatusLiveVideoSegmentInvalid, "explicit presentation-time origin is required", nil)
	}
	presentation, subNano, err := livePresentationTime(*state.origin, timing.presentationStart, state.track.timescale)
	if err != nil {
		return fail(StatusLiveVideoSegmentInvalid, "cannot map presentation time", err)
	}
	result.PresentationTime = presentation
	end := time.Unix(key.created.Unix()+int64(key.validity), int64(key.created.Nanosecond()))
	if !key.permits(info.sequence, presentation) || (subNano && presentation.Equal(end)) {
		return fail(StatusLiveVideoSegmentInvalid, "segment presentation time is outside the session key validity period", nil)
	}
	if _, used := state.eventIDs[event.id]; !policy.MonotonicEventIDs && used {
		return fail(StatusLiveVideoSegmentInvalid, "VSI event ID is not session-unique", nil)
	}
	if policy.MonotonicEventIDs && state.seen && event.id <= state.lastEventID {
		return fail(StatusLiveVideoSegmentInvalid, "event ID must strictly increase under monotonic policy", nil)
	}
	if !policy.MonotonicEventIDs && len(state.eventIDs) >= maxLiveEventIDs {
		return fail(StatusLiveVideoSegmentInvalid, "session event-ID history limit reached; reinitialization is required", nil)
	}
	var credentialStatuses []StatusEntry
	state, credentialStatuses, err = l.recheckLiveCredential(ctx, state, info.manifestID, policy)
	result.Statuses = append(result.Statuses, credentialStatuses...)
	if err != nil {
		if canceled := ctx.Err(); canceled != nil {
			return fail(StatusGeneralError, "credential recheck canceled", canceled)
		}
		return fail(StatusLiveVideoSessionKeyInvalid, "authorizing credential recheck failed", err)
	}
	if err := ctx.Err(); err != nil {
		return fail(StatusGeneralError, "live media validation canceled", err)
	}
	if !policy.MonotonicEventIDs && state.eventIDs == nil {
		state.eventIDs = make(map[uint32]struct{})
	}
	if !policy.MonotonicEventIDs {
		state.eventIDs[event.id] = struct{}{}
	}
	state.lastEventID = event.id
	state.lastSequence, state.seen = info.sequence, true
	l.init = state
	result.Valid = true
	return result
}
