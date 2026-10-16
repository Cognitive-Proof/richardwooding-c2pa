//! Test-only adapter for c2pa-rs 8f16c0f78673461ba41c184e71d29a6492be571c.
//! Install as a child module of live_video::vsi_signing; see README.md.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::{
    assertion::AssertionBase, live_video::LiveVideoValidator, status_tracker::StatusTracker,
};
use chrono::{TimeZone, Utc};
use std::{fs, io::Cursor, path::Path, sync::Arc};

fn settings(root: &str) -> crate::settings::Settings {
    crate::settings::Settings::new()
        .with_json(
            &serde_json::json!({
                "trust":{"anchors":[{"trust_anchors":root,"trust_kind":"manifest"}]},
                "verify":{"verify_trust":true}
            })
            .to_string(),
        )
        .unwrap()
}

fn validator(dir: &Path) -> LiveVideoValidator {
    let init = fs::read(dir.join("init.mp4")).unwrap();
    let root = fs::read_to_string(dir.join("root.pem")).unwrap();
    let context = Arc::new(
        crate::Context::new()
            .with_settings(settings(&root))
            .unwrap(),
    );
    let reader = Reader::from_shared_context(&context)
        .with_stream("video/mp4", Cursor::new(&init))
        .unwrap();
    assert_eq!(
        reader.validation_state(),
        crate::ValidationState::Trusted,
        "manifest must validate with explicit root: {:?}",
        reader.validation_results()
    );
    let id = reader.active_manifest().unwrap().label().unwrap();
    let claim = reader.store.get_claim(id).unwrap();
    let keys =
        SessionKeys::from_assertion(claim.get_assertion(SessionKeys::LABEL, 0).unwrap()).unwrap();
    let certs = crate::crypto::cose::cert_chain_from_sign1(&claim.cose_sign1().unwrap()).unwrap();
    let mut v = LiveVideoValidator::new();
    let mut tracker = StatusTracker::default();
    v.validate_init_segment(&init, &mut tracker).unwrap();
    v.set_media_time_origin(chrono::DateTime::<Utc>::UNIX_EPOCH);
    v.validate_session_keys(&keys, id, Some(&certs[0]), &mut tracker)
        .unwrap();
    assert!(
        tracker.filter_errors().collect::<Vec<_>>().is_empty(),
        "{tracker:?}"
    );
    v
}

#[test]
fn go_interop_generate_rust() {
    let out = std::env::var("C2PA_INTEROP_RUST").unwrap();
    let input = std::env::var("C2PA_INTEROP_INPUT").unwrap();
    let out = Path::new(&out);
    fs::create_dir_all(out).unwrap();
    let credentials = std::env::var("C2PA_INTEROP_CREDENTIALS").unwrap();
    let manifest_signer = crate::create_signer::from_keys(
        &fs::read(Path::new(&credentials).join("chain.pem")).unwrap(),
        &fs::read(Path::new(&credentials).join("key.pem")).unwrap(),
        crate::SigningAlg::Ed25519,
        None,
    )
    .unwrap();
    let certs = manifest_signer.certs().unwrap();
    let root = pem::encode(&pem::Pem::new("CERTIFICATE", certs.last().unwrap().clone()));
    // Authoring also performs trust verification, with this fixture's explicit root.
    crate::settings::set_settings_value(
        "trust.anchors",
        serde_json::json!([{"trust_anchors":root,"trust_kind":"manifest"}]),
    )
    .unwrap();
    crate::settings::set_settings_value("verify.verify_trust", true).unwrap();
    let mut signer = LiveVideoVsiSigner::from_signing_key(
        r#"{"assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"http://c2pa.org/digitalsourcetype/empty"}]}}]}"#,
        manifest_signer.as_ref(), SigningKey::from_bytes(&[0x42;32]), b"rust-go-interop".to_vec(), 880000021, 60).unwrap();
    signer.session_keys[0].created_at = Utc
        .timestamp_opt(1760000042, 0)
        .single()
        .unwrap()
        .to_rfc3339();
    fs::write(out.join("root.pem"), root).unwrap();
    fs::write(out.join("validation-time.txt"), Utc::now().to_rfc3339()).unwrap();
    let init = fs::read(Path::new(&input).join("init.mp4")).unwrap();
    fs::write(
        out.join("init.mp4"),
        signer
            .sign_init_segment(&init, "video/mp4", manifest_signer.as_ref())
            .unwrap(),
    )
    .unwrap();
    for n in 880000021..=880000023 {
        let name = format!("{n}.m4s");
        let media = fs::read(Path::new(&input).join(&name)).unwrap();
        fs::write(out.join(name), signer.sign_media_segment(&media).unwrap()).unwrap();
    }
    check(out);
    crate::settings::reset_default_settings().unwrap();
}

fn check(dir: &Path) {
    let mut v = validator(dir);
    for n in 880000021..=880000023 {
        let media = fs::read(dir.join(format!("{n}.m4s"))).unwrap();
        let mut tracker = StatusTracker::default();
        v.validate_verifiable_segment_info(&media, &mut tracker)
            .unwrap();
        assert!(
            tracker.filter_errors().collect::<Vec<_>>().is_empty(),
            "{tracker:?}"
        );
        // A fresh receiver must reject a changed sample byte, independently of continuity.
        let mut damaged = media;
        *damaged.last_mut().unwrap() ^= 1;
        let mut negative = validator(dir);
        let mut tracker = StatusTracker::default();
        let result = negative.validate_verifiable_segment_info(&damaged, &mut tracker);
        assert!(result.is_err() || tracker.filter_errors().next().is_some());
    }
}

#[test]
fn go_interop_validate_go() {
    let dir = std::env::var("C2PA_INTEROP_GO").unwrap();
    check(Path::new(&dir));
    // A different, valid test CA must not authorize the Go initialization.
    let other = std::env::var("C2PA_INTEROP_RUST").unwrap();
    let root = fs::read_to_string(Path::new(&other).join("root.pem")).unwrap();
    let context = Arc::new(
        crate::Context::new()
            .with_settings(settings(&root))
            .unwrap(),
    );
    let reader = Reader::from_shared_context(&context)
        .with_stream(
            "video/mp4",
            Cursor::new(fs::read(Path::new(&dir).join("init.mp4")).unwrap()),
        )
        .unwrap();
    assert_ne!(reader.validation_state(), crate::ValidationState::Trusted);
}

#[test]
fn go_interop_validate_go_rotation() {
    let Ok(dir) = std::env::var("C2PA_INTEROP_ROTATION") else {
        return;
    };
    let dir = Path::new(&dir);
    let root = fs::read_to_string(dir.join("root.pem")).unwrap();
    let context = Arc::new(
        crate::Context::new()
            .with_settings(settings(&root))
            .unwrap(),
    );
    let mut v = validator(dir);
    for n in 880000021..=880000023 {
        let media = fs::read(dir.join(format!("{n}.m4s"))).unwrap();
        let mut tracker = StatusTracker::default();
        v.validate_verifiable_segment_info_with_context(&media, &context, &mut tracker)
            .unwrap();
        assert!(
            tracker.filter_errors().collect::<Vec<_>>().is_empty(),
            "{tracker:?}"
        );
        if n == 880000022 {
            assert_eq!(
                v.session_key_manifest_state(),
                Some(crate::ValidationState::Trusted)
            );
        }
    }
}
