// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The settings-only VALIDATE crossing used by --validate, before OPEN, through both real doors.

use busbar_auth_admin_tokens::{EMPTY_TOKEN, NOT_A_DIGEST};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::{
    call::{Blob, InHead, OutHead, BLOB_JSON},
    lifecycle::{slot as life, OpenIn, OpenOut, ValidateIn},
};
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of, Bind, Called, DispatchConfig,
    Dispatcher, Frame, LinkedRow, Plugin,
};
use std::sync::Arc;

#[test]
fn validate_refuses_every_invalid_digest_before_open_and_keeps_the_error_safe() {
    let misplaced_token = "admin-validation-raw-token-canary";
    let misplaced_settings = format!("\"{misplaced_token}\"");
    let cases: &[(&[u8], &str)] = &[
        (b"{}", NOT_A_DIGEST),
        (b"null", NOT_A_DIGEST),
        (b"not-json", NOT_A_DIGEST),
        (misplaced_settings.as_bytes(), NOT_A_DIGEST),
        (
            br#""ga7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad""#,
            NOT_A_DIGEST,
        ),
        (
            br#""e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855""#,
            EMPTY_TOKEN,
        ),
    ];
    for dropped in [false, true] {
        let leg = if dropped { "dropped" } else { "linked" };
        let dispatcher = Dispatcher::new(DispatchConfig::default());
        let bind = Bind {
            instance: "admin-settings-validation".into(),
            max_inflight_cap: 64,
            sink: Arc::new(busbar_plugin_loader::dispatch::NoSink),
            dispatcher: dispatcher.adopter(),
            conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
        };
        let plugin = if dropped {
            let path =
                std::path::PathBuf::from(std::env::var_os("BUSBAR_PLUGIN_CDYLIB").expect(
                    "build the fresh actual admin-tokens cdylib and set BUSBAR_PLUGIN_CDYLIB",
                ));
            assert!(
                path.is_absolute() && path.is_file(),
                "BUSBAR_PLUGIN_CDYLIB must name the fresh actual product image"
            );
            load_dropped::<Auth>(
                &path,
                &rendering_of(busbar_auth_admin_tokens::door::door).unwrap(),
                bind,
            )
        } else {
            load_linked::<Auth>(
                &LinkedRow::of(busbar_auth_admin_tokens::door::door).unwrap(),
                bind,
            )
        }
        .expect("load the real admin-token door");
        for &(settings, expected) in cases {
            let validated = validate(&plugin, settings);
            assert_eq!(validated.outcome, Outcome::Failed, "{leg:?}: {validated:?}");
            let text = String::from_utf8(validated.error.expect("a settings refusal says why"))
                .expect("the refusal is text");
            assert_eq!(text, expected, "{leg:?}");
            assert!(!text.contains(misplaced_token));
            assert_eq!(open(&plugin, settings).outcome, Outcome::Failed);
        }

        let valid = br#"" \tBA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD\n""#;
        assert_eq!(validate(&plugin, valid).outcome, Outcome::Ready);
        assert_eq!(validate(&plugin, valid).outcome, Outcome::Ready);
        assert_eq!(open(&plugin, valid).outcome, Outcome::Ready);
        assert_eq!(close(&plugin).outcome, Outcome::Ready);
        assert_eq!(
            plugin
                .inner
                .crossings
                .load(std::sync::atomic::Ordering::Relaxed),
            16
        );
        assert_eq!(
            plugin
                .inner
                .resumes
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }
}

fn json(settings: &[u8]) -> Blob {
    Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}
fn validate(p: &Plugin<Auth>, settings: &[u8]) -> Called {
    let mut error = [0u8; 512];
    let mut f = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: json(settings),
            err_buf: error.as_mut_ptr(),
            err_cap: error.len(),
            ..unsafe { std::mem::zeroed() }
        },
        out_head(),
    );
    let before = plugin_counts(p);
    let answer = p.call(life::VALIDATE, &mut f);
    assert_eq!(plugin_counts(p), (before.0 + 1, before.1));
    answer
}
fn open(p: &Plugin<Auth>, settings: &[u8]) -> Called {
    let mut f = Frame::new(
        OpenIn {
            head: in_head(),
            settings: json(settings),
            generation: 1,
            ..unsafe { std::mem::zeroed() }
        },
        OpenOut {
            head: out_head(),
            ..unsafe { std::mem::zeroed() }
        },
    );
    let before = plugin_counts(p);
    let answer = p.call(life::OPEN, &mut f);
    assert_eq!(plugin_counts(p), (before.0 + 1, before.1));
    answer
}
fn close(p: &Plugin<Auth>) -> Called {
    let before = plugin_counts(p);
    let answer = p.call(
        life::CLOSE,
        &mut Frame::<InHead, OutHead>::new(in_head(), out_head()),
    );
    assert_eq!(plugin_counts(p), (before.0 + 1, before.1));
    answer
}
fn plugin_counts(p: &Plugin<Auth>) -> (u64, u64) {
    use std::sync::atomic::Ordering::SeqCst;
    (p.inner.crossings.load(SeqCst), p.inner.resumes.load(SeqCst))
}
