// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/auth-admin-tokens/src/lib.rs`.

use super::*;
use busbar_contract::sha256_hex;

fn hash(s: &str) -> String {
    sha256_hex(s.as_bytes())
}

/// The fold over at most one line per carrier, as `verify` runs it.
fn fold(configured_hash: &str, bearer: Option<&str>, header: Option<&str>) -> Verdict {
    judge(
        configured_hash,
        bearer.as_slice(),
        header.as_slice(),
        token_matches,
    )
}

#[test]
fn no_credential_passes() {
    let h = hash("secret");
    assert_eq!(fold(&h, None, None), Verdict::Pass);
}

/// Both carriers matching (where `|` and `^` differ) still identifies.
#[test]
fn either_carrier_identifies() {
    let h = hash("secret");
    for (b, hd) in [
        (Some("secret"), None),
        (None, Some("secret")),
        (Some("secret"), Some("secret")),
        (Some("secret"), Some("wrong")),
        (Some("wrong"), Some("secret")),
    ] {
        match fold(&h, b, hd) {
            Verdict::Identity(p) => assert_eq!(p.subject, ADMIN_TOKENS_PRINCIPAL_ID),
            other => panic!("expected Identify, got {other:?} for ({b:?},{hd:?})"),
        }
    }
}

/// A configured token that is itself JWS-shaped identifies.
#[test]
fn a_jws_shaped_configured_token_identifies() {
    let token = "abc.def.ghi";
    let h = hash(token);
    match fold(&h, Some(token), None) {
        Verdict::Identity(p) => assert_eq!(p.subject, ADMIN_TOKENS_PRINCIPAL_ID),
        other => panic!("expected Identity, got {other:?}"),
    }
    let settings = format!("\"{h}\"");
    let plugin = <AdminTokens as VerifyPlugin>::open_refusing(settings.as_bytes(), &[])
        .expect("a digest opens");
    match fold(&plugin.digest(), Some(token), None) {
        Verdict::Identity(p) => assert_eq!(p.subject, ADMIN_TOKENS_PRINCIPAL_ID),
        other => panic!("expected Identity, got {other:?}"),
    };
}

#[test]
fn wrong_credential_rejects() {
    let h = hash("secret");
    assert_eq!(fold(&h, Some("nope"), None), Verdict::Reject);
    assert_eq!(fold(&h, None, Some("nope")), Verdict::Reject);
}

#[test]
fn a_non_jws_wrong_credential_still_terminally_rejects() {
    let h = hash("secret");

    for candidate in ["nope", "a.b", "a.b.c.d", "a..c", ".b.c", "a.b."] {
        assert_eq!(
            fold(&h, Some(candidate), None),
            Verdict::Reject,
            "`{candidate}` is addressed to this module and wrong; it must deny, not pass"
        );
        assert_eq!(
            fold(&h, None, Some(candidate)),
            Verdict::Reject,
            "`{candidate}` on the header carrier must deny too"
        );
    }
}

#[test]
fn a_jws_shaped_wrong_token_never_admits_and_the_fold_still_finds_the_token() {
    let h = hash("secret");
    let jws = "aaa.bbb.ccc";
    assert_eq!(fold(&h, Some(jws), None), Verdict::Reject);

    for (b, hd) in [(Some("secret"), Some(jws)), (Some(jws), Some("secret"))] {
        match fold(&h, b, hd) {
            Verdict::Identity(p) => assert_eq!(p.subject, ADMIN_TOKENS_PRINCIPAL_ID),
            other => panic!("expected Identify, got {other:?} for ({b:?},{hd:?})"),
        }
    }
}

/// The `X-Admin-Token` line as 1.5.5 read it: blank or not header text is absent.
#[test]
fn a_blank_or_non_text_admin_header_is_absent() {
    for value in [
        &b""[..],
        "t\u{f6}k\u{e9}n".as_bytes(),
        b"tok\x01en",
        b"\xff",
    ] {
        assert_eq!(header_line(value), None, "{value:?}");
    }
    assert_eq!(header_line(b"the-token"), Some("the-token"));
    assert_eq!(header_line(b"a b\tc"), Some("a b\tc"));
}

/// `open` takes the digest, never the raw token, and refuses anything that is not one — with a
/// refusal ([`NOT_A_DIGEST`]) that never echoes the value.
#[test]
fn open_refuses_settings_that_are_not_a_sha256_hex_digest() {
    let h = hash("secret");
    for settings in [
        "".to_string(),
        "\"\"".to_string(),
        "\"   \"".to_string(),
        "\"secret\"".to_string(),
        format!("\"{}\"", &h[..63]),
        format!("\"{h}0\""),
        format!("\"{}\"", "zz".repeat(32)),
        h.clone(),
        format!("{{\"token\":\"{h}\"}}"),
    ] {
        let err = <AdminTokens as VerifyPlugin>::open_refusing(settings.as_bytes(), &[])
            .err()
            .unwrap_or_else(|| panic!("{settings:?} opened"));
        assert_eq!(err, Refusal::failed(NOT_A_DIGEST));
    }
}

/// The digest of the empty string is a blank admin token: refused, in either case, without echo.
#[test]
fn open_refuses_the_digest_of_an_empty_token() {
    let d = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(hash(""), d);
    for digest in [d.to_string(), d.to_ascii_uppercase(), format!(" {d}\\n")] {
        let settings = format!("\"{digest}\"");
        let err = <AdminTokens as VerifyPlugin>::open_refusing(settings.as_bytes(), &[])
            .err()
            .unwrap_or_else(|| panic!("{settings:?} opened"));
        assert_eq!(err, Refusal::failed(EMPTY_TOKEN));
        assert!(err.to_string().contains("empty token"), "{err}");
        assert!(!err.to_string().to_ascii_lowercase().contains(d), "{err}");
    }
}

/// The digest opens with surrounding whitespace and in either case.
#[test]
fn open_takes_the_digest_trimmed_in_either_case() {
    let h = hash("secret");
    let settings = format!("\"  {}\\n\"", h.to_ascii_uppercase());
    let plugin =
        <AdminTokens as VerifyPlugin>::open_refusing(settings.as_bytes(), &[]).expect("opens");
    assert_eq!(plugin.digest().as_str(), h);
}

/// The Statement names the module and its two credential lines.
#[test]
fn the_statement_names_the_module_and_the_header_carrier() {
    assert_eq!(STATEMENT.name.len, ADMIN_TOKENS_MODULE_NAME.len());
    assert_eq!(
        STATEMENT.mark_words_len, 2,
        "its two carriers are Statement word marks"
    );
    assert_eq!(TAIL.caps, busbar_contract::abi::auth::CAP_INBOUND);
    assert_eq!(
        TAIL.facts,
        busbar_contract::abi::auth::FACT_OPERATOR,
        "the operator credential, and a rotatable compare is never cached"
    );
    assert_eq!(TAIL.operator_principal.len, ADMIN_TOKENS_PRINCIPAL_ID.len());
}

/// The Bearer comes off the `authorization` line: the scheme in any case, a
/// non-empty token, and a value that is header text; anything else presents no Bearer.
#[test]
fn the_bearer_is_read_off_the_authorization_line() {
    assert_eq!(bearer_line(b"Bearer abc123"), Some("abc123"));
    assert_eq!(bearer_line(b"bEaReR abc123"), Some("abc123"));
    assert_eq!(bearer_line(b"Basic abc123"), None);
    assert_eq!(bearer_line(b"Bearer "), None);
    assert_eq!(bearer_line(b"Bearer"), None);
    assert_eq!(bearer_line(b""), None);
    assert_eq!(
        bearer_line(b"Bearer \xff"),
        None,
        "a non-UTF-8 value is not a Bearer"
    );
}

/// Bearer consumes the RFC 6750 ASCII-space separator run, not arbitrary token whitespace.
#[test]
fn the_bearer_consumes_the_scheme_separator_and_preserves_token_bytes() {
    let h = hash("secret");
    for value in ["Bearer secret", "Bearer  secret", "bEaReR    secret"] {
        assert_eq!(bearer_line(value.as_bytes()), Some("secret"));
        assert!(matches!(
            fold(&h, bearer_line(value.as_bytes()), None),
            Verdict::Identity(_)
        ));
    }
    for value in ["Bearer ", "Bearer    ", "Bearer\tsecret", " Bearer secret"] {
        assert_eq!(bearer_line(value.as_bytes()), None);
    }
    for token in ["a b", "secret ", "\tsecret", "secret\t"] {
        let value = format!("Bearer  {token}");
        assert_eq!(bearer_line(value.as_bytes()), Some(token));
        assert_eq!(
            fold(&h, bearer_line(value.as_bytes()), None),
            Verdict::Reject,
            "separator parsing must not normalize token bytes"
        );
    }
    assert_eq!(
        fold(&h, bearer_line(b"Bearer  wrong"), None),
        Verdict::Reject
    );
}

/// `Debug` never prints the admin token's digest.
#[test]
fn debug_never_prints_the_configured_digest() {
    let h = hash("secret");
    let settings = format!("\"{h}\"");
    let plugin =
        <AdminTokens as VerifyPlugin>::open_refusing(settings.as_bytes(), &[]).expect("opens");
    let shown = format!("{plugin:?}");
    assert!(!shown.contains(&h), "{shown}");
    assert!(!shown.contains(&h[..16]), "{shown}");
}

/// A wrong token is refused AND the refusal is logged (module = admin-tokens), with neither the
/// token nor the digest in the log.
#[test]
fn a_wrong_token_reject_is_logged_without_the_token() {
    let h = hash("secret");
    let cap = LogCapture::capturing_debug();
    let verdict = tracing::subscriber::with_default(cap.subscriber(), || {
        fold(&h, Some("WRONG-TOKEN-TEXT"), None)
    });
    assert_eq!(verdict, Verdict::Reject);
    let logged = cap.messages().join("\n");
    assert!(logged.contains("admin-tokens"), "{logged:?}");
    assert!(logged.contains("mismatch"), "{logged:?}");
    assert!(!logged.contains("WRONG-TOKEN-TEXT"), "{logged:?}");
    assert!(!logged.contains(&h[..16]), "{logged:?}");
}

/// Passes (no token presented, none configured) are not refusals and log nothing.
#[test]
fn a_pass_logs_nothing() {
    let h = hash("secret");
    let cap = LogCapture::capturing_debug();
    tracing::subscriber::with_default(cap.subscriber(), || {
        assert_eq!(fold(&h, None, None), Verdict::Pass);
    });
    assert!(cap.messages().is_empty(), "{:?}", cap.messages());
}

/// A credential line that is not header text is read as absent AND says so in the log, without the
/// value.
#[test]
fn a_non_header_text_credential_line_is_logged() {
    let cap = LogCapture::capturing_debug();
    tracing::subscriber::with_default(cap.subscriber(), || {
        assert_eq!(bearer_line(b"Bearer sec\xffret"), None);
        assert_eq!(header_line(b"sec\x01ret"), None);

        assert_eq!(bearer_line(b"Basic abc"), None);
    });
    let logged = cap.messages().join("\n");
    assert!(logged.contains("admin-tokens"), "{logged:?}");
    assert!(logged.contains("authorization"), "{logged:?}");
    assert!(logged.contains("x-admin-token"), "{logged:?}");
    assert!(!logged.contains("ret"), "value leaked: {logged:?}");
    assert_eq!(cap.messages().len(), 2, "{logged:?}");
}

/// A credential line that is PRESENT but yields no token (an empty Bearer token, a blank
/// `X-Admin-Token`) is read as absent and says so in the log; a token or other scheme logs nothing.
#[test]
fn a_present_line_with_no_token_is_logged() {
    let cap = LogCapture::capturing_debug();
    tracing::subscriber::with_default(cap.subscriber(), || {
        assert_eq!(bearer_line(b"Bearer "), None);
        assert_eq!(bearer_line(b"Bearer"), None);
        assert_eq!(header_line(b""), None);
    });
    let logged = cap.messages().join("\n");
    assert!(logged.contains("authorization"), "{logged:?}");
    assert!(logged.contains("x-admin-token"), "{logged:?}");
    assert!(logged.contains("carries no token"), "{logged:?}");
    assert_eq!(cap.messages().len(), 3, "{logged:?}");
    assert_eq!(cap.count("authorization"), 2, "{logged:?}");

    let cap = LogCapture::capturing_debug();
    tracing::subscriber::with_default(cap.subscriber(), || {
        assert_eq!(bearer_line(b"Basic abc"), None);
        assert_eq!(bearer_line(b"Bearer tok"), Some("tok"));
        assert_eq!(header_line(b"tok"), Some("tok"));
    });
    assert!(cap.messages().is_empty(), "{:?}", cap.messages());
}

/// The primitive answers equality only for the same full byte string. Constant-time use is
/// the contract's guarantee, not measured here.
#[test]
fn the_constant_time_primitive_compares_the_full_bytes() {
    assert!(constant_time_eq("abc", "abc"));
    assert!(!constant_time_eq("abc", "abd"));
    assert!(!constant_time_eq("abc", "abcd"));
}

/// An admin token never appears in a log line or an error string: not when it matches, not when it
/// mismatches, not when its line is malformed, and not in a settings refusal or `Debug`.
#[test]
fn an_admin_token_never_appears_in_logs_or_errors() {
    const TOKEN: &str = "ADMIN-SENTINEL-7f3a91c2e8b4";
    let h = hash(TOKEN);
    let cap = LogCapture::capturing_debug();
    let mut surfaces: Vec<String> = Vec::new();
    tracing::subscriber::with_default(cap.subscriber(), || {
        let _ = fold(&h, Some(TOKEN), None);
        let _ = fold(&h, None, Some(TOKEN));
        let _ = fold(&h, Some(&format!("{TOKEN}x")), None);
        let _ = fold(&h, None, Some(&format!("x{TOKEN}")));

        let _ = bearer_line(format!("Bearer {TOKEN}\u{1}").as_bytes());
        let _ = header_line(format!("{TOKEN}\u{7f}").as_bytes());
        let _ = bearer_line(format!("Bearer {TOKEN}\u{ff}").as_bytes());
    });

    for settings in [
        TOKEN.to_string(),
        format!("\"{TOKEN}\""),
        format!("\"{}\"", hash("")),
        format!("{{\"token\": \"{TOKEN}\"}}"),
    ] {
        match digest_of(settings.as_bytes()) {
            Err(e) => surfaces.push(e.to_string()),
            Ok(d) => panic!("settings {settings:?} were accepted as the digest {d:?}"),
        }
        match <AdminTokens as VerifyPlugin>::open_refusing(settings.as_bytes(), &[]) {
            Err(e) => surfaces.push(e.to_string()),
            Ok(_) => panic!("open accepted {settings:?}"),
        }
    }

    let plugin = <AdminTokens as VerifyPlugin>::open_refusing(format!("\"{h}\"").as_bytes(), &[])
        .expect("opens");
    surfaces.push(format!("{plugin:?}"));
    surfaces.extend(cap.messages());
    for surface in &surfaces {
        assert!(!surface.contains(TOKEN), "token leaked: {surface:?}");
        assert!(!surface.contains(&h), "digest leaked: {surface:?}");
        assert!(
            !surface.contains(&h[..16]),
            "digest prefix leaked: {surface:?}"
        );
    }
    assert!(!cap.messages().is_empty(), "the refusals were logged");
}

/// The Statement declares the verifier's concurrency ([`CONCURRENCY`]): a pure compare holding only
/// the rotatable digest, as webhook-signature, sigv4 and oauth do.
#[test]
fn statement_concurrency_is_1024() {
    assert_eq!(STATEMENT.max_inflight, 1024);
}

/// A settings refusal is a line in the contract's instance-relative form (`settings: <reason>`), so
/// the host reports it as `auth.admin-tokens.settings: <reason>`, never echoing the value.
#[test]
fn a_settings_refusal_is_an_instance_relative_settings_line() {
    use busbar_contract::abi::mechanism::lifecycle::{check_validate_refusal, refusal_lines};
    for refusal in [NOT_A_DIGEST, EMPTY_TOKEN] {
        assert!(refusal.starts_with("settings: "), "{refusal}");
        assert!(
            check_validate_refusal(refusal.as_bytes()).is_ok(),
            "{refusal}"
        );
        let lines = refusal_lines("auth", "admin-tokens", refusal);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].starts_with("auth.admin-tokens.settings: "),
            "{lines:?}"
        );
        assert!(refusal.contains("not echoed"), "{refusal}");
    }
}

/// A refresh whose settings are not a digest is refused (FAILED, never echoing the value), keeps the
/// digest held AND says so in the log once, at WARN.
#[test]
fn a_refused_refresh_is_logged_and_keeps_the_digest() {
    const RAW: &str = "REFRESH-RAW-TOKEN-5c1e";
    let h = hash("secret");
    let plugin = <AdminTokens as VerifyPlugin>::open_refusing(format!("\"{h}\"").as_bytes(), &[])
        .expect("opens");
    let cap = LogCapture::capturing_debug();
    tracing::subscriber::with_default(cap.subscriber(), || {
        assert_eq!(
            plugin.reload(format!("\"{RAW}\"").as_bytes(), &[]),
            Err(Refusal::failed(NOT_A_DIGEST))
        );
    });
    assert_eq!(plugin.digest().as_str(), h, "the held digest stands");
    let logged = cap.messages().join("\n");
    assert_eq!(cap.messages().len(), 1, "{logged:?}");
    assert!(logged.contains("admin-tokens"), "{logged:?}");
    assert!(logged.contains("refresh"), "{logged:?}");
    assert!(!logged.contains(RAW), "settings echoed: {logged:?}");
    // A refused refresh leaves the old digest in force, so it is logged at WARN, not routine info.
    let cap = LogCapture::default();
    tracing::subscriber::with_default(cap.subscriber(), || {
        assert!(plugin.reload(format!("\"{RAW}\"").as_bytes(), &[]).is_err());
    });
    assert_eq!(
        cap.messages().len(),
        1,
        "a refused refresh logs at WARN: {:?}",
        cap.messages()
    );
    assert_eq!(
        cap.messages()[0].split_whitespace().next(),
        Some("WARN"),
        "the refused refresh must retain the audit's warning severity"
    );
    // An accepted refresh is not a refusal: it logs nothing.
    let rotated = hash("rotated");
    let cap = LogCapture::capturing_debug();
    tracing::subscriber::with_default(cap.subscriber(), || {
        assert_eq!(
            plugin.reload(format!("\"{rotated}\"").as_bytes(), &[]),
            Ok(0)
        );
    });
    assert_eq!(plugin.digest().as_str(), rotated);
    assert!(cap.messages().is_empty(), "{:?}", cap.messages());
}

/// The SDK's secret-derived digest is a wiping holder and agrees with an independent published
/// SHA-256 test vector.
#[test]
fn the_presented_token_uses_a_wiping_digest_with_unchanged_hash_bytes() {
    fn wipes<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let digest = sha256(&[b"abc"]);
    wipes(&digest);
    assert_eq!(
        &digest[..],
        &[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    );

    for len in [55, 56, 63, 64, 65, 127, 128, 129] {
        let token = "a".repeat(len);
        let configured = hash(&token);
        for (bearer, header) in [(Some(token.as_str()), None), (None, Some(token.as_str()))] {
            assert!(matches!(
                fold(&configured, bearer, header),
                Verdict::Identity(_)
            ));
        }
        assert_eq!(fold(&configured, Some("different"), None), Verdict::Reject);
    }
}

/// The held digest lives in a wiping holder (`ZeroizeOnDrop`), so the digest a `reload` replaces and
/// the one a dropped instance holds are zeroed; a reload replaces it in place, so the retired digest
/// is dropped, not kept alongside, and no longer admits. The crate forbids `unsafe`, so freed memory
/// is not read back: the wipe itself is `zeroize`'s, pinned here by the holder's type.
#[test]
fn the_held_digest_is_a_wiping_holder_that_a_reload_replaces() {
    fn wipes<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let first = hash("first");
    let settings = format!("\"{first}\"");
    let plugin =
        <AdminTokens as VerifyPlugin>::open_refusing(settings.as_bytes(), &[]).expect("opens");
    {
        let held = plugin.configured_hash.read().expect("unpoisoned");
        wipes(&*held);
        assert_eq!(held.as_str(), first);
    }
    wipes(&digest_of(settings.as_bytes()).expect("a digest"));
    let second = hash("second");
    assert_eq!(
        plugin.reload(format!("\"{second}\"").as_bytes(), &[]),
        Ok(0)
    );
    assert_eq!(plugin.digest().as_str(), second);
    assert_eq!(
        fold(&plugin.digest(), Some("first"), None),
        Verdict::Reject,
        "the retired digest no longer admits"
    );
    assert!(matches!(
        fold(&plugin.digest(), Some("second"), None),
        Verdict::Identity(_)
    ));
}

/// `header_text` accepts exactly tab and 0x20..=0x7e: the range edges (0x1f, 0x20, 0x7e, 0x7f).
#[test]
fn header_text_range_edges() {
    assert_eq!(header_text(&[0x1f]), None);
    assert_eq!(header_text(&[0x20]), Some(" "));
    assert_eq!(header_text(&[0x7e]), Some("~"));
    assert_eq!(header_text(&[0x7f]), None);
    assert_eq!(header_text(b"\t"), Some("\t"));
    assert_eq!(header_text(&[b'a', 0x7f, b'b']), None);
}

/// Once a credential is presented, both carriers are hashed and compared with no short circuit (an
/// absent one against the placeholder), and every presented copy of a carrier is compared: the
/// count of compares depends only on how many lines were presented, never on which one matched.
#[test]
fn every_carrier_and_every_copy_is_compared_with_no_short_circuit() {
    let h = hash("secret");
    let none: &[&str] = &[];
    for (bearers, headers, compares) in [
        (&["secret"][..], none, 2),
        (none, &["secret"][..], 2),
        (&["wrong"][..], none, 2),
        (&["secret"][..], &["secret"][..], 2),
        (&["secret"][..], &["wrong"][..], 2),
        (&["wrong"][..], &["secret"][..], 2),
        (&["secret", "wrong"][..], none, 3),
        (&["wrong", "secret"][..], &["secret"][..], 3),
        (&["secret", "secret"][..], &["wrong", "wrong"][..], 4),
        (none, none, 0),
    ] {
        let count = std::cell::Cell::new(0);
        let _ = judge(h.as_str(), bearers, headers, |token, configured| {
            count.set(count.get() + 1);
            token_matches(token, configured)
        });
        assert_eq!(
            count.get(),
            compares,
            "compares for ({bearers:?}, {headers:?})"
        );
    }
}

/// A carrier presented on more than one line matches only if every copy does: a wrong copy is a
/// presented wrong credential, whichever copy comes first. The other carrier still identifies on its
/// own, as a single wrong line beside a right one does.
#[test]
fn a_carrier_on_several_lines_matches_only_if_every_copy_does() {
    let h = hash("secret");
    let none: &[&str] = &[];
    for (bearers, headers, identifies) in [
        (&["secret", "secret"][..], none, true),
        (&["secret", "wrong"][..], none, false),
        (&["wrong", "secret"][..], none, false),
        (none, &["secret", "wrong"][..], false),
        (none, &["wrong", "secret"][..], false),
        (&["secret"][..], &["secret", "wrong"][..], true),
        (&["wrong", "secret"][..], &["secret"][..], true),
    ] {
        let verdict = judge(h.as_str(), bearers, headers, token_matches);
        if identifies {
            assert!(
                matches!(verdict, Verdict::Identity(_)),
                "({bearers:?}, {headers:?}): {verdict:?}"
            );
        } else {
            assert_eq!(verdict, Verdict::Reject, "({bearers:?}, {headers:?})");
        }
    }
}

/// A panic while the digest lock is held poisons it; the instance still judges against the digest
/// it holds and still takes a rotation, so one panic never takes the admin credential check down.
#[test]
fn a_poisoned_digest_lock_still_judges_and_rotates() {
    let first = hash("first");
    let plugin =
        <AdminTokens as VerifyPlugin>::open_refusing(format!("\"{first}\"").as_bytes(), &[])
            .expect("opens");
    let panicked = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let _held = plugin.configured_hash.write().expect("unpoisoned");
                panic!("poison the digest lock");
            })
            .join()
    });
    assert!(panicked.is_err());
    assert!(plugin.configured_hash.is_poisoned());
    assert_eq!(plugin.digest().as_str(), first);
    assert!(matches!(
        fold(&plugin.digest(), Some("first"), None),
        Verdict::Identity(_)
    ));
    let second = hash("second");
    assert_eq!(
        plugin.reload(format!("\"{second}\"").as_bytes(), &[]),
        Ok(0)
    );
    assert_eq!(plugin.digest().as_str(), second);
}

/// The settings string decodes to the same digest whether or not it escapes any of it: raw, with
/// JSON whitespace around the string, with escaped whitespace inside it, with a digit or every
/// character `\u`-escaped (either hex case), and with Unicode whitespace raw or escaped.
#[test]
fn a_digest_with_or_without_json_escapes_reads_the_same() {
    let h = hash("secret");
    let mut every_char_escaped = String::new();
    for c in h.chars() {
        every_char_escaped += &format!("\\u{:04X}", u32::from(c));
    }
    for settings in [
        format!("\"{h}\""),
        format!(" \r\n\t\"{}\"\n ", h.to_ascii_uppercase()),
        format!("\"\\t{h}\\n\\r\\f\""),
        format!("\"\\u00{:x}{}\"", h.as_bytes()[0], &h[1..]),
        format!("\"{every_char_escaped}\""),
        format!("\"\u{a0}{h}\\u2003\\u000B\\u000b\""),
    ] {
        assert_eq!(
            digest_of(settings.as_bytes())
                .as_deref()
                .map(String::as_str),
            Ok(h.as_str()),
            "{settings:?}"
        );
    }
}

/// Anything but a whitespace or hex character, raw or escaped, is refused without echo, as is
/// anything that is not exactly one well-formed JSON string.
#[test]
fn a_settings_string_with_a_non_hex_character_or_escape_is_refused() {
    let h = hash("secret");
    let (head, tail) = h.split_at(32);
    for inner in [
        "\\\"",
        "\\\\",
        "\\/",
        "\\b",
        "\\u0067",
        "\\u00e9",
        "\\uD800",
        "\\uDFFF",
        "\\uD83D\\uDE00",
        "\\u00",
        "\\u00g0",
        "\\q",
        "\\",
        "\u{1}",
        "\t",
        "\"",
        "\u{e9}",
    ] {
        let settings = format!("\"{head}{inner}{tail}\"");
        assert_eq!(
            digest_of(settings.as_bytes()),
            Err(NOT_A_DIGEST),
            "{settings:?}"
        );
    }
    for settings in [
        format!("\"{h}"),
        format!("{h}\""),
        format!("\"{h}\" x"),
        format!("\"{h}\"\"\""),
        format!("\u{feff}\"{h}\""),
        format!("\u{a0}\"{h}\""),
        "\"".to_string(),
        "\"\\u0000\"".to_string(),
        "1".to_string(),
    ] {
        assert_eq!(
            digest_of(settings.as_bytes()),
            Err(NOT_A_DIGEST),
            "{settings:?}"
        );
    }
    let mut not_utf8 = format!("\"{h}\"").into_bytes();
    not_utf8[1] = 0xff;
    assert_eq!(digest_of(&not_utf8), Err(NOT_A_DIGEST));
}

/// The hand decoder agrees with a real JSON parser followed by the whitespace trim: every document
/// it admits parses to a string whose trimmed text is the digest, and every document whose parsed,
/// trimmed text is a digest is admitted.
#[test]
fn the_settings_decoder_agrees_with_a_json_parser() {
    let h = hash("secret");
    let (head, tail) = h.split_at(32);
    let parsed = |settings: &[u8]| -> Option<String> {
        let text: String = serde_json::from_slice(settings).ok()?;
        let digest = text.trim();
        (digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| digest.to_ascii_lowercase())
    };
    let mut documents = Vec::new();
    for inner in [
        "",
        " ",
        "\\t",
        "\\n",
        "\\r",
        "\\f",
        "\\b",
        "\\/",
        "\\\\",
        "\\\"",
        "\\u0020",
        "\\u0041",
        "\\u0067",
        "\\u00A0",
        "\\u3000",
        "\\uD800",
        "\\uD83D\\uDE00",
        "\u{3000}",
        "\u{1}",
        "\u{7f}",
        "\\x",
    ] {
        documents.push(format!("\"{head}{inner}{tail}\""));
        documents.push(format!("\"{inner}{h}{inner}\""));
        documents.push(format!(" \"{inner}{h}\" "));
    }
    for settings in documents {
        let ours = digest_of(settings.as_bytes()).ok();
        assert_eq!(
            ours.as_deref().map(String::as_str),
            parsed(settings.as_bytes()).as_deref(),
            "{settings:?}"
        );
    }
}

mod reentrant_refresh_subscriber {
    use super::*;
    use std::cell::RefCell;
    use std::sync::Arc;

    use busbar_contract::abi::auth::{self, IdentifyOut, NamedValue, VerifyIn};
    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, BLOB_OCTETS};
    use busbar_contract::abi::mechanism::call::{InHead, OutHead};
    use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
    use busbar_plugin_loader::dispatch::kinds::auth::Auth;
    use busbar_plugin_loader::dispatch::{
        in_head, load_linked, out_head, Bind, DispatchConfig, Dispatcher, Frame, LinkedRow,
    };

    thread_local! {
        static OBSERVED: RefCell<Vec<bool>> = const { RefCell::new(Vec::new()) };
    }

    struct RefreshOnEvent(Arc<AdminTokens>);

    impl tracing::Subscriber for RefreshOnEvent {
        fn register_callsite(
            &self,
            _: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, _: &tracing::Event<'_>) {
            let unlocked = self.0.configured_hash.try_write().is_ok();
            OBSERVED.with(|seen| seen.borrow_mut().push(unlocked));
            if unlocked {
                let settings = format!("\"{}\"", hash("rotated-token"));
                assert_eq!(self.0.reload(settings.as_bytes(), &[]), Ok(0));
                assert_eq!(self.0.digest().as_str(), hash("rotated-token"));
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    struct Observed(Arc<AdminTokens>);
    impl VerifyPlugin for Observed {
        fn open_refusing(settings: &[u8], secrets: &[&[u8]]) -> Result<Self, Refusal> {
            AdminTokens::open_refusing(settings, secrets).map(|plugin| Self(Arc::new(plugin)))
        }
        fn reload(&self, settings: &[u8], secrets: &[&[u8]]) -> Result<u64, Refusal> {
            self.0.reload(settings, secrets)
        }
        fn verify(&self, request: &VerifyView<'_>) -> Answer {
            tracing::subscriber::with_default(RefreshOnEvent(self.0.clone()), || {
                self.0.verify(request)
            })
        }
    }

    mod fixture {
        busbar_contract::auth_verify_door!(super::Observed, crate::STATEMENT);
    }

    #[test]
    fn carrier_and_mismatch_logging_allow_reentrant_digest_rotation() {
        for (value, header, expected) in [
            (
                &b"Bearer"[..],
                Some(&b"initial-token"[..]),
                auth::VERDICT_IDENTITY,
            ),
            (&b"Bearer wrong-token"[..], None, auth::VERDICT_REJECT),
        ] {
            OBSERVED.with(|seen| seen.borrow_mut().clear());
            let dispatcher = Dispatcher::new(DispatchConfig::default());
            let bind = Bind {
                instance: "admin-reentrant-refresh".into(),
                max_inflight_cap: 64,
                sink: Arc::new(busbar_plugin_loader::dispatch::NoSink),
                dispatcher: dispatcher.adopter(),
                conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
            };
            let plugin = load_linked::<Auth>(&LinkedRow::of(fixture::door).unwrap(), bind).unwrap();
            let settings = format!("\"{}\"", hash("initial-token"));
            let input = OpenIn {
                head: in_head(),
                host: std::ptr::null(),
                settings: Blob {
                    ptr: settings.as_ptr(),
                    len: settings.len(),
                    fmt: busbar_contract::abi::mechanism::call::BLOB_JSON,
                    flags: 0,
                },
                secrets: std::ptr::null(),
                secrets_len: 0,
                generation: 1,
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            };
            let output = OpenOut {
                head: out_head(),
                instance: std::ptr::null_mut(),
                err_len: 0,
            };
            assert_eq!(
                plugin
                    .call(life::OPEN, &mut Frame::new(input, output))
                    .outcome,
                Outcome::Ready
            );
            let mut lines = vec![NamedValue {
                name: AbiStr {
                    ptr: b"authorization".as_ptr(),
                    len: b"authorization".len(),
                },
                value: Blob {
                    ptr: value.as_ptr(),
                    len: value.len(),
                    fmt: BLOB_OCTETS,
                    flags: 0,
                },
            }];
            if let Some(value) = header {
                lines.push(NamedValue {
                    name: AbiStr {
                        ptr: b"x-admin-token".as_ptr(),
                        len: b"x-admin-token".len(),
                    },
                    value: Blob {
                        ptr: value.as_ptr(),
                        len: value.len(),
                        fmt: BLOB_OCTETS,
                        flags: 0,
                    },
                });
            }
            let mut bytes = [0u8; 256];
            let mut strips = [auth::StripName {
                name: busbar_contract::abi::mechanism::call::Span::ZERO,
                place: 0,
                _reserved: 0,
            }; 2];
            let absent = Blob {
                ptr: std::ptr::null(),
                len: 0,
                fmt: 0,
                flags: 0,
            };
            let empty = AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            };
            let zero = busbar_contract::abi::mechanism::call::Span::ZERO;
            let mut frame = Frame::new(
                VerifyIn {
                    head: in_head(),
                    credential: absent,
                    lines: std::ptr::null(),
                    lines_len: 0,
                    request: auth::RequestFacts {
                        method: empty,
                        authority: empty,
                        canonical_path: empty,
                        query: empty,
                        timestamp: 0,
                    },
                    out_buf: auth::IdentityBuf {
                        buf: std::ptr::null_mut(),
                        buf_cap: 0,
                        groups: std::ptr::null_mut(),
                        groups_cap: 0,
                        _reserved: 0,
                    },
                    point: 0,
                    _reserved: 0,
                    conn: 0,
                    unit: 0,
                    peer: absent,
                    body: absent,
                    strip: std::ptr::null_mut(),
                    strip_cap: 0,
                    _reserved2: 0,
                },
                IdentifyOut {
                    head: out_head(),
                    verdict: 0,
                    needed_groups: 0,
                    needed_bytes: 0,
                    identity: auth::IdentityOut {
                        subject: zero,
                        key_id: zero,
                        key_name: zero,
                        user: zero,
                        provider: zero,
                        name: zero,
                        claims: zero,
                        claims_fmt: 0,
                        flags: 0,
                        ttl_secs: 0,
                        groups_len: 0,
                        _reserved: 0,
                        replay_key: zero,
                        replay_ttl_secs: 0,
                        credential: zero,
                    },
                    decision: 0,
                    strip_len: 0,
                    needed_strip: 0,
                    _reserved: 0,
                },
            );
            frame.input.lines = lines.as_ptr();
            frame.input.lines_len = lines.len();
            frame.input.point = auth::POINT_HEAD;
            frame.input.out_buf.buf = bytes.as_mut_ptr();
            frame.input.out_buf.buf_cap = bytes.len();
            frame.input.strip = strips.as_mut_ptr();
            frame.input.strip_cap = strips.len() as u32;
            let called = plugin.call(auth::slot::VERIFY, &mut frame);
            assert_eq!(
                plugin
                    .call(
                        life::CLOSE,
                        &mut Frame::<InHead, OutHead>::new(in_head(), out_head())
                    )
                    .outcome,
                Outcome::Ready
            );
            assert_eq!(called.outcome, Outcome::Ready, "{called:?}");
            assert_eq!(frame.out.verdict, expected);
            assert_eq!(
                OBSERVED.with(|seen| seen.borrow().clone()),
                [true],
                "the subscriber must rotate the digest without a live read guard"
            );
        }
    }
}

#[test]
fn a_padded_admin_header_is_compared_verbatim_and_rejected() {
    let configured = hash("secret");
    for value in [" secret", "secret ", "\tsecret\t"] {
        assert_eq!(header_line(value.as_bytes()), Some(value));
        assert_eq!(
            fold(&configured, None, header_line(value.as_bytes())),
            Verdict::Reject,
            "{value:?}"
        );
    }
}

// Standard tracing formatting into an in-memory writer; the assertions below inspect product logs.
#[derive(Clone, Default)]
struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for LogCapture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}
impl LogCapture {
    fn capturing_debug() -> Self {
        Self::default()
    }
    fn messages(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
    fn count(&self, text: &str) -> usize {
        self.messages()
            .iter()
            .filter(|line| line.contains(text))
            .count()
    }
    fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
        tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(self.clone())
            .finish()
    }
}

/// Every presented credential that does not hash-match the configured token is rejected, on
/// either carrier or both, whatever its shape (1.5.5 ended every mismatch in `Reject`, terminal in
/// the admin chain: a wrong JWS-shaped token is not passed on to the next `admin_auth:` module).
#[test]
fn non_matching_credentials_of_any_shape_never_identify() {
    let h = hash("the-real-admin-token");
    for cred in [
        "",
        "\0\x01\x02\x7f-random-bytes-ish",
        "a.b",
        "a.b.c.d",
        "aaa.bbb.ccc",
        "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvciJ9.c2ln",
        "not-a-jwt-at-all-just-plain-text",
        "not base64!!! ####",
        "eyJhbGciOiJub25lIn0..",
        "the-real-admin-token-but-longer",
        "the-real-admin-toke",
        "the-real-admin-tokfn",
    ] {
        for (bearer, header) in [
            (Some(cred), None),
            (None, Some(cred)),
            (Some(cred), Some(cred)),
        ] {
            assert_eq!(
                fold(&h, bearer, header),
                Verdict::Reject,
                "a non-matching presented credential must stop the chain: {cred:?}"
            );
        }
    }
    let h = hash("secret");
    assert_eq!(fold(&h, Some("wrong"), Some("a.b.c")), Verdict::Reject);
    assert_eq!(fold(&h, Some("a.b.c"), Some("wrong")), Verdict::Reject);
}

/// A Bearer whose value is not header text (`to_str` fails) presents nothing, as 1.5.5 read it.
#[test]
fn a_bearer_that_is_not_header_text_is_absent_as_in_1_5_5() {
    for value in [
        "Bearer t\u{f6}k\u{e9}n".as_bytes(),
        b"Bearer tok\x01en",
        b"Bearer tok\x7fen",
    ] {
        assert_eq!(bearer_line(value), None, "{value:?} presents no Bearer");
    }
    assert_eq!(bearer_line(b"Bearer tok\ten"), Some("tok\ten"));
    assert_eq!(bearer_line(b"bearer the-token"), Some("the-token"));
}
