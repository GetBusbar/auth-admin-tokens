// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Mutation-hardening tests for `busbar-auth-admin-tokens`.

use busbar_auth_admin_tokens::{authenticate_admin_tokens, ADMIN_TOKENS_PRINCIPAL_ID};
use busbar_contract::abi::sdk::auth_door::Verdict;
use busbar_contract::sha256_hex;

fn hash(s: &str) -> String {
    sha256_hex(s.as_bytes())
}

/// Closes the surviving `|` → `^` mutant: when BOTH carriers match the configured token, OR and XOR
#[test]
fn both_carriers_correct_still_identifies() {
    let h = hash("secret");
    match authenticate_admin_tokens(Some(&h), Some("secret"), Some("secret")) {
        Verdict::Identity(p) => assert_eq!(p.subject, ADMIN_TOKENS_PRINCIPAL_ID),
        other => panic!("both carriers correct must Identify, got {other:?}"),
    }
}

/// Every presented credential that does not hash-match the configured token is rejected. Passing
#[test]
fn non_matching_credentials_of_any_shape_never_identify() {
    let h = hash("the-real-admin-token");
    let bad_candidates = [
        "",
        "\0\x01\x02\x7f-random-bytes-ish",
        "a.b",
        "a.b.c.d",
        "not-a-jwt-at-all-just-plain-text",
        "not base64!!! ####",
        "eyJhbGciOiJub25lIn0..",
        "the-real-admin-token-but-longer",
        "the-real-admin-toke",
        "the-real-admin-tokfn",
    ];
    for cred in bad_candidates {
        for (bearer, header) in [
            (Some(cred), None),
            (None, Some(cred)),
            (Some(cred), Some(cred)),
        ] {
            assert_eq!(
                authenticate_admin_tokens(Some(&h), bearer, header),
                Verdict::Reject,
                "a non-matching presented credential must stop the chain: {cred:?}"
            );
        }
    }
}

/// Wrong credentials on both carriers `Reject`, whatever either one's shape: a dotted token is not
/// special (the module parses no JWS), so neither carrier's shape turns the verdict into a `Pass`.
#[test]
fn wrong_credentials_on_both_carriers_reject_whatever_their_shape() {
    let h = hash("secret");
    assert_eq!(
        authenticate_admin_tokens(Some(&h), Some("wrong"), Some("a.b.c")),
        Verdict::Reject,
        "a wrong bearer beside a wrong dotted header must Reject"
    );
    assert_eq!(
        authenticate_admin_tokens(Some(&h), Some("a.b.c"), Some("wrong")),
        Verdict::Reject,
        "a wrong header beside a wrong dotted bearer must Reject"
    );
}
