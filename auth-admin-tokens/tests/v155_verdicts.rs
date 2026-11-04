// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin-token verdicts and carrier reading of published 1.5.5 (`crates/auth-admin-tokens` and

use busbar_auth_admin_tokens::{authenticate_admin_tokens, bearer_token};
use busbar_contract::abi::sdk::auth_door::Verdict;
use busbar_contract::sha256_hex;

/// 1.5.5 ended every mismatch in `Reject`, terminal in the admin chain: a wrong token shaped like
#[test]
fn a_wrong_jws_shaped_token_rejects_as_in_1_5_5() {
    let h = sha256_hex(b"secret");
    for jws in [
        "aaa.bbb.ccc",
        "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvciJ9.c2ln",
    ] {
        for (b, hd) in [(Some(jws), None), (None, Some(jws)), (Some(jws), Some(jws))] {
            assert_eq!(
                authenticate_admin_tokens(Some(&h), b, hd),
                Verdict::Reject,
                "a presented wrong credential is rejected whatever its shape ({b:?}, {hd:?})"
            );
        }
    }
}

/// A Bearer whose value is not header text (`to_str` fails) presents nothing, as 1.5.5 read it.
#[test]
fn a_bearer_that_is_not_header_text_is_absent_as_in_1_5_5() {
    for value in [
        "Bearer t\u{f6}k\u{e9}n".as_bytes(),
        b"Bearer tok\x01en",
        b"Bearer tok\x7fen",
    ] {
        assert_eq!(bearer_token(value), None, "{value:?} presents no Bearer");
    }
    assert_eq!(bearer_token(b"Bearer tok\ten"), Some("tok\ten"));
    assert_eq!(bearer_token(b"bearer the-token"), Some("the-token"));
}
