// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The signed schema and the real lifecycle validator agree on representative settings.

use super::*;
use serde_json::{json, Value};

fn check(cases: &[(Value, bool)]) {
    let schema: Value = serde_json::from_slice(SETTINGS_SCHEMA).expect("schema JSON");
    let validator = jsonschema::validator_for(&schema).expect("valid settings schema");
    assert_eq!(STATEMENT.settings_schema.ptr, SETTINGS_SCHEMA.as_ptr());
    assert_eq!(STATEMENT.settings_schema.len, SETTINGS_SCHEMA.len());
    assert_eq!(
        STATEMENT.settings_schema.fmt,
        busbar_contract::abi::mechanism::call::BLOB_JSON
    );
    for (settings, accepted) in cases {
        let bytes = serde_json::to_vec(settings).expect("settings JSON");
        assert_eq!(
            validator.is_valid(settings),
            *accepted,
            "schema: {settings}"
        );
        assert_eq!(
            <AdminTokens as VerifyPlugin>::validate(&bytes).is_ok(),
            *accepted,
            "lifecycle: {settings}"
        );
    }
}

#[test]
fn settings_schema_matches_digest_lifecycle() {
    let digest = "a".repeat(64);
    check(&[
        (json!(digest), true),
        (json!("A".repeat(64)), true),
        (json!(format!("\u{2003}\t{digest}\r\n")), true),
        (json!(""), false),
        (json!("a".repeat(63)), false),
        (json!("g".repeat(64)), false),
        (json!(EMPTY_TOKEN_SHA256), false),
        (
            json!(format!(" {} ", EMPTY_TOKEN_SHA256.to_uppercase())),
            false,
        ),
        (json!({"digest": digest}), false),
        (Value::Null, false),
    ]);
}
