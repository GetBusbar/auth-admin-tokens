// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Verifies Bearer authorization headers and credential stripping through the loaded admin-token door.

use std::sync::Arc;
use std::time::Duration;

use busbar_auth_admin_tokens::{
    authenticate_admin_tokens, ADMIN_TOKENS_PRINCIPAL_ID, ADMIN_TOKEN_HEADER,
};
use busbar_contract::abi::auth::AuthPoint;
use busbar_contract::abi::sdk::auth_door::Verdict;
use busbar_contract::auth_calls::{AuthCalls, Verified, VerifyAnswer, VerifyRequest};
use busbar_contract::sha256_hex;
use busbar_plugin_loader::auth_axis::AuthRows;
use busbar_plugin_loader::dispatch::{Budgets, DispatchConfig, Dispatcher};
use busbar_plugin_loader::sign::Manifest;
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};

/// The operator's token; the plugin is opened over its SHA-256 digest.
const TOKEN: &str = "the-operator-token";

/// The line a Bearer arrives on, spelled here so this file names nothing the change added.
const AUTHORIZATION: &str = "authorization";

/// The linked door's statement: a first-party `kind: auth` plugin on the auth kind's memory ABI.
fn statement() -> Manifest {
    Manifest {
        name: "busbar-auth-admin-tokens".into(),
        alias: "admin-tokens".into(),
        kind: "auth".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
        abi_version: busbar_contract::abi::auth::ABI_VERSION,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),

        statement: None,
        former_names: Vec::new(),
    }
}

/// The linked door, opened over the token's digest through the loader's auth rows.
fn opened() -> Arc<dyn AuthCalls> {
    let registry = PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(
            statement(),
            busbar_auth_admin_tokens::door::door,
        )])
        .expect("the linked door admits the plugin");
    let dispatcher = Dispatcher::new(DispatchConfig {
        workers: 2,
        budgets: Budgets::default(),
        watchdog_period: Duration::from_millis(20),
        ..Default::default()
    });

    assert!(dispatcher.lend_seal(busbar_contract::plugin::TestKernelSeal));
    let dispatcher = Arc::new(dispatcher);
    let digest = sha256_hex(TOKEN.as_bytes());
    AuthRows::new(Arc::new(registry), dispatcher)
        .open("admin-tokens", "admin-tokens", &serde_json::json!(digest))
        .expect("the plugin opens over a digest")
}

/// A request at the Head point carrying `lines` as presented.
fn request(lines: &[(&str, &str)]) -> VerifyRequest {
    let mut request = VerifyRequest::default();
    request.point = AuthPoint::Head;
    request.lines = lines
        .iter()
        .map(|(n, v)| ((*n).to_string(), v.as_bytes().to_vec().into()))
        .collect();
    request.method = "GET".into();
    request.authority = "node.example".into();
    request.path = "/admin/v1/keys".into();
    request
}

/// An answer as `verdict [strips]`.
fn spelled(a: &VerifyAnswer) -> String {
    let verdict = match &a.verified {
        Verified::Identity(id) => format!("Identity({})", id.subject),
        other => format!("{other:?}"),
    };
    let mut strips: Vec<&str> = a.strips.iter().map(|s| s.name.as_ref()).collect();
    strips.sort_unstable();
    format!("{verdict} [{}]", strips.join(", "))
}

/// The Bearer is read off the `authorization` line: alone it identifies (in any scheme case), a
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_bearer_on_the_authorization_line_is_judged() {
    let door = opened();
    let operator = format!("Identity({ADMIN_TOKENS_PRINCIPAL_ID})");
    let both = format!("[{AUTHORIZATION}, {ADMIN_TOKEN_HEADER}]");
    let bearer = format!("Bearer {TOKEN}");
    let cased = format!("bEaReR {TOKEN}");
    let spaced = format!("Bearer  {TOKEN}");
    let cased_spaced = format!("bEaReR    {TOKEN}");
    let cases = [
        (
            vec![(AUTHORIZATION, bearer.as_str())],
            format!("{operator} {both}"),
        ),
        (
            vec![(AUTHORIZATION, cased.as_str())],
            format!("{operator} {both}"),
        ),
        (
            vec![(AUTHORIZATION, spaced.as_str())],
            format!("{operator} {both}"),
        ),
        (
            vec![(AUTHORIZATION, cased_spaced.as_str())],
            format!("{operator} {both}"),
        ),
        (
            vec![(AUTHORIZATION, "Bearer  not-the-token")],
            format!("Reject {both}"),
        ),
        (
            vec![(AUTHORIZATION, "Bearer not-the-token")],
            format!("Reject {both}"),
        ),
        (
            vec![(AUTHORIZATION, "Basic not-a-bearer")],
            format!("Pass {both}"),
        ),
        (
            vec![(ADMIN_TOKEN_HEADER, TOKEN)],
            format!("{operator} {both}"),
        ),
        (vec![(ADMIN_TOKEN_HEADER, "")], format!("Pass {both}")),
        (vec![(AUTHORIZATION, "Bearer ")], format!("Pass {both}")),
        (vec![(AUTHORIZATION, "Bearer    ")], format!("Pass {both}")),
    ];
    for (lines, want) in cases {
        let now = door
            .verify_now(&request(&lines))
            .expect("admin-tokens answers on the spot");
        assert_eq!(spelled(&now), want, "on the spot: {lines:?}");
        let awaited = Box::into_pin(door.verify(request(&lines))).await;
        assert_eq!(spelled(&awaited), want, "awaited: {lines:?}");
    }
}

/// The door's verdict for a Bearer on its line is the fold's own for that Bearer: the module's
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_door_judges_the_line_as_the_fold_judges_the_bearer() {
    let door = opened();
    let digest = sha256_hex(TOKEN.as_bytes());
    for token in [TOKEN, "not-the-token", "aaa.bbb.ccc"] {
        let line = format!("Bearer {token}");
        let got = door
            .verify_now(&request(&[(AUTHORIZATION, line.as_str())]))
            .expect("admin-tokens answers on the spot");
        let want = match authenticate_admin_tokens(Some(&digest), Some(token), None) {
            Verdict::Identity(id) => format!("Identity({})", id.subject),
            Verdict::Reject | Verdict::RejectBecause(_) => "Reject".into(),
            Verdict::Pass => "Pass".into(),
        };
        assert!(
            spelled(&got).starts_with(&format!("{want} ")),
            "{token}: {} is not the fold's {want}",
            spelled(&got)
        );
    }
}

/// Every presented copy of a carrier line is judged through the door: a carrier repeated with one
/// wrong copy is a presented wrong credential (`Reject`), whichever copy comes first, and a Bearer
/// behind another scheme's line is still read. Both names are stripped either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_copy_of_a_repeated_carrier_line_is_judged() {
    let door = opened();
    let operator = format!("Identity({ADMIN_TOKENS_PRINCIPAL_ID})");
    let both = format!("[{AUTHORIZATION}, {ADMIN_TOKEN_HEADER}]");
    let bearer = format!("Bearer {TOKEN}");
    let cases = [
        (
            vec![
                (ADMIN_TOKEN_HEADER, TOKEN),
                (ADMIN_TOKEN_HEADER, "not-the-token"),
            ],
            format!("Reject {both}"),
        ),
        (
            vec![
                (ADMIN_TOKEN_HEADER, "not-the-token"),
                (ADMIN_TOKEN_HEADER, TOKEN),
            ],
            format!("Reject {both}"),
        ),
        (
            vec![
                (AUTHORIZATION, "Basic x"),
                (AUTHORIZATION, "Bearer not-the-token"),
            ],
            format!("Reject {both}"),
        ),
        (
            vec![(AUTHORIZATION, "Basic x"), (AUTHORIZATION, bearer.as_str())],
            format!("{operator} {both}"),
        ),
        (
            vec![(ADMIN_TOKEN_HEADER, TOKEN), (ADMIN_TOKEN_HEADER, TOKEN)],
            format!("{operator} {both}"),
        ),
        (
            vec![
                (AUTHORIZATION, bearer.as_str()),
                (ADMIN_TOKEN_HEADER, TOKEN),
                (ADMIN_TOKEN_HEADER, "not-the-token"),
            ],
            format!("{operator} {both}"),
        ),
    ];
    for (lines, want) in cases {
        let now = door
            .verify_now(&request(&lines))
            .expect("admin-tokens answers on the spot");
        assert_eq!(spelled(&now), want, "on the spot: {lines:?}");
        let awaited = Box::into_pin(door.verify(request(&lines))).await;
        assert_eq!(spelled(&awaited), want, "awaited: {lines:?}");
    }
}

/// Both carriers are read verbatim through the door, as 1.5.5 read them: the Bearer is split on
/// its first single space with the rest kept as the token, and an `X-Admin-Token` value is the
/// token as sent. A padded right token is a presented wrong credential (`Reject`); a leading space
/// leaves the Bearer no scheme (a silent absence, `Pass`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn padded_carrier_values_are_read_verbatim_as_in_1_5_5() {
    let door = opened();
    let both = format!("[{AUTHORIZATION}, {ADMIN_TOKEN_HEADER}]");
    let spaced = format!("Bearer  {TOKEN}");
    let trailing = format!("Bearer {TOKEN}\t");
    let leading = format!(" Bearer {TOKEN}");
    let header = format!("\t{TOKEN} ");
    let cases = [
        (
            vec![(AUTHORIZATION, spaced.as_str())],
            format!("Reject {both}"),
        ),
        (
            vec![(AUTHORIZATION, trailing.as_str())],
            format!("Reject {both}"),
        ),
        (
            vec![(AUTHORIZATION, leading.as_str())],
            format!("Pass {both}"),
        ),
        (vec![(AUTHORIZATION, "Bearer   ")], format!("Reject {both}")),
        (
            vec![(ADMIN_TOKEN_HEADER, header.as_str())],
            format!("Reject {both}"),
        ),
        (vec![(ADMIN_TOKEN_HEADER, " \t ")], format!("Reject {both}")),
    ];
    for (lines, want) in cases {
        let now = door
            .verify_now(&request(&lines))
            .expect("admin-tokens answers on the spot");
        assert_eq!(spelled(&now), want, "on the spot: {lines:?}");
    }
}
