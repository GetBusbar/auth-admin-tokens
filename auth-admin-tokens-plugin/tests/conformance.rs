// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE ADMIN-AUTH MODULE, BOTH DOORS, ONE ROW** — the `admin-tokens` plugin's linked + dropped-in

use std::sync::Arc;
use std::time::Duration;

const ADMIN_TOKEN_HEADER: &str = "x-admin-token";
const AUTHORIZATION_HEADER: &str = "authorization";
use busbar_contract::abi::auth::AuthPoint;
use busbar_contract::auth_calls::{Verified, VerifyAnswer, VerifyRequest};
use busbar_contract::sha256_hex;
use busbar_plugin_loader::auth_axis::AuthRows;
use busbar_plugin_loader::dispatch::{Budgets, DispatchConfig, Dispatcher};
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};

/// The release key the first-party dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[31u8; 32])
}

/// The version both arms state.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The operator's token. The plugin is configured with its SHA-256 digest, never the token.
const TOKEN: &str = "the-operator-token";

/// An identity continues the chain.
const IDENTIFIES: &str = "Identity(admin) Continue";
/// A presented wrong credential stops it.
const REJECTS: &str = "Reject Stop";
/// No credential presented continues it.
const PASSES: &str = "Pass Continue";

/// The carriers each door judges, as (Bearer, `X-Admin-Token`, verdict): the accepted token on
/// either and both, wrong or padded tokens, a dotted token, and no credential at all.
const CASES: [(Option<&str>, Option<&str>, &str); 13] = [
    (Some(TOKEN), None, IDENTIFIES),
    (None, Some(TOKEN), IDENTIFIES),
    (Some(TOKEN), Some(TOKEN), IDENTIFIES),
    (Some("not-the-token"), Some(TOKEN), IDENTIFIES),
    (Some(TOKEN), Some("not-the-token"), IDENTIFIES),
    (None, Some(" the-operator-token"), REJECTS),
    (None, Some("the-operator-token "), REJECTS),
    (None, Some("\tthe-operator-token\t"), REJECTS),
    (Some("not-the-token"), None, REJECTS),
    (None, Some("not-the-token"), REJECTS),
    (Some("aaa.bbb.ccc"), None, REJECTS),
    (Some("aaa.bbb.ccc"), Some("not-the-token"), REJECTS),
    (None, None, PASSES),
];

/// The qualification lane supplies the exact freshly built actual product image.
fn cdylib() -> Vec<u8> {
    let path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
            .expect("build the fresh actual admin-tokens cdylib and set BUSBAR_PLUGIN_CDYLIB"),
    );
    assert!(
        path.is_absolute() && path.is_file(),
        "BUSBAR_PLUGIN_CDYLIB must name the fresh actual product image"
    );
    std::fs::read(path).expect("read actual product cdylib")
}

/// The door's own Statement rendering, as the lower-case hex a signed manifest carries (the
/// manifest's `statement` field).
fn rendering_hex() -> String {
    let rendering = busbar_plugin_loader::dispatch::LinkedRow::of(busbar_auth_admin_tokens::door)
        .expect("the door states itself")
        .statement;
    rendering.iter().map(|b| format!("{b:02x}")).collect()
}

/// The statement both doors make: a first-party `kind: auth` plugin on the auth kind's memory ABI.
fn statement() -> Manifest {
    Manifest {
        name: "busbar-auth-admin-tokens".into(),
        alias: "admin-tokens".into(),
        kind: "auth".into(),
        version: VERSION.into(),
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
        statement: Some(rendering_hex()),
        former_names: Vec::new(),
    }
}

/// THE LINKED DOOR: the logic crate's `door::door` through `PluginRegistry::link`.
fn linked() -> PluginRegistry {
    PluginRegistry::empty()
        .link(vec![LinkedPlugin::door(
            statement(),
            busbar_auth_admin_tokens::door,
        )])
        .expect("the linked door admits the plugin")
}

/// THE DROPPED-IN DOOR: `lib` signed by `signer` into a fresh `plugins/` directory, scanned under a
/// trust policy that admits it (first-party under the release key, else as an allowed third party).
fn dropped(tag: &str, lib: &[u8], signer: &SigningKey) -> PluginRegistry {
    let dir = std::env::temp_dir().join(format!(
        "auth-admin-tokens-conf-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let third_party = signer.verifying_key() != release().verifying_key();
    let mut manifest = statement();
    if third_party {
        manifest.publisher = "a-third-party".into();
    }
    let publisher = (manifest.publisher.clone(), signer.verifying_key());
    let signed = sign(signer, manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libauth.so", lib).unwrap();
    std::fs::write(dir.join("auth.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release().verifying_key()),
        first_party_keys: Vec::new(),
        revoked: Default::default(),
        release_keys_floor: 0,
        release_clock: None,
        release_enforce_expiry: false,
        binary_version: VERSION.into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: std::iter::once(publisher).filter(|_| third_party).collect(),
        allow_unsigned: false,
        allow_third_party: third_party,
        min_versions: Default::default(),
    };
    let registry =
        busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the signed plugin scans");
    let _ = std::fs::remove_dir_all(&dir);
    registry
}

/// The process's dispatcher, as the composition root builds one: lent a seal, so a verify reveals
/// the credential lines it lends the door.
fn dispatcher() -> Arc<Dispatcher> {
    let d = Dispatcher::new(
        DispatchConfig {
            workers: 2,
            budgets: Budgets::default(),
            watchdog_period: Duration::from_millis(20),
            ..Default::default()
        },
        busbar_contract::services::test_caller_binding(),
    );
    assert!(d.lend_seal(busbar_contract::plugin::TestKernelSeal));
    Arc::new(d)
}

/// One carrier case as the host hands it to `verify` at the Head point: the Bearer on the
/// `authorization` line as `Bearer <token>`, the header verbatim on `x-admin-token`.
fn request(bearer: Option<&str>, header: Option<&str>) -> VerifyRequest {
    let line = |name: &str, value: String| (name.to_string(), value.into_bytes().into());
    let lines = bearer
        .map(|b| line(AUTHORIZATION_HEADER, format!("Bearer {b}")))
        .into_iter()
        .chain(header.map(|h| line(ADMIN_TOKEN_HEADER, h.to_string())))
        .collect();
    let mut request = VerifyRequest::default();
    request.point = AuthPoint::Head;
    request.lines = lines;
    request.method = "GET".into();
    request.authority = "node.example".into();
    request.path = "/admin/v1/keys".into();
    request
}

/// The lines every answer names for the transport to strip, as the transcript spells them.
const STRIPS: &str = "[authorization, x-admin-token]";

/// An answer as the transcript spells it: the verdict, the decision, the lines to strip.
fn spelled(a: &VerifyAnswer) -> String {
    let verdict = match &a.verified {
        Verified::Identity(id) => format!("Identity({})", id.subject),
        other => format!("{other:?}"),
    };
    let strips: Vec<&str> = a.strips.iter().map(|s| s.name.as_ref()).collect();
    format!("{verdict} {:?} [{}]", a.decision, strips.join(", "))
}

/// What one door does, as one comparable transcript: the row's statement (every manifest field but
/// its digest and signature), its facts, every case's answer, and the refusal of a raw token.
async fn transcript(registry: PluginRegistry, digest: &str) -> serde_json::Value {
    let registry = Arc::new(registry);
    let p = registry
        .resolve("admin-tokens")
        .expect("the alias resolves");
    let stated = Manifest {
        sha256: String::new(),
        signature: String::new(),
        ..p.manifest.clone()
    };
    let rows = AuthRows::new(registry.clone(), dispatcher());
    let opened = rows
        .open(
            "admin-tokens",
            "admin-tokens",
            &serde_json::json!(digest).into(),
        )
        .expect("the plugin opens over a digest");
    let mut now = Vec::new();
    let mut submitted = Vec::new();
    for (bearer, header, _) in CASES {
        let v = opened
            .verify_now(&request(bearer, header))
            .expect("admin-tokens answers on the spot");
        now.push(spelled(&v));
        let v = Box::into_pin(opened.verify(request(bearer, header))).await;
        submitted.push(spelled(&v));
    }
    let refused = rows
        .open(
            "admin-tokens",
            "admin-tokens",
            &serde_json::json!("the-raw-token").into(),
        )
        .err();
    serde_json::json!({
        "row": stated,
        "first_party": p.first_party(),
        "name": opened.name(),
        "facts": opened.facts(),
        "operator": rows.operator(),
        "now": now,
        "submitted": submitted,
        "refused": refused,
    })
}

/// The plugin registers ONE row and judges as ONE plugin through either door, on the spot and
/// awaited alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_linked_and_the_dropped_in_admin_tokens_plugin_are_one_plugin() {
    let digest = sha256_hex(TOKEN.as_bytes());
    let lib = cdylib();

    let linked = transcript(linked(), &digest).await;
    let dropped_in = transcript(dropped("first-party", &lib, &release()), &digest).await;
    assert_eq!(linked, dropped_in, "the two doors are not one plugin");

    let want: Vec<String> = CASES
        .iter()
        .map(|(_, _, verdict)| format!("{verdict} {STRIPS}"))
        .collect();
    assert_eq!(linked["now"], serde_json::json!(want));
    assert_eq!(linked["submitted"], serde_json::json!(want));
    let verdicts = linked["now"].to_string();
    for verdict in ["Identity(admin)", "Reject", "Pass"] {
        assert!(verdicts.contains(verdict), "no {verdict} among {verdicts}");
    }
    assert_eq!(linked["name"], "admin-tokens");
    assert_eq!(
        linked["facts"],
        busbar_contract::abi::auth::FACT_OPERATOR,
        "the operator credential, and a rotatable compare is never cached"
    );
    assert_eq!(
        linked["operator"],
        serde_json::json!(["admin-tokens", "admin"]),
        "the host finds the operator credential's row by its Statement"
    );
    assert!(
        linked["refused"].is_string(),
        "a raw token is refused as settings: {}",
        linked["refused"]
    );
    assert!(
        !linked["refused"].to_string().contains("the-raw-token"),
        "the refusal never echoes the settings"
    );

    let third = SigningKey::from_bytes(&[7u8; 32]);
    let foreign = transcript(dropped("third-party", &lib, &third), &digest).await;
    assert_ne!(
        foreign, linked,
        "a third-party row must not read as the first-party one"
    );
    assert_eq!(foreign["first_party"], false);

    let rotated = transcript(
        dropped("rotated", &lib, &release()),
        &sha256_hex(b"a-rotated-token"),
    )
    .await;
    assert_eq!(rotated["row"], linked["row"], "one row either way");
    assert_ne!(
        rotated["now"], linked["now"],
        "a door judging another token must not compare equal"
    );
    assert!(!rotated["now"].to_string().contains("Identity"));
}

/// Every published input is an explicit product assertion on both independently loaded doors.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn published_auth_cases_match_through_both_real_doors() {
    let inputs: serde_json::Value = serde_json::from_str(include_str!("conformance.json")).unwrap();
    let lib = cdylib();
    for registry in [linked(), dropped("published-cases", &lib, &release())] {
        let rows = AuthRows::new(Arc::new(registry), dispatcher());
        let settings: serde_json::Value =
            serde_json::from_str(inputs["settings"].as_str().unwrap()).unwrap();
        let opened = rows
            .open("admin-tokens", "admin-tokens", &settings.into())
            .unwrap();
        let rotated_settings: serde_json::Value =
            serde_json::from_str(inputs["auth"]["rotated_settings"].as_str().unwrap()).unwrap();
        let rotated = rows
            .open("admin-tokens", "rotated-admin", &rotated_settings.into())
            .unwrap();
        for case in inputs["auth"]["cases"].as_array().unwrap() {
            let presented = || {
                let mut request = request(None, None);
                request.lines = case["lines"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.clone(),
                            value.as_str().unwrap().as_bytes().to_vec().into(),
                        )
                    })
                    .collect();
                request
            };
            let request = presented();
            let now = opened.verify_now(&request).expect("answers synchronously");
            let submitted = Box::into_pin(opened.verify(presented())).await;
            assert_eq!(spelled(&now), spelled(&submitted));
            let expected = case["verdict"].as_str().unwrap();
            let golden = match expected {
                "identity:admin" => "Identity(admin) Continue [authorization, x-admin-token]",
                "reject" => "Reject Stop [authorization, x-admin-token]",
                "pass" => "Pass Continue [authorization, x-admin-token]",
                other => panic!("unexpected verdict {other}"),
            };
            assert_eq!(spelled(&now), golden);
            assert_eq!(spelled(&submitted), golden);

            match expected {
                "identity:admin" => {
                    assert!(
                        matches!(&now.verified, Verified::Identity(id) if id.subject == "admin")
                    );
                    for answer in [
                        rotated.verify_now(&request).unwrap(),
                        Box::into_pin(rotated.verify(presented())).await,
                    ] {
                        assert!(!matches!(answer.verified, Verified::Identity(_)));
                    }
                }
                "reject" => assert!(matches!(now.verified, Verified::Reject)),
                "pass" => assert!(matches!(now.verified, Verified::Pass)),
                other => panic!("unexpected verdict {other}"),
            }
            for word in inputs["auth"]["never_echoed"].as_array().unwrap() {
                assert!(!spelled(&now).contains(word.as_str().unwrap()));
                assert!(!spelled(&submitted).contains(word.as_str().unwrap()));
            }
        }
    }
}

#[test]
fn the_declared_needs_are_the_statements() {
    let stated =
        busbar_plugin_loader::dispatch::rendering_of(busbar_auth_admin_tokens::door).unwrap();
    let facts = busbar_contract::abi::mechanism::rendering::read(&stated).unwrap();
    assert!(facts.needs.is_empty(), "admin tokens requires no connector");
    let declared: serde_json::Value =
        serde_json::from_str(include_str!("../../auth-admin-tokens/declares.json")).unwrap();
    assert!(declared
        .get("needs")
        .is_none_or(|needs| needs.as_array().is_some_and(Vec::is_empty)));
}

#[test]
fn the_suite_runs_in_the_profile_it_was_asked_to() {
    assert!(
        !(cfg!(debug_assertions) && std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some()),
        "BUSBAR_EXPECT_RELEASE is set: run conformance with --release"
    );
}
