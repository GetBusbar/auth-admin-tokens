// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **A ROTATED ADMIN TOKEN IS PICKED UP BY `refresh`, WITHOUT A RE-OPEN** (CREDENTIAL-LOCKDOWN P1.5).

use std::mem::zeroed;
use std::sync::Arc;

use busbar_contract::abi::auth::{
    slot, IdentifyOut, IdentityBuf, NamedValue, RequestFacts, StripName, VerifyIn, POINT_HEAD,
    VERDICT_IDENTITY, VERDICT_PASS, VERDICT_REJECT,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, OutHead, Outcome, Span, BLOB_JSON, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, RefreshIn};
use busbar_contract::sha256_hex;
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of, Bind, Diagnostic, DispatchConfig,
    Dispatcher, Dropped, EnvelopeSink, Frame, LinkedRow, Metric, Plugin,
};

const OLD: &str = "the-operator-token";
const NEW: &str = "the-rotated-operator-token";

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn s(b: &str) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn blob(b: &[u8], fmt: u32) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags: 0,
    }
}

struct Quiet;

impl EnvelopeSink for Quiet {
    fn metric(&self, _: Metric<'_>) {}
    fn diag(&self, _: Diagnostic<'_>) {}
    fn dropped(&self, _: Dropped) {}
}

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("refresh-rotation"),
        max_inflight_cap: 64,
        sink: Arc::new(Quiet),
        dispatcher: d.adopter(),
        conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
    }
}

fn linked(d: &Dispatcher) -> Plugin<Auth> {
    let row = LinkedRow::of(busbar_auth_admin_tokens::door).expect("the door states itself");
    load_linked::<Auth>(&row, bind(d)).expect("the linked door loads")
}

fn dropped(d: &Dispatcher) -> Plugin<Auth> {
    let path = cdylib_path();
    let stated =
        rendering_of(busbar_auth_admin_tokens::door).expect("the door renders its Statement");
    load_dropped::<Auth>(&path, &stated, bind(d)).expect("the dropped door loads")
}

/// The settings document for `token`: its SHA-256 digest as a JSON string.
fn settings_of(token: &str) -> String {
    format!("\"{}\"", sha256_hex(token.as_bytes()))
}

// Each check is tied to this actual auth product, with exact zero/resume arms.
fn checked_call<
    I: busbar_plugin_loader::dispatch::InFrame,
    O: busbar_plugin_loader::dispatch::OutFrame,
>(
    p: &Plugin<Auth>,
    slot: u32,
    frame: &mut Frame<I, O>,
) -> busbar_plugin_loader::dispatch::Called {
    let expected = u64::from(p.is_open() || matches!(slot, life::OPEN | life::VALIDATE));
    let before = (p.test_invocations().0, p.test_invocations().1);
    let answer = p.call(slot, frame);
    let after = (p.test_invocations().0, p.test_invocations().1);
    assert_eq!(
        (after.0 - before.0, after.1 - before.1),
        (expected, 0),
        "auth slot {slot}"
    );
    answer
}

fn open(p: &Plugin<Auth>, settings: &str) -> Outcome {
    let mut o: Frame<OpenIn, OpenOut> = Frame::new(z(), z());
    o.input.head = in_head();
    o.out.head = out_head();
    o.input.generation = 1;
    o.input.settings = blob(settings.as_bytes(), BLOB_JSON);
    let answer = checked_call(p, life::OPEN, &mut o);
    assert_eq!(answer.lease, 0);
    assert!(answer.recall.is_none());
    if answer.outcome == Outcome::Ready {
        assert!(answer.error.is_none());
    }
    answer.outcome
}

fn refresh(p: &Plugin<Auth>, settings: &str, generation: u64) -> Outcome {
    let mut f: Frame<RefreshIn, OutHead> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out = out_head();
    f.input.generation = generation;
    f.input.settings = blob(settings.as_bytes(), BLOB_JSON);
    let answer = checked_call(p, life::REFRESH, &mut f);
    assert_eq!(answer.lease, 0);
    assert!(answer.recall.is_none());
    if answer.outcome == Outcome::Ready {
        assert!(answer.error.is_none());
    } else {
        let text = String::from_utf8(answer.error.clone().expect("a refused refresh says why"))
            .expect("the refusal is text");
        assert!(text.starts_with("settings: "), "{text}");
        assert!(!text.contains("the-raw-token"), "settings echoed: {text}");
    }
    answer.outcome
}

/// One `verify` at `Head` with `token` as the Bearer: `outcome verdict`.
fn bearer(p: &Plugin<Auth>, token: &str) -> String {
    let line = format!("Bearer {token}");
    let lines = [NamedValue {
        name: s("authorization"),
        value: blob(line.as_bytes(), BLOB_OCTETS),
    }];
    let mut buf = vec![0u8; 256];
    let mut groups = vec![Span { offset: 0, len: 0 }; 4];
    let mut strips = vec![
        StripName {
            name: Span { offset: 0, len: 0 },
            place: 0,
            _reserved: 0,
        };
        8
    ];
    let mut f: Frame<VerifyIn, IdentifyOut> = Frame::new(z(), z());
    f.input.head = in_head();
    f.out.head = out_head();
    f.input.lines = lines.as_ptr();
    f.input.lines_len = lines.len();
    f.input.point = POINT_HEAD;
    f.input.strip = strips.as_mut_ptr();
    f.input.strip_cap = strips.len() as u32;
    f.input.request = RequestFacts {
        method: s("GET"),
        authority: s("node.example"),
        canonical_path: s("/admin/v1/keys"),
        query: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        timestamp: 0,
    };
    f.input.out_buf = IdentityBuf {
        buf: buf.as_mut_ptr(),
        buf_cap: buf.len(),
        groups: groups.as_mut_ptr(),
        groups_cap: groups.len() as u32,
        _reserved: 0,
    };
    let c = checked_call(p, slot::VERIFY, &mut f);
    let verdict = match f.out.verdict {
        VERDICT_IDENTITY => "identity",
        VERDICT_REJECT => "reject",
        VERDICT_PASS => "pass",
        _ => "?",
    };
    format!("{:?} {verdict}", c.outcome)
}

/// The script, one line per call.
fn script(p: &Plugin<Auth>) -> Vec<String> {
    vec![
        format!("open {:?}", open(p, &settings_of(OLD))),
        format!("old {}", bearer(p, OLD)),
        format!("new {}", bearer(p, NEW)),
        // The admin cache flush: unchanged settings, nothing changes.
        format!("flush {:?}", refresh(p, &settings_of(OLD), 2)),
        format!("old after flush {}", bearer(p, OLD)),
        format!("new after flush {}", bearer(p, NEW)),
        // The rotation: the new digest, on the same instance.
        format!("rotate {:?}", refresh(p, &settings_of(NEW), 3)),
        format!("old after rotate {}", bearer(p, OLD)),
        format!("new after rotate {}", bearer(p, NEW)),
        // Settings that are not a digest: refused, and the instance keeps the digest it holds.
        format!("bad {:?}", refresh(p, "\"the-raw-token\"", 4)),
        format!("old after bad {}", bearer(p, OLD)),
        format!("new after bad {}", bearer(p, NEW)),
    ]
}

const EXPECTED: &[&str] = &[
    "open Ready",
    "old Ready identity",
    "new Ready reject",
    "flush Ready",
    "old after flush Ready identity",
    "new after flush Ready reject",
    "rotate Ready",
    "old after rotate Ready reject",
    "new after rotate Ready identity",
    "bad Failed",
    "old after bad Ready reject",
    "new after bad Ready identity",
];

#[test]
fn refresh_picks_up_a_rotated_digest_without_a_reopen() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    for p in [linked(&d), dropped(&d)] {
        assert_eq!(script(&p), EXPECTED);
        assert_eq!(p.test_invocations().0, 12);
        assert_eq!(p.test_invocations().1, 0);
    }
}

fn cdylib_path() -> std::path::PathBuf {
    let path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
            .expect("build the fresh actual admin-tokens cdylib and set BUSBAR_PLUGIN_CDYLIB"),
    );
    assert!(
        path.is_absolute() && path.is_file(),
        "BUSBAR_PLUGIN_CDYLIB must name the fresh actual product image"
    );
    path
}

/// The ABI lifecycle and short-buffer contract previously hidden inside the suite macro.
#[test]
fn lifecycle_and_short_identity_contract_through_both_real_doors() {
    use busbar_contract::abi::auth::{
        BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldsIn, FieldsOut, OpenOutboundIn,
        OpenOutboundOut, OutboundReadyIn, OutboundReadyOut,
    };
    use busbar_contract::abi::mechanism::call::{InHead, OutHead};
    use busbar_contract::abi::mechanism::lifecycle::{TickIn, TickOut, ValidateIn};
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    for p in [linked(&d), dropped(&d)] {
        assert!(
            !bearer(&p, OLD).starts_with("Ready"),
            "unopened cannot verify"
        );
        let inputs: serde_json::Value =
            serde_json::from_str(include_str!("conformance.json")).unwrap();
        for settings in inputs["auth"]["bad_settings"].as_array().unwrap() {
            let settings = settings.as_str().unwrap();
            let mut error = [0u8; 512];
            let mut f: Frame<ValidateIn, OutHead> = Frame::new(z(), out_head());
            f.input.head = in_head();
            f.input.settings = blob(settings.as_bytes(), BLOB_JSON);
            f.input.err_buf = error.as_mut_ptr();
            f.input.err_cap = error.len();
            let c = checked_call(&p, life::VALIDATE, &mut f);
            assert_eq!(c.outcome, Outcome::Failed);
            assert_eq!(c.lease, 0);
            let text = String::from_utf8(c.error.expect("reason")).unwrap();
            assert!(!text.is_empty());
            assert!(!text.contains("the-raw-token"));
            assert_eq!(open(&p, settings), Outcome::Failed);
        }
        let settings = settings_of(OLD);
        assert_eq!(open(&p, &settings), Outcome::Ready);
        let before_ready = product_counts(&p);
        p.ready(&d, std::time::Duration::from_secs(10))
            .expect("ready step");
        let after_ready = product_counts(&p);
        assert_eq!(
            (
                after_ready.0 - before_ready.0,
                after_ready.1 - before_ready.1
            ),
            (u64::from(p.has_ready()), 0)
        );
        let line = format!("Bearer {OLD}");
        let lines = [NamedValue {
            name: s("authorization"),
            value: blob(line.as_bytes(), BLOB_OCTETS),
        }];
        let mut f: Frame<VerifyIn, IdentifyOut> = Frame::new(z(), z());
        f.input.head = in_head();
        f.out.head = out_head();
        f.input.point = POINT_HEAD;
        f.input.lines = lines.as_ptr();
        f.input.lines_len = lines.len();
        let short = checked_call(&p, slot::VERIFY, &mut f);
        assert_eq!(short.outcome, Outcome::Failed);
        assert_eq!(
            short.lease, 0,
            "the host does not expose negotiated storage"
        );
        assert_ne!(
            f.out.head.lease, 0,
            "the published absent short_reply declares retained storage"
        );
        let token = short.recall.expect("one short-buffer recall");
        let mut bytes = vec![0u8; f.out.needed_bytes as usize];
        let mut groups = vec![Span { offset: 0, len: 0 }; f.out.needed_groups as usize];
        let mut strips = vec![
            StripName {
                name: Span { offset: 0, len: 0 },
                place: 0,
                _reserved: 0
            };
            2
        ];
        f.input.out_buf = IdentityBuf {
            buf: bytes.as_mut_ptr(),
            buf_cap: bytes.len(),
            groups: groups.as_mut_ptr(),
            groups_cap: groups.len() as u32,
            _reserved: 0,
        };
        f.input.strip = strips.as_mut_ptr();
        f.input.strip_cap = strips.len() as u32;
        f.out.head = out_head();
        let before_recall = product_counts(&p);
        let answer = p.recall(token, slot::VERIFY, &mut f);
        let after_recall = product_counts(&p);
        assert_eq!(
            (
                after_recall.0 - before_recall.0,
                after_recall.1 - before_recall.1
            ),
            (2, 0)
        );
        assert_eq!(answer.outcome, Outcome::Ready);
        assert_eq!(answer.lease, 0);
        assert!(answer.recall.is_none());
        assert_eq!(f.out.verdict, VERDICT_IDENTITY);
        let subject = f.out.identity.subject;
        assert_eq!(
            &bytes[subject.offset as usize..(subject.offset + subject.len) as usize],
            b"admin"
        );
        {
            let mut f: Frame<BeginLoginIn, BeginLoginOut> = Frame::new(z(), z());
            f.input.head = in_head();
            f.out.head = out_head();
            assert_eq!(
                checked_call(&p, slot::BEGIN_LOGIN, &mut f).outcome,
                Outcome::Refused
            );
        }
        {
            let mut f: Frame<CompleteLoginIn, IdentifyOut> = Frame::new(z(), z());
            f.input.head = in_head();
            f.out.head = out_head();
            assert_eq!(
                checked_call(&p, slot::COMPLETE_LOGIN, &mut f).outcome,
                Outcome::Refused
            );
        }
        {
            let mut f: Frame<OpenOutboundIn, OpenOutboundOut> = Frame::new(z(), z());
            f.input.head = in_head();
            f.out.head = out_head();
            assert_eq!(
                checked_call(&p, slot::OPEN_OUTBOUND, &mut f).outcome,
                Outcome::Refused
            );
        }
        {
            let mut f: Frame<OutboundReadyIn, OutboundReadyOut> = Frame::new(z(), z());
            f.input.head = in_head();
            f.out.head = out_head();
            assert_eq!(
                checked_call(&p, slot::OUTBOUND_READY, &mut f).outcome,
                Outcome::Refused
            );
        }
        {
            let mut f: Frame<FieldsIn, FieldsOut> = Frame::new(z(), z());
            f.input.head = in_head();
            f.out.head = out_head();
            assert_eq!(
                checked_call(&p, slot::FIELDS, &mut f).outcome,
                Outcome::Refused
            );
        }
        let mut tick = Frame::new(
            TickIn {
                head: in_head(),
                now_ns: 1,
            },
            TickOut {
                head: out_head(),
                next_tick_ns: 0,
            },
        );
        assert_eq!(
            checked_call(&p, life::TICK, &mut tick).outcome,
            Outcome::Ready
        );
        assert_eq!(refresh(&p, &settings, 2), Outcome::Ready);
        assert_eq!(bearer(&p, OLD), "Ready identity");
        assert_eq!(
            checked_call(
                &p,
                life::CLOSE,
                &mut Frame::<InHead, OutHead>::new(in_head(), out_head())
            )
            .outcome,
            Outcome::Ready
        );
        assert!(
            !bearer(&p, OLD).starts_with("Ready"),
            "closed cannot verify"
        );
        assert_eq!(p.test_invocations().0, 17);
        assert_eq!(p.test_invocations().1, 0);
    }
}

// These inputs mutate only the real product's door metadata or one failing lifecycle callback.
// They contain no credential parsing or alternate authentication implementation.
static MUTATED_DOOR: std::sync::atomic::AtomicPtr<busbar_contract::abi::mechanism::door::Door> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
extern "C" fn mutated_door() -> &'static busbar_contract::abi::mechanism::door::Door {
    // SAFETY: the sole mutation test below installs leaked, complete door data before use.
    unsafe { &*MUTATED_DOOR.load(std::sync::atomic::Ordering::SeqCst) }
}
static READY_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
extern "C" fn refused_ready(
    _: *mut std::ffi::c_void,
    _: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> busbar_contract::abi::mechanism::call::RawOutcome {
    use busbar_contract::abi::mechanism::call::RawOutcome;
    READY_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let failed = RawOutcome::of(Outcome::Failed);
    // SAFETY: READY lends an OutHead; the error text is static.
    unsafe {
        let head = &mut *out.cast::<OutHead>();
        head.outcome = failed;
        head.error = s("admin test discovery refused");
    }
    failed
}

#[test]
fn real_auth_door_metadata_and_ready_failures_are_refused() {
    use busbar_contract::abi::mechanism::{
        door::{Door, DoorParts},
        KindCode,
    };
    use busbar_plugin_loader::dispatch::LoadError;
    let real = busbar_auth_admin_tokens::door().parts();
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let stated = rendering_of(busbar_auth_admin_tokens::door).unwrap();
    let path = cdylib_path();
    // SAFETY: this fresh actual product image exports the documented raw door symbol. The
    // library stays alive while its address and Statement are inspected.
    let library = unsafe { libloading::Library::new(&path) }.expect("open actual product image");
    let symbol: libloading::Symbol<busbar_contract::abi::sdk::door::RawDoorFn> =
        unsafe { library.get(b"busbar_plugin_door\0") }.unwrap();
    assert_ne!(
        *symbol as usize,
        busbar_auth_admin_tokens::door as *const () as usize,
        "dropped tests must use another image"
    );
    let dropped_parts = unsafe { Door::read_parts(symbol()) };
    assert_eq!(dropped_parts.kind_abi, real.kind_abi);
    assert_eq!(dropped_parts.layout, real.layout);
    let install = |parts: DoorParts| {
        // SAFETY: all pointed-to product tables remain static. Metadata-only corruptions are
        // rejected before invocation; the one replacement READY obeys its ABI.
        let door = unsafe { Door::__from_parts(parts) };
        MUTATED_DOOR.store(
            Box::into_raw(Box::new(door)),
            std::sync::atomic::Ordering::SeqCst,
        );
    };
    for abi in [real.kind_abi + 1, real.kind_abi.wrapping_sub(1)] {
        install(DoorParts {
            kind_abi: abi,
            ..real
        });
        let want = LoadError::KindAbi {
            kind: KindCode::Auth,
            door: abi,
            host: real.kind_abi,
        };
        assert_eq!(rendering_of(mutated_door).unwrap_err(), want);
        assert_eq!(LinkedRow::of(mutated_door).unwrap_err(), want);
        let mut wrong = stated.clone();
        let at = busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC.len() + 8;
        wrong[at..at + 4].copy_from_slice(&abi.to_le_bytes());
        assert_eq!(
            load_dropped::<Auth>(&path, &wrong, bind(&d)).err(),
            Some(LoadError::ManifestKindAbi {
                stated: abi,
                host: real.kind_abi
            })
        );
    }
    for layout in [real.layout ^ 1, 0] {
        install(DoorParts { layout, ..real });
        let refusal = rendering_of(mutated_door).unwrap_err();
        assert!(
            matches!(refusal, LoadError::KindLayout { kind: KindCode::Auth, stated, host, .. } if stated == layout && host == real.layout)
        );
        assert!(refusal
            .to_string()
            .contains("rebuild against this busbar-contract"));
        assert_eq!(LinkedRow::of(mutated_door).unwrap_err(), refusal);
        let row = LinkedRow {
            statement: stated.clone(),
            door: raw_mutated_door,
        };
        assert_eq!(load_linked::<Auth>(&row, bind(&d)).err(), Some(refusal));
    }
    {
        use busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4 as Store;
        let row = LinkedRow::of(busbar_auth_admin_tokens::door).unwrap();
        assert_eq!(
            load_linked::<Store>(&row, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Auth,
                want: KindCode::Store
            })
        );
        assert_eq!(
            load_dropped::<Store>(&path, &stated, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Auth,
                want: KindCode::Store
            })
        );
    }
    {
        use busbar_plugin_loader::dispatch::kinds::secret::Secret;
        let row = LinkedRow::of(busbar_auth_admin_tokens::door).unwrap();
        assert_eq!(
            load_linked::<Secret>(&row, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Auth,
                want: KindCode::Secret
            })
        );
        assert_eq!(
            load_dropped::<Secret>(&path, &stated, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Auth,
                want: KindCode::Secret
            })
        );
    }
    {
        use busbar_plugin_loader::dispatch::kinds::hook::Hook;
        let row = LinkedRow::of(busbar_auth_admin_tokens::door).unwrap();
        assert_eq!(
            load_linked::<Hook>(&row, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Auth,
                want: KindCode::Hook
            })
        );
        assert_eq!(
            load_dropped::<Hook>(&path, &stated, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Auth,
                want: KindCode::Hook
            })
        );
    }
    {
        use busbar_plugin_loader::dispatch::kinds::export::Export;
        let row = LinkedRow::of(busbar_auth_admin_tokens::door).unwrap();
        assert_eq!(
            load_linked::<Export>(&row, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Auth,
                want: KindCode::Export
            })
        );
        assert_eq!(
            load_dropped::<Export>(&path, &stated, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Auth,
                want: KindCode::Export
            })
        );
    }
    {
        use busbar_plugin_loader::dispatch::kinds::plane::Plane;
        let row = LinkedRow::of(busbar_auth_admin_tokens::door).unwrap();
        assert_eq!(
            load_linked::<Plane>(&row, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Auth,
                want: KindCode::Plane
            })
        );
        assert_eq!(
            load_dropped::<Plane>(&path, &stated, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Auth,
                want: KindCode::Plane
            })
        );
    }
    {
        use busbar_plugin_loader::dispatch::kinds::transport::Transport;
        let row = LinkedRow::of(busbar_auth_admin_tokens::door).unwrap();
        assert_eq!(
            load_linked::<Transport>(&row, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Auth,
                want: KindCode::Transport
            })
        );
        assert_eq!(
            load_dropped::<Transport>(&path, &stated, bind(&d)).err(),
            Some(LoadError::ManifestKind {
                stated: KindCode::Auth,
                want: KindCode::Transport
            })
        );
    }
    // A real door under an honestly rendered row is distinct from a restated version.
    let mut statement = unsafe { real.statement.read_unaligned() };
    statement.version = s("99.0.0");
    let other_statement = Box::leak(Box::new(statement));
    install(DoorParts {
        statement: other_statement,
        ..real
    });
    let lying = rendering_of(mutated_door).expect("alternate version is valid rendering");
    busbar_contract::abi::mechanism::rendering::read(&lying)
        .expect("statement mismatch input must remain parseable");
    assert_ne!(lying, stated);
    let row = LinkedRow {
        statement: lying.clone(),
        door: raw_product_door,
    };
    assert_eq!(
        load_linked::<Auth>(&row, bind(&d)).err(),
        Some(LoadError::StatementMismatch)
    );
    assert_eq!(
        load_dropped::<Auth>(&path, &lying, bind(&d)).err(),
        Some(LoadError::StatementMismatch)
    );
    let row = LinkedRow {
        statement: stated.clone(),
        door: raw_mutated_door,
    };
    assert_eq!(
        load_linked::<Auth>(&row, bind(&d)).err(),
        Some(LoadError::StatementMismatch)
    );
    install(DoorParts {
        ready: Some(refused_ready),
        ..real
    });
    let row = LinkedRow::of(mutated_door).unwrap();
    let plugin = load_linked::<Auth>(&row, bind(&d)).unwrap();
    assert_eq!(open(&plugin, &settings_of(OLD)), Outcome::Ready);
    assert!(plugin.has_ready());
    READY_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
    let before = product_counts(&plugin);
    assert_eq!(
        plugin
            .ready(&d, std::time::Duration::from_secs(10))
            .unwrap_err(),
        "plugin 'admin-tokens' ready failed: admin test discovery refused"
    );
    let after = product_counts(&plugin);
    assert_eq!(
        (after.0 - before.0, after.1 - before.1),
        (1, 0),
        "failed ready is not retried or resumed"
    );
    assert_eq!(
        READY_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one actual callback invocation"
    );
}

extern "C" fn raw_product_door() -> *const busbar_contract::abi::mechanism::door::Door {
    busbar_auth_admin_tokens::door()
}
extern "C" fn raw_mutated_door() -> *const busbar_contract::abi::mechanism::door::Door {
    mutated_door()
}

/// Raw response properties are compared across both product images and both dispatch paths;
/// the domain goldens separately prohibit two equally wrong verdict/decision/strip answers.
#[test]
fn all_published_cases_preserve_raw_abi_properties_and_exact_crossings() {
    let inputs: serde_json::Value = serde_json::from_str(include_str!("conformance.json")).unwrap();
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let mut doors = Vec::new();
    for p in [linked(&d), dropped(&d)] {
        assert_eq!(
            open(&p, inputs["settings"].as_str().unwrap()),
            Outcome::Ready
        );
        let before = product_counts(&p);
        p.ready(&d, std::time::Duration::from_secs(10)).unwrap();
        let after = product_counts(&p);
        assert_eq!(
            (after.0 - before.0, after.1 - before.1),
            (u64::from(p.has_ready()), 0)
        );
        let mut answers = Vec::new();
        for case in inputs["auth"]["cases"].as_array().unwrap() {
            let now = raw_published_case(&p, &d, case, false);
            let submitted = raw_published_case(&p, &d, case, true);
            assert_eq!(now, submitted, "synchronous/submitted raw ABI parity");
            for answer in [&now, &submitted] {
                assert_eq!(answer["outcome"], "Ready");
                assert_eq!(answer["lease"], 0);
                assert_eq!(answer["error"], serde_json::Value::Null);
                assert_eq!(answer["short"], false);
                let (verdict, decision, subject) = match case["verdict"].as_str().unwrap() {
                    "identity:admin" => (
                        VERDICT_IDENTITY,
                        busbar_contract::abi::auth::DECISION_CONTINUE,
                        Some("admin"),
                    ),
                    "reject" => (
                        VERDICT_REJECT,
                        busbar_contract::abi::auth::DECISION_STOP,
                        None,
                    ),
                    "pass" => (
                        VERDICT_PASS,
                        busbar_contract::abi::auth::DECISION_CONTINUE,
                        None,
                    ),
                    other => panic!("unexpected published verdict {other}"),
                };
                assert_eq!(answer["verdict"], verdict);
                assert_eq!(answer["decision"], decision);
                assert_eq!(answer["subject"], serde_json::json!(subject));
                assert_eq!(answer["groups_len"], 0);
                assert_eq!(
                    answer["strips"],
                    serde_json::json!([
                        ["authorization", busbar_contract::abi::auth::STRIP_FIELD],
                        ["x-admin-token", busbar_contract::abi::auth::STRIP_FIELD],
                    ])
                );
                for word in inputs["auth"]["never_echoed"].as_array().unwrap() {
                    assert!(!answer.to_string().contains(word.as_str().unwrap()));
                }
            }
            answers.push(now);
        }
        let mut close = Frame::new(in_head(), out_head());
        assert_eq!(
            checked_call(&p, life::CLOSE, &mut close).outcome,
            Outcome::Ready
        );
        doors.push(answers);
    }
    assert_eq!(
        doors[0], doors[1],
        "independent images preserve all raw response fields"
    );
}

fn product_counts(p: &Plugin<Auth>) -> (u64, u64) {
    (p.test_invocations().0, p.test_invocations().1)
}

fn raw_published_case(
    p: &Plugin<Auth>,
    d: &Dispatcher,
    case: &serde_json::Value,
    submitted: bool,
) -> serde_json::Value {
    use busbar_contract::abi::mechanism::call::DeadlineClass;
    let lines: Vec<NamedValue> = case["lines"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| NamedValue {
            name: s(name),
            value: blob(value.as_str().unwrap().as_bytes(), BLOB_OCTETS),
        })
        .collect();
    let mut bytes = [0u8; 512];
    let mut groups = [Span { offset: 0, len: 0 }; 16];
    let mut strips = [StripName {
        name: Span { offset: 0, len: 0 },
        place: 0,
        _reserved: 0,
    }; 8];
    let mut frame: Frame<VerifyIn, IdentifyOut> = Frame::new(z(), z());
    frame.input.head = in_head();
    frame.out.head = out_head();
    frame.input.point = POINT_HEAD;
    frame.input.lines = lines.as_ptr();
    frame.input.lines_len = lines.len();
    frame.input.request = RequestFacts {
        method: s("GET"),
        authority: s("conformance.invalid"),
        canonical_path: s("/conformance"),
        query: s(""),
        timestamp: 0,
    };
    frame.input.out_buf = IdentityBuf {
        buf: bytes.as_mut_ptr(),
        buf_cap: bytes.len(),
        groups: groups.as_mut_ptr(),
        groups_cap: groups.len() as u32,
        _reserved: 0,
    };
    frame.input.strip = strips.as_mut_ptr();
    frame.input.strip_cap = strips.len() as u32;
    let (outcome, lease, error, short, output) = if submitted {
        let before = product_counts(p);
        let ticket = d.mint(0).expect("available ticket");
        let reply = d.submit(
            p,
            ticket,
            slot::VERIFY,
            frame,
            DeadlineClass::Call,
            busbar_plugin_loader::dispatch::now_ns().saturating_add(10_000_000_000),
        );
        let done = reply
            .wait(std::time::Duration::from_secs(10))
            .expect("actual admin verifies");
        let output = done.frame.as_ref().expect("completed frame").out;
        let values = (
            done.outcome,
            done.lease,
            done.error.clone(),
            done.short,
            output,
        );
        drop(reply);
        d.recycle(ticket);
        assert!(d.retirement_barrier(ticket, std::time::Duration::from_secs(10)));
        let after = product_counts(p);
        assert_eq!(
            (after.0 - before.0, after.1 - before.1),
            (1, 0),
            "one submitted actual verify, no resume"
        );
        values
    } else {
        let answer = checked_call(p, slot::VERIFY, &mut frame);
        (
            answer.outcome,
            answer.lease,
            answer.error,
            answer.recall.is_some(),
            frame.out,
        )
    };
    let text = |span: Span| {
        let at = span.offset as usize;
        let end = at.checked_add(span.len as usize).expect("bounded span");
        String::from_utf8(
            bytes
                .get(at..end)
                .expect("response span inside lent buffer")
                .to_vec(),
        )
        .unwrap()
    };
    let subject = (outcome == Outcome::Ready && output.verdict == VERDICT_IDENTITY)
        .then(|| text(output.identity.subject));
    let names: Vec<_> = strips[..output.strip_len as usize]
        .iter()
        .map(|strip| (text(strip.name), strip.place))
        .collect();
    let groups: Vec<_> = groups[..output.identity.groups_len as usize]
        .iter()
        .map(|span| text(*span))
        .collect();
    serde_json::json!({
        "outcome": format!("{outcome:?}"), "lease": lease, "error": error, "short": short,
        "verdict": output.verdict, "decision": output.decision,
        "needed_bytes": output.needed_bytes, "needed_groups": output.needed_groups,
        "needed_strip": output.needed_strip, "groups_len": output.identity.groups_len,
        "subject": subject, "groups": groups, "strips": names,
    })
}
