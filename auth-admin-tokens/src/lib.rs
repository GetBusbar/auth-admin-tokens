// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in `admin-tokens` ADMIN auth PLUGIN.
//!
//! A module for the `admin_auth:` chain (the parallel chain gating `/admin/v1/*`): the single
//! operator admin token, presented as `Authorization: Bearer` or `X-Admin-Token`. Architecturally a
//! peer of any external admin module (AD/OIDC); this one is credential-compare only. An admin
//! credential legitimately arrives on two carriers, and the constant-time both-carriers fold lives
//! INSIDE the module: selecting a carrier before the compare would reintroduce the timing observable
//! the fold kills.
//!
//! ## One door
//!
//! [`door::door`] is the plugin's door, built by the SDK's `auth_verify_door!` over
//! [`AdminTokens`]: a `kind: auth` plugin that states `CAP_INBOUND` only, reads its two credential
//! lines (`authorization` for the Bearer, and `x-admin-token`), names both for the transport to strip
//! whatever its verdict, and judges on the spot. A build that LINKS this crate registers that door as
//! its `admin-tokens` row; the dropped-in build (`busbar-auth-admin-tokens-plugin`) exports the SAME
//! door as `busbar_plugin_door`. The crate holds no `unsafe`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use busbar_contract::abi::auth::{AuthPoints, AuthTail};
use busbar_contract::abi::mechanism::door::{MarkWord, Statement};
use busbar_contract::abi::sdk::auth_door::{
    carrier, verify_tail, with_operator, with_tail, Answer, Strip, Verdict, VerifiedIdentity,
    VerifyPlugin, VerifyView,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::hmac::sha256;
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::constant_time_eq;
use zeroize::Zeroizing;

/// The fixed principal id the operator admin token identifies as. The built-in operator credential
/// carries FULL admin scope by definition (it is the root credential the deployment was born with);
/// group-mapped external principals get their scope from `group_map:` instead.
pub const ADMIN_TOKENS_PRINCIPAL_ID: &str = "admin";

/// The module name: the `admin_auth:` chain entry this module answers.
pub const ADMIN_TOKENS_MODULE_NAME: &str = "admin-tokens";

/// The second carrier the operator token may arrive on (lower-case); the first is the Bearer.
pub const ADMIN_TOKEN_HEADER: &str = "x-admin-token";

/// The line the Bearer arrives on (lower-case), as `Bearer <token>`.
pub const AUTHORIZATION_HEADER: &str = "authorization";

/// The length of a SHA-256 digest in hex: the configured digest's, and each presented token's.
const DIGEST_HEX_LEN: usize = 64;

/// A field value as header text (as `HeaderValue::to_str`): visible ASCII, space or tab; any other
/// byte makes the value no text at all.
fn header_text(value: &[u8]) -> Option<&str> {
    if !value
        .iter()
        .all(|&b| b == b'\t' || (0x20..0x7f).contains(&b))
    {
        return None;
    }
    std::str::from_utf8(value).ok()
}

/// The token of an `Authorization` value already known to be header text, in the Bearer scheme:
/// the scheme matched case-insensitively, the token non-empty. The Bearer scheme's separator
/// is one or more ASCII spaces (RFC 6750 §2.1); consume that run, preserving all subsequent token
/// bytes. A tab is not a scheme separator, and a leading space leaves the scheme empty.
fn bearer_of_text(text: &str) -> Option<&str> {
    let (scheme, token) = text.split_once(' ')?;
    let token = token.trim_start_matches(' ');
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// The operator identity.
fn operator() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: ADMIN_TOKENS_PRINCIPAL_ID.to_string(),
        ..VerifiedIdentity::default()
    }
}

/// Judge every presented line of each carrier (`bearers` off the `authorization` lines, `headers`
/// off the `x-admin-token` lines) against the configured admin token hash (the lower-case SHA-256
/// hex [`digest_of`] reads off the settings), comparing each with `matches` ([`token_matches`]; the
/// parameter is the seam that lets a test count the compares).
///
/// Timing stance: once any credential is presented, BOTH carriers are hashed and compared
/// unconditionally (an absent one against a fixed placeholder whose result is discarded) and the
/// results fold with bitwise-OR, so "Bearer matched", "Bearer missed, header matched" and "only one
/// carrier presented" are indistinguishable. Candidates are SHA-256-hashed before the constant-time
/// compare, so it runs over fixed-length digests and reveals neither the configured token's length
/// nor a partial match.
///
/// No credential presented ⇒ `Pass` (a chain that ends all-`Pass` is denied, fail-closed).
///
/// A credential presented and not matching is a wrong credential, whatever its shape: `Reject`,
/// terminal in the admin chain. A JWS/JWT-shaped wrong token is not passed on to the next
/// `admin_auth:` module.
fn judge(
    configured_hash: &str,
    bearers: &[&str],
    headers: &[&str],
    matches: impl Fn(&str, &str) -> bool,
) -> Verdict {
    if bearers.is_empty() && headers.is_empty() {
        return Verdict::Pass;
    }
    let bearer_match = carrier_matches(bearers, configured_hash, &matches);
    let header_match = carrier_matches(headers, configured_hash, &matches);
    if std::hint::black_box(bearer_match | header_match) != 0 {
        return Verdict::Identity(operator());
    }
    // A credential was presented and no carrier matched. Neither the token nor the digest is
    // logged.
    tracing::info!(
        module = ADMIN_TOKENS_MODULE_NAME,
        "admin token refused: token mismatch"
    );
    Verdict::Reject
}

/// Whether `token` is the configured admin token: its SHA-256 digest in lower-case hex, compared
/// with `configured_hash` in constant time. The digest and its hex are derived from the presented
/// secret, so both are wiped when the compare is done.
fn token_matches(token: &str, configured_hash: &str) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = sha256(&[token.as_bytes()]);
    let mut hex = Zeroizing::new([0u8; DIGEST_HEX_LEN]);
    for (i, h) in hex.iter_mut().enumerate() {
        let b = digest[i / 2];
        *h = HEX[usize::from(if i % 2 == 0 { b >> 4 } else { b & 0xf })];
    }
    constant_time_eq(&hex, configured_hash)
}

/// What an absent carrier is compared as, so a request presenting one carrier costs what one
/// presenting both does. Its result is discarded: an absent carrier never matches.
const ABSENT_PLACEHOLDER: &str = "";

/// One carrier's fold: `1` when at least one line of it was presented and EVERY presented line
/// matches (a carrier presented twice, once wrong, is a wrong credential), else `0`. Every copy is
/// compared, with no short circuit; an absent carrier is compared once as [`ABSENT_PLACEHOLDER`].
fn carrier_matches(
    copies: &[&str],
    configured_hash: &str,
    matches: &impl Fn(&str, &str) -> bool,
) -> u8 {
    let presented = !copies.is_empty();
    let compared: &[&str] = if presented {
        copies
    } else {
        &[ABSENT_PLACEHOLDER]
    };
    let mut every = 1u8;
    for &token in compared {
        every &= std::hint::black_box(u8::from(matches(token, configured_hash)));
    }
    u8::from(presented) & every
}

/// The refusal of settings that are not a digest. It never echoes what it was given.
pub const NOT_A_DIGEST: &str = "settings: must be the admin token's SHA-256 digest as 64 hex \
                                characters (the value is not echoed)";

/// The refusal of the digest of an empty token: a blank admin token is refused. It never echoes
/// what it was given.
pub const EMPTY_TOKEN: &str = "settings: is the SHA-256 digest of an empty token, which is \
                               refused (the value is not echoed)";

/// SHA-256 of the empty string: the digest of a blank admin token.
const EMPTY_TOKEN_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The configured digest out of the settings document: a JSON string holding the admin token's
/// SHA-256 digest as 64 hex characters (surrounding whitespace ignored), lower-cased. Fail-closed:
/// anything else is refused. Always hash the token before configuring it: a raw token that is
/// itself 64 hex characters is indistinguishable from a digest and would be interpreted as one.
///
/// The string is decoded by `settings_text` into one wiping buffer, so no unwiped copy of the
/// digest is made, whether or not the document escapes any of it.
///
/// # Errors
/// [`NOT_A_DIGEST`]; [`EMPTY_TOKEN`] for the digest of an empty token.
pub fn digest_of(settings: &[u8]) -> Result<Zeroizing<String>, &'static str> {
    let text = settings_text(settings).ok_or(NOT_A_DIGEST)?;
    let digest = text.trim();
    if digest.len() != DIGEST_HEX_LEN || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NOT_A_DIGEST);
    }
    let digest = Zeroizing::new(digest.to_ascii_lowercase());
    if digest.as_str() == EMPTY_TOKEN_SHA256 {
        return Err(EMPTY_TOKEN);
    }
    Ok(digest)
}

/// The text of the settings document, which must be exactly one JSON string (RFC 8259) with only
/// JSON whitespace around it, decoded into a wiping buffer. The buffer is reserved at the
/// document's length up front, and a decoded character is never longer than its encoding, so it is
/// never reallocated and no unwiped copy is left behind.
///
/// Only what a digest document can hold is decoded: whitespace and hex digits, raw or escaped
/// (`\t`, `\n`, `\r`, `\f`, `\uXXXX`). Any other character, escape or code point (`\"`, `\\`, `\/`,
/// `\b`, a surrogate, a raw control character) is refused (`None`): it could never be part of a
/// digest, so the refusal is the one [`digest_of`] would reach anyway.
fn settings_text(settings: &[u8]) -> Option<Zeroizing<String>> {
    let document = std::str::from_utf8(settings).ok()?;
    let body = document
        .trim_matches([' ', '\t', '\n', '\r'])
        .strip_prefix('"')?
        .strip_suffix('"')?;
    let mut text = Zeroizing::new(String::with_capacity(body.len()));
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        let c = match c {
            '\\' => match chars.next()? {
                't' => '\t',
                'n' => '\n',
                'r' => '\r',
                'f' => '\u{c}',
                'u' => {
                    let mut code = 0u32;
                    for _ in 0..4 {
                        code = code * 16 + chars.next()?.to_digit(16)?;
                    }
                    char::from_u32(code)?
                }
                _ => return None,
            },
            c if c < ' ' => return None,
            c => c,
        };
        if !(c.is_whitespace() || c.is_ascii_hexdigit()) {
            return None;
        }
        text.push(c);
    }
    Some(text)
}

/// The Bearer off one `authorization` line. A value that is not header text, or a Bearer with no
/// token, is read as absent and says so in the log (never the value). Another scheme is a silent
/// absence.
fn bearer_line(value: &[u8]) -> Option<&str> {
    let Some(text) = header_text(value) else {
        note_malformed(AUTHORIZATION_HEADER);
        return None;
    };
    let token = bearer_of_text(text);
    if token.is_none() {
        let scheme = text.split_once(' ').map_or(text, |(scheme, _)| scheme);
        if scheme.eq_ignore_ascii_case("bearer") {
            note_no_token(AUTHORIZATION_HEADER);
        }
    }
    token
}

/// The token off one `X-Admin-Token` line, verbatim (as 1.5.5 compared it: a padded value is a
/// different credential). A value that is not header text, or is empty, is read as absent, never a
/// presented wrong credential, and says so in the log (never the value).
fn header_line(value: &[u8]) -> Option<&str> {
    let Some(text) = header_text(value) else {
        note_malformed(ADMIN_TOKEN_HEADER);
        return None;
    };
    if text.is_empty() {
        note_no_token(ADMIN_TOKEN_HEADER);
        return None;
    }
    Some(text)
}

/// The log line for a credential line that is not header text.
fn note_malformed(line: &str) {
    tracing::info!(
        module = ADMIN_TOKENS_MODULE_NAME,
        line,
        "admin token line is not header text and is read as absent"
    );
}

/// The log line for a credential line that is present but carries no token.
fn note_no_token(line: &str) {
    tracing::info!(
        module = ADMIN_TOKENS_MODULE_NAME,
        line,
        "admin token line carries no token and is read as absent"
    );
}

/// The plugin: the configured admin token's SHA-256 hex digest (never the raw token).
///
/// The digest sits behind a lock so a `reload` carrying a ROTATED digest replaces it in place: the
/// new token is accepted and the old one refused without a re-open. The digest is held wiping: a
/// replaced or dropped digest is zeroed.
///
/// `Debug` is implemented by hand and never prints the digest.
pub struct AdminTokens {
    configured_hash: std::sync::RwLock<Zeroizing<String>>,
}

impl AdminTokens {
    /// The digest this instance judges against now.
    fn digest(&self) -> std::sync::RwLockReadGuard<'_, Zeroizing<String>> {
        self.configured_hash
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl std::fmt::Debug for AdminTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminTokens").finish_non_exhaustive()
    }
}

impl VerifyPlugin for AdminTokens {
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        digest_of(settings).map(|_| ()).map_err(Refusal::failed)
    }

    fn open_refusing(settings: &[u8], _secrets: &[&[u8]]) -> Result<Self, Refusal> {
        Ok(Self {
            configured_hash: std::sync::RwLock::new(digest_of(settings).map_err(Refusal::failed)?),
        })
    }

    /// A reload (the host's `refresh`): the settings it carries are read as `open` reads them, so a
    /// rotated digest replaces the one held and is judged from the next request on. Settings that
    /// are not a digest are refused (FAILED, never echoing the value) and logged, and the digest
    /// held stands: dropping to no digest would answer `Pass`, and a held instance never stops
    /// judging. Nothing is cached, so nothing is dropped: `0`.
    fn reload(&self, settings: &[u8], _secrets: &[&[u8]]) -> Result<u64, Refusal> {
        match digest_of(settings) {
            Ok(digest) => {
                *self
                    .configured_hash
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = digest;
                Ok(0)
            }
            Err(reason) => {
                tracing::warn!(
                    module = ADMIN_TOKENS_MODULE_NAME,
                    reason,
                    "admin token refresh refused: the held digest stands"
                );
                Err(Refusal::failed(reason))
            }
        }
    }

    /// Every presented `authorization` line (for its Bearer) and `X-Admin-Token` line is put to the
    /// fold in one call, so the fold is the module's own: a carrier sent on more than one line
    /// matches only if every copy does. Whatever the verdict, both lines are named for the transport
    /// to strip: they are this module's credential lines.
    fn verify(&self, request: &VerifyView<'_>) -> Answer {
        // Release the lock before parsing carriers or invoking arbitrary tracing subscribers.
        let digest: Zeroizing<String> = self.digest().clone();
        let mut bearers = Vec::new();
        let mut headers = Vec::new();
        for (name, value) in request.lines() {
            if name.eq_ignore_ascii_case(AUTHORIZATION_HEADER.as_bytes()) {
                bearers.extend(bearer_line(value));
            } else if name.eq_ignore_ascii_case(ADMIN_TOKEN_HEADER.as_bytes()) {
                headers.extend(header_line(value));
            }
        }
        let verdict = judge(digest.as_str(), &bearers, &headers, token_matches);
        Answer {
            strips: vec![
                Strip::field(AUTHORIZATION_HEADER),
                Strip::field(ADMIN_TOKEN_HEADER),
            ],
            ..verdict.into()
        }
    }
}

/// The credential lines `verify` reads, the Statement's carrier word marks: the host lends exactly
/// these.
const CARRIERS: &[MarkWord] = &[carrier(AUTHORIZATION_HEADER), carrier(ADMIN_TOKEN_HEADER)];

/// The auth tail: inbound only, judged on the spot, nothing cached (a compare against a value the
/// operator can rotate is never worth caching), reading its two credential lines. It states that it
/// IS the operator credential, and the principal id its identity carries: the host finds the
/// operator credential's row by this fact, never by its name.
const TAIL: &AuthTail = &with_operator(verify_tail(0, AuthPoints::HEAD), ADMIN_TOKENS_PRINCIPAL_ID);

/// The concurrency the plugin states it serves.
pub const CONCURRENCY: u32 = 1024;

/// JSON Schema for the lifecycle settings document, embedded in the signed Statement.
const SETTINGS_SCHEMA: &[u8] = include_bytes!("../settings.schema.json");

/// What the plugin states: its name, version, the concurrency it serves ([`CONCURRENCY`]: a pure
/// compare holding only the rotatable digest, like the other verifiers) and its two carriers.
pub const STATEMENT: Statement = with_tail(
    Statement {
        settings_schema: busbar_contract::abi::mechanism::call::Blob::json(SETTINGS_SCHEMA),
        mark_words: CARRIERS.as_ptr(),
        mark_words_len: CARRIERS.len(),
        ..statement(
            ADMIN_TOKENS_MODULE_NAME,
            env!("CARGO_PKG_VERSION"),
            CONCURRENCY,
        )
    },
    TAIL,
);

/// The door: `door::door`, the plugin's `DoorFn`. A build that links this crate registers it as the
/// `admin-tokens` row; `busbar-auth-admin-tokens-plugin` exports it as `busbar_plugin_door`.
pub mod door {
    busbar_contract::auth_verify_door!(super::AdminTokens, super::STATEMENT);
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;

#[cfg(test)]
mod settings_schema_tests;
