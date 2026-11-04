<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-auth-admin-tokens

First-party signed kind:auth plugin cdylib: the built-in admin-tokens admin-auth module (the single operator admin token, compared in constant time), packaged as a droppable busbar plugin.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `auth` | `admin-tokens` | `busbar-auth-admin-tokens-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-auth-admin-tokens/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-auth-admin-tokens/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-auth-admin-tokens` is a `kind: auth` busbar plugin.

## Config

Configured under the `admin-tokens` module name (an `admin_auth:` chain entry).

**Settings** are a JSON string holding the lower-case SHA-256 hex digest of the admin token (64 hex
characters; surrounding whitespace is ignored and upper-case is lower-cased). Configure only the
digest, never the raw token. A raw token that is itself 64 hex characters cannot be distinguished
from a digest and is interpreted as one; hash it before configuration too. The digest of an empty
token is refused. A refusal never echoes the value.

```json
"<SHA-256 hex digest of your generated admin token>"
```

That placeholder is deliberately invalid. Generate a random token and its settings JSON locally,
for example with Python 3:

```sh
python3 - <<'PY'
import hashlib
import json
import secrets

token = secrets.token_urlsafe(32)
print("Admin token:", token)
print("Settings JSON:", json.dumps(hashlib.sha256(token.encode("utf-8")).hexdigest()))
PY
```

Store the generated admin token as an operator secret. Put only the generated settings JSON in the
configuration.

**Rotation.** To rotate the admin token, configure the new digest: it takes effect when busbar opens
the `admin-tokens` module with the new settings (at start-up, or on a configuration reload, which
rebuilds the admin chain). At busbar 1.6.0 the host's `refresh` of this
module (the admin credential-cache flush) re-sends the settings the instance was opened with, so it
does not rotate the digest. A `refresh` that does carry a rotated digest (the plugin ABI allows
one) replaces the digest held, with no re-open: the new token is accepted and the old one refused.
A `refresh` whose settings are not a digest is refused (never echoing the value) and logged, and
the held digest stands.

**Carriers.** The token is read off either of two lines: `Authorization: Bearer <token>` (scheme
matched case-insensitively) or `X-Admin-Token: <token>`. As in busbar 1.5.5, both are read
verbatim: the Bearer value is split on its first single space and the token is the rest exactly as
sent (`Bearer  <token>` presents ` <token>`, a leading space leaves no scheme, a tab is no
separator), and an `X-Admin-Token` value is the token exactly as sent, spaces and tabs included.
A padded token is therefore a different, wrong credential. A line that is not header text (visible
ASCII, space or tab), a Bearer with no token, or an empty `X-Admin-Token` is read as absent and
logged at info (never the value); another scheme is a silent absence. Every line of a carrier that
a request repeats is read: a carrier matches only if every one of its presented lines does.

**Verdicts.** Once any credential is presented, both carriers are compared (constant time, over
SHA-256 digests of the candidates; an absent carrier against a fixed placeholder), so the timing
does not reveal which carrier matched, and a request presenting one carrier runs as many compares
as one presenting both. Each further copy of a repeated line adds one compare.
- A carrier matching the digest: identity `admin` (the operator credential, full admin scope).
- A credential presented and not matching, whatever its shape (a dotted, JWS-like token is not
  special): `Reject`, terminal in the admin chain. A line read as absent (see Carriers) presents no
  credential.
- No credential presented: `Pass` (the chain denies if every module passes).

**Strips.** Whatever the verdict, both the `authorization` and `x-admin-token` lines are named for
the transport to strip: they are this module's credential lines.

## Build

```bash
cargo build --release -p busbar-auth-admin-tokens-plugin
```

## Tests

The plugin's integration tests load the freshly built cdylib, named by `BUSBAR_PLUGIN_CDYLIB`
(`.dylib` on macOS):

```bash
cargo build --release --locked -p busbar-auth-admin-tokens-plugin --lib
BUSBAR_PLUGIN_CDYLIB="$PWD/target/release/libbusbar_auth_admin_tokens_plugin.so" cargo test --release --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
