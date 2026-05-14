
## Secure Design

The script was reviewed through multiple security passes. The properties enforced:

**cosign verification**
- Both verification attempts pin `--certificate-oidc-issuer` — no issuer-free fallback that would accept any Sigstore signer
- Identity is extracted directly from the signing certificate or bundle — not hardcoded or guessed
- Extracted identity is validated as a GitHub Actions workflow URL before being used
- Verification failure aborts with full diagnostic output including the identities attempted

**Input validation**
- `--repo` validated to `^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`
- `--version` validated to `^[0-9]+\.[0-9]+\.[0-9]+...` — no `latest`, no relative strings
- `--binary` validated to alphanumeric, hyphen, underscore, dot only
- `--cutoff` validated to strict `^[0-9]{4}-[0-9]{2}-[0-9]{2}$` before passing to `date` — prevents relative date strings like `"yesterday"` being accepted
- `--lock-dir` and `--install-dir` validated as absolute paths with no `..` and no system directory prefixes (`/etc`, `/usr`, `/bin`, etc.) checked by prefix not exact match
- Raw binary filename validated for safe characters before install
- Argument count checked before `shift 2` — missing values produce clear errors, not unbound variable crashes

**Network**
- Both `api_curl` and `binary_curl` use `--proto "=https" --location --proto-redir "=https"` — HTTPS enforced on the initial request and any redirect destination
- `--location` is required because GitHub release asset URLs redirect to `objects.githubusercontent.com` for the actual file; `--proto-redir "=https"` prevents redirect to non-HTTPS
- All asset URLs validated against a `github.com` / `objects.githubusercontent.com` allowlist before use and before download
- API responses capped at 1MB; binary downloads uncapped (tools can be 100MB+)
- curl errors surfaced in the abort message rather than swallowed via `2>/dev/null`

**Asset detection**
- Pattern detection uses exact string matching (`==`) and literal suffix matching — no regexp against API-provided asset names
- Binary detection uses regexp built only from validated internal inputs (OS labels, arch labels, extensions) — never from raw API data
- Checksums file detected by exact name or versioned suffix match — prevents `.checksums.txt.sig` being mistaken for `.checksums.txt`

**Archive extraction**
- Archive contents listed and scanned for path traversal entries (`/`-prefixed, `..`-containing, bare `..`) before any extraction happens
- After extraction, `find` uses `-type f -not -type l` to reject symlinks explicitly
- Resolved binary path checked against `$WORKDIR` via `pwd -P` to catch symlink escapes
- `--wildcards` (GNU-only tar extension) not used — portable on Linux and macOS

**Temp directory and lockfile**
- Temp dir set to `chmod 700` immediately after creation
- Lockfile set to `chmod 600` on write; lockfile directory set to `chmod 700` on creation
- Lockfile owner uid checked before reading — detects pre-planted lockfiles
- `stat` failure distinguished from genuine ownership mismatch with separate error messages

**Timestamp**
- Signing epoch validated as a numeric Unix timestamp
- Zero or empty epoch aborts rather than writing a meaningless lockfile entry
- If `--cutoff` is set and timestamp cannot be extracted, script aborts — cutoff is never silently skipped
- `asn1parse` used only for data extraction on cosign-verified certs, not for trust decisions (see [timestamp extraction](#timestamp-extraction))
- Both `UTCTIME` (13-char) and `GENERALIZEDTIME` (15-char) ASN.1 date formats handled
- Date extraction uses bash string operations — no `sed \s` which is non-POSIX and fails on BSD sed (macOS)

**Checksums**
- Binary filename confirmed present in checksums file before `sha256sum --ignore-missing` is trusted — it exits 0 even when the file isn't listed
- Manual fallback uses anchored grep so a short binary name like `go` doesn't match `golang`
- Extracted hash validated as 64 hex characters before comparison

**Shell safety**
- `set -euo pipefail` throughout — unset variables and pipeline failures abort immediately
- `printf '%s'` used instead of `echo` for piping JSON — prevents echo interpreting escape sequences
- `jq --arg` used for all variable substitution into jq expressions — no injection via asset names
- `base64_decode` uses `${1:-}` default — safe under `set -u` when called with no argument
