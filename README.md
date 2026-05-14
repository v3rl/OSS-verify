# oss-verify

A supply chain verification script for any OSS tool hosted on GitHub. Downloads, cryptographically verifies, and installs binaries.

> **Disclaimer:** This script significantly raises the bar for supply chain attacks but cannot stop everything. Read the [limitations](#limitations--what-this-script-cannot-stop) section before relying on it.

---

## How it works

The script fetches the release asset list from the GitHub API, auto-detects the signing pattern used by the project, then uses [cosign](https://github.com/sigstore/cosign) to verify that the binary was produced by a specific, named GitHub Actions workflow and recorded in the [Rekor](https://rekor.sigstore.dev) public transparency log — an append-only, externally operated audit log that cannot be quietly modified.

After verification it writes a **lockfile** pinning the exact hashes and signing timestamp. Future installs of the same version must match the lockfile exactly.

```
Fetch release asset list from GitHub API
        ↓
Auto-detect binary asset for your OS/arch
        ↓
Auto-detect signing pattern (A, B, C, or D)
        ↓
cosign verify-blob
  → checks signature is valid
  → checks identity matches the tool's CI workflow (extracted from the cert/bundle)
  → checks Rekor transparency log entry exists
  → both attempts pin the OIDC issuer — no issuer-free fallback
        ↓
Timestamp extraction (from Rekor entry or signing certificate)
        ↓
Timestamp check (optional --cutoff)
  → rejects if signed after a known compromise date
  → cutoff validated as strict YYYY-MM-DD before use
        ↓
Lockfile check
  → first run: writes pinned hashes + signing epoch
  → subsequent runs: verifies ownership, compares all pinned values
        ↓
Archive path traversal scan (before extraction)
        ↓
Install (symlink-safe extraction, path escape check)
```

---

## Limitations — what this script cannot stop

**This is the most important section.**

### The hardest attack: attacker with live CI credentials

If an attacker compromises a project's CI credentials and uses them to publish a malicious release, cosign verification will **pass**. The binary is legitimately signed by the real workflow — it's just that the workflow was triggered by an attacker.

This is exactly what happened with Trivy v0.69.4 in March 2026. Anyone downloading that version for the first time had no automated defence:

- cosign passes ✅ — signed by Aqua's legitimate CI identity
- Rekor entry exists ✅ — real transparency log entry
- No lockfile exists yet ✅ — first install, nothing to compare against
- **Result: malware installed**

No purely technical verification step can save you here on a first install of a compromised version. The attacker has all the right keys.

### What does and doesn't help

| Scenario | cosign | lockfile | cutoff | Human process |
|---|---|---|---|---|
| Binary swapped on release page (no CI access) | ✅ stops it | ✅ stops it | — | — |
| Same version re-downloaded after lockfile written | — | ✅ stops it | — | — |
| Attacker with CI creds, version you installed before attack | — | ✅ stops it | ✅ if date known | — |
| Attacker with CI creds, **fresh install of compromised version** | ❌ | ❌ | ❌ unless you already know | ✅ only defence |

### The `--cutoff` flag helps — but only after you know

```bash
./oss-verify.sh --repo aquasecurity/trivy --version 0.69.4 --cutoff 2026-03-18
```

This rejects v0.69.4 because it was signed after the cutoff. But you have to already know the compromise date to set the flag. The cutoff date must be strictly `YYYY-MM-DD` — relative strings like `"yesterday"` are rejected. It is useful for:

- Reinstalling a version you know is safe
- Enforcing a known-good window across your team after an incident is disclosed

It does not help on a zero-day install of a version you don't yet know is compromised.

### The lockfile helps — but only for versions installed before the attack

If you installed and locked v0.69.2 before March 19, any future reinstall of v0.69.2 on any machine is protected. The lockfile will reject a different binary for the same version tag.

It does nothing for v0.69.4 which was never in your lockfile.

---

## What the script is good for

- **Binary swapped without re-signing.** An attacker who can modify a release page but doesn't have CI credentials cannot produce a valid cosign signature. The script catches this reliably.

- **Drift between installs.** If a binary changes between your first and second install of the same version — for any reason — the lockfile catches it.

- **Team consistency.** Commit the lockfile to your repo and every developer and CI run installs the exact binary you personally reviewed.

- **Post-incident recovery.** After a compromise is disclosed, `--cutoff` lets you verify that the version you have predates the attack window.

- **No hardcoded tool list.** Any public GitHub repo that signs its releases with cosign works automatically — no registration or profile required.

- **Removing the grunt work.** Manually running cosign, extracting timestamps, and managing hashes is tedious. This script automates the mechanical parts of a process you should be doing anyway.

---

## Requirements

```bash
cosign      # https://github.com/sigstore/cosign/releases
curl
jq
openssl     # used for identity extraction and timestamp parsing
sha256sum   # or shasum on macOS; busybox sha256sum also supported
bash 4+     # macOS ships bash 3.2 — script auto-detects and re-execs with Homebrew bash
```

Optional:
```bash
zstd        # only needed if the tool ships .tar.zst archives
unzip       # only needed if the tool ships .zip archives
```

---

## Quick start

```bash
chmod +x oss-verify.sh

# Install Trivy
./oss-verify.sh --repo aquasecurity/trivy --version 0.70.0

# Install TruffleHog
./oss-verify.sh --repo trufflesecurity/trufflehog --version 3.95.3

# Install Grype with a trust cutoff
./oss-verify.sh --repo anchore/grype --version 0.112.0 --cutoff 2026-03-01

# Install gh CLI (binary name differs from repo name)
./oss-verify.sh --repo cli/cli --binary gh --version 2.49.0

# Verify only, do not install
./oss-verify.sh --repo anchore/syft --version 1.19.0 --no-install

# See what the script would do without downloading anything
./oss-verify.sh --repo aquasecurity/trivy --version 0.70.0 --dry-run

# Show detailed detection steps
./oss-verify.sh --repo anchore/grype --version 0.112.0 --verbose
```

Add `~/.local/bin` to your PATH if not already:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

---

## Options

| Flag | Description |
|---|---|
| `--repo <owner/repo>` | GitHub repository in `owner/repo` format (required) |
| `--version <x.y.z>` | Exact version to install (required — no auto-fetch by design) |
| `--binary <name>` | Binary name if it differs from the repo name (e.g. `gh` for `cli/cli`) |
| `--cutoff <YYYY-MM-DD>` | Reject binaries signed after this date — must be strict ISO date |
| `--lock-dir <path>` | Override lockfile directory — must be absolute, non-system path |
| `--install-dir <path>` | Override install directory (default: `~/.local/bin`) |
| `--no-install` | Verify only, skip install |
| `--dry-run` | Print detected pattern and asset URLs, then exit without downloading |
| `--verbose` | Show detailed detection steps including cert parsing diagnostics |
| `--help` | Show usage |

### Environment variables

| Variable | Description |
|---|---|
| `OSS_VERIFY_LOCK_DIR` | Default lockfile directory |

---

## Signing patterns (auto-detected)

The script inspects the release assets and automatically determines which signing pattern the project uses. No configuration needed.

### Pattern A — Direct bundle
Used by: **Trivy**, **cosign**

cosign signs the binary tarball directly via a `.sigstore.json` bundle. One verification step. The bundle contains the Rekor transparency log entry including the `integratedTime` timestamp, which is used for lockfile pinning and `--cutoff` enforcement.

```
cosign verify-blob <binary.tar.gz>
  --bundle <binary.tar.gz>.sigstore.json
  --certificate-identity <extracted from bundle>
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Timestamp source: `integratedTime` from the Rekor entry inside the bundle.
Lockfile pins: binary SHA256, bundle SHA256, signing epoch.

### Pattern B — Checksums + certificate + signature
Used by: **TruffleHog**, **crane**, **Grype**

cosign signs a `checksums.txt` file (not the binary directly). Two steps: cosign verifies the checksums file, then `sha256sum` verifies the binary against it. The signing certificate is a short-lived Fulcio-issued cert valid for ~10 minutes around the time of signing.

```
# Step 1
cosign verify-blob checksums.txt
  --certificate checksums.txt.pem
  --signature   checksums.txt.sig
  --certificate-identity <extracted from .pem>
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Step 2
sha256sum --ignore-missing -c checksums.txt
```

Timestamp source: `notBefore` from the signing certificate's validity window.
Lockfile pins: binary SHA256, checksums SHA256, certificate SHA256, signing epoch.

### Pattern C — Checksums + sigstore bundle
Used by: **Syft**

Same two-step chain as Pattern B but uses a `.sigstore.json` bundle instead of separate `.pem` and `.sig` files. The bundle contains a Rekor entry with an `integratedTime` timestamp.

Timestamp source: `integratedTime` from the Rekor entry inside the bundle.
Lockfile pins: binary SHA256, checksums SHA256, bundle SHA256, signing epoch.

### Pattern D — Checksums only (no cosign)
Fallback for tools that don't yet support cosign.

SHA256 only — verifies **integrity** (file wasn't corrupted) but not **provenance** (who built it). The script warns clearly when this pattern is used and refuses to proceed if `--cutoff` is set since there is no signing timestamp available to enforce it.

---

## Timestamp extraction

Timestamps are used for two purposes: writing a meaningful signing date to the lockfile, and enforcing `--cutoff` rejection.

The source depends on the signing pattern:

**Patterns A and C (sigstore bundle)** — the bundle contains a `verificationMaterial.tlogEntries[0].integratedTime` field written by the Rekor transparency log at the moment of signing. This is the most authoritative timestamp — it comes from infrastructure outside the project's control and cannot be backdated.

**Pattern B (certificate + signature)** — the `.pem` file is a short-lived X.509 certificate issued by Fulcio. The `notBefore` field reflects when Fulcio issued the cert, which happens within seconds of the GitHub Actions OIDC token being presented during signing. The script extracts this using two strategies:

- **Strategy A:** `openssl x509 -startdate` — works for standard PEM certificates.
- **Strategy B:** `openssl asn1parse` — used when `openssl x509` refuses to parse the cert. This occurs with some Fulcio intermediate CA chains (e.g. Grype uses ECDSA P-384 certs that OpenSSL 3.0 rejects at the `x509` level). `asn1parse` reads the raw ASN.1 structure directly and extracts the `UTCTIME` or `GENERALIZEDTIME` field.

### On the security of asn1parse for timestamp extraction

`asn1parse` does not validate the certificate chain — it reads raw bytes. This is intentional and safe in this context for the following reason: `asn1parse` is only ever called **after cosign has already verified the certificate**. cosign uses Sigstore's own trust roots (not the system OpenSSL trust store) to validate the full Fulcio chain, the Rekor entry, and the signature. OpenSSL refusing to parse the cert via `openssl x509` is an OpenSSL version compatibility issue, not a trust issue.

The security model is: cosign validates the cert → we trust the cert → we use `asn1parse` only to read a date field from an already-trusted artifact. We are not using `asn1parse` to make any trust decision.

The `notBefore` date on a Fulcio-issued cert cannot be backdated by an attacker. It reflects when Fulcio's CA issued the cert in response to a valid GitHub Actions OIDC token. An attacker with compromised CI credentials could trigger a real signing event — but the resulting cert's `notBefore` would accurately reflect when that signing happened, not an earlier date.

---

## Lockfile pinning

On first install the script writes a lockfile:

```
~/.local/share/oss-verify/trivy-0.70.0-linux-amd64.lock
```

```json
{
  "repo": "aquasecurity/trivy",
  "version": "0.70.0",
  "os_arch": "linux/amd64",
  "pattern": "direct_bundle",
  "signing_epoch": "1746000000",
  "signing_date": "2026-04-30 12:00:00 UTC",
  "identity": "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.70.0",
  "binary_sha256": "abc123...",
  "bundle_sha256": "def456..."
}
```

On subsequent installs of the same version, the script:

1. Checks the lockfile is owned by the current user — detects pre-planted lockfile attacks where another user writes a forged lockfile before your first install
2. Compares the signing epoch — any difference aborts
3. Compares every SHA256 hash — any difference aborts

If anything differs the install is refused and you are told to investigate before proceeding.

### Sharing lockfiles across a team

Commit the lockfile to your repository. Every developer and CI run will verify against the binary you personally reviewed on day one.

```bash
# Developer machine — first install
./oss-verify.sh --repo trufflesecurity/trufflehog --version 3.95.3 \
  --lock-dir ./lockfiles

# Commit the lockfile
git add lockfiles/trufflehog-3.95.3-linux-amd64.lock
git commit -m "pin trufflehog 3.95.3"

# CI — uses the committed lockfile
OSS_VERIFY_LOCK_DIR=./lockfiles \
  ./oss-verify.sh --repo trufflesecurity/trufflehog --version 3.95.3
```

---

## Why version is required (no auto-fetch)

The script deliberately refuses to run without an explicit `--version`. There is no `--version latest`.

Fetching "latest" at install time means you are always installing an unreviewed version. If the release page is compromised between your review and your install, you get the compromised binary. Pinning to an explicit version — and locking it — means you install exactly what you decided to install.

Check releases manually before upgrading:

- TruffleHog: https://github.com/trufflesecurity/trufflehog/releases
- Trivy: https://github.com/aquasecurity/trivy/releases
- Grype: https://github.com/anchore/grype/releases
- Syft: https://github.com/anchore/syft/releases
- cosign: https://github.com/sigstore/cosign/releases
- crane: https://github.com/google/go-containerregistry/releases

---

## What cosign actually checks

When cosign verifies a blob it confirms:

1. The cryptographic signature over the file is valid
2. The signing certificate was issued by Fulcio (Sigstore's CA) to a GitHub Actions OIDC identity
3. The certificate identity matches the workflow URL extracted from the cert
4. The Rekor transparency log contains an entry for this signing event
5. The signing timestamp falls within the certificate's validity window

An attacker **without** CI credentials cannot forge any of this. An attacker **with** CI credentials can produce signatures that pass all five checks — which is why human process remains the last line of defence for that scenario.

---

## SHA256 vs cosign vs cosign + lockfile

| | SHA256 only | cosign | cosign + lockfile |
|---|---|---|---|
| File not corrupted in transit | ✅ | ✅ | ✅ |
| File came from the right CI pipeline | ❌ | ✅ | ✅ |
| Attacker swapped binary (no CI access) | ❌ | ✅ | ✅ |
| Binary changed between installs | ❌ | ❌ | ✅ |
| Team installs identical binary | ❌ | ❌ | ✅ |
| Attacker used compromised CI credentials | ❌ | ❌ | ❌ on first install |
| Compromised version re-installed post-lockfile | ❌ | ❌ | ✅ |

---

## Real-world incident: Trivy (March 2026)

On 19 March 2026, a threat actor used compromised Aqua Security CI credentials to publish malicious versions of Trivy (v0.69.4), trivy-action, and setup-trivy.

**Who this script would have helped:**
Users who had previously installed and locked v0.69.2 were protected. Any reinstall of v0.69.2 would compare against the locked binary hash and pass. Any attempt to install v0.69.4 with `--cutoff 2026-03-18` would have been blocked.

**Who this script would not have helped:**
Anyone installing v0.69.4 for the first time, with no prior lockfile and no cutoff date set. cosign verification passes because the attacker used Aqua's real CI credentials. The only protection in that scenario was human: monitoring security advisories and not blindly upgrading on release day.

The Trivy incident is a useful reminder that supply chain security is defence in depth. This script handles the automated layers. The human layers — deliberate version pinning, advisory monitoring, delayed upgrades — are not optional extras.
