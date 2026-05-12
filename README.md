# oss-verify

A supply chain verification script for OSS security tools. Downloads, cryptographically verifies, and installs binaries — with no GitHub login required.

> **Disclaimer:** This script significantly raises the bar for supply chain attacks but cannot stop everything. Read the [limitations](#limitations--what-this-script-cannot-stop) section before relying on it.

---

## The problem it solves

When you `curl | bash` or download a binary from a release page, you are trusting:

- The release page hasn't been tampered with
- The binary is what the maintainers actually built
- Nobody has swapped it since it was signed

SHA256 checksums alone don't help — an attacker who controls the release page can update both the binary and the checksum. You need **provenance verification**, not just integrity verification.

---

## How it works

The script uses [cosign](https://github.com/sigstore/cosign) to verify that a binary was produced by a specific, named GitHub Actions workflow and recorded in the [Rekor](https://rekor.sigstore.dev) public transparency log — an append-only, externally operated audit log that cannot be quietly modified.

After verification it writes a **lockfile** pinning the exact hashes and signing timestamp it saw. Future installs of the same version must match the lockfile exactly.

```
Download binary + signing files
        ↓
cosign verify-blob
  → checks signature is valid
  → checks identity matches the tool's CI workflow
  → checks Rekor transparency log entry exists
        ↓
Timestamp check (optional --cutoff)
  → rejects if signed after a known compromise date
        ↓
Lockfile check
  → first run: writes pinned hashes
  → subsequent runs: compares against pinned hashes
        ↓
Install
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
./oss-verify.sh --tool trivy --version 0.69.4 --cutoff 2026-03-18
```

This rejects v0.69.4 because it was signed after the cutoff. But you have to already know the compromise date to set the flag. It is useful for:

- Reinstalling a version you know is safe
- Enforcing a known-good window across your team after an incident is disclosed

It does not help on a zero-day install of a version you don't yet know is compromised.

### The lockfile helps — but only for versions installed before the attack

If you installed and locked v0.69.2 before March 19, any future reinstall of v0.69.2 on any machine is protected. The lockfile will reject a different binary for the same version tag.

It does nothing for v0.69.4 which was never in your lockfile.

---

## What actually protects you against CI credential compromise

These are **human processes**, not automated tooling:

1. **Never install on release day.** Wait a few days. The community detects compromised releases quickly. Aqua's incident was publicly disclosed within hours.

2. **Subscribe to security advisories** for every tool you depend on. GitHub → Watch → Security alerts.

3. **Pin deliberately after reading the release notes.** Review what changed before upgrading. A release with unexpected binary size changes or unusual changelog entries is a warning sign.

4. **Don't auto-upgrade in CI.** Pinning `--version latest` in any form, even via a script, means you install whatever the attacker published.

5. **Use the lockfile + cutoff after an incident is disclosed.** Once a compromise window is known, `--cutoff` lets you enforce that boundary across your team.

---

## What the script is genuinely good for

- **Binary swapped without re-signing.** An attacker who can modify a release page but doesn't have CI credentials cannot produce a valid cosign signature. The script catches this reliably.

- **Drift between installs.** If a binary changes between your first and second install of the same version — for any reason — the lockfile catches it.

- **Team consistency.** Commit the lockfile to your repo and every developer and CI run installs the exact binary you personally reviewed.

- **Post-incident recovery.** After a compromise is disclosed, `--cutoff` lets you verify that the version you have predates the attack window.

- **Removing the grunt work.** Manually running cosign, extracting timestamps, and managing hashes is tedious. This script automates the mechanical parts of a process you should be doing anyway.

---

## Requirements

```bash
cosign      # https://github.com/sigstore/cosign/releases
curl
jq
sha256sum
openssl
```

Install cosign itself using the script (it signs itself, so no chicken-and-egg problem):

```bash
./oss-verify.sh --tool cosign --version 2.4.1
```

---

## Quick start

```bash
chmod +x oss-verify.sh

# See all supported tools
./oss-verify.sh --list

# Install TruffleHog
./oss-verify.sh --tool trufflehog --version 3.95.3

# Install Trivy with a trust cutoff
./oss-verify.sh --tool trivy --version 0.70.0 --cutoff 2026-03-01

# Verify only, do not install
./oss-verify.sh --tool grype --version 0.88.0 --no-install
```

Add `~/.local/bin` to your PATH if not already:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

---

## Options

| Flag | Description |
|---|---|
| `--tool <name>` | Tool to install (required) |
| `--version <x.y.z>` | Exact version (required — no auto-fetch) |
| `--cutoff <YYYY-MM-DD>` | Reject binaries signed after this date |
| `--lock-dir <path>` | Override lockfile directory |
| `--install-dir <path>` | Override install directory (default: `~/.local/bin`) |
| `--no-install` | Verify only, skip install |
| `--list` | List all supported tools |
| `--help` | Show usage |

### Environment variables

| Variable | Description |
|---|---|
| `OSS_VERIFY_LOCK_DIR` | Default lockfile directory (overridden by `--lock-dir`) |

---

## Supported tools

| Tool | Description | Signing pattern |
|---|---|---|
| `trufflehog` | Secret scanner by TruffleSecurity | B — checksums + cert/sig |
| `trivy` | Vulnerability scanner by Aqua Security | A — direct bundle |
| `cosign` | Sigstore signing tool | A — direct bundle |
| `grype` | Vulnerability scanner by Anchore | C — checksums + bundle |
| `syft` | SBOM generator by Anchore | C — checksums + bundle |
| `crane` | OCI registry tool by Google | B — checksums + cert/sig |

---

## Signing patterns

Different projects sign their releases in different ways. The script handles all of them transparently.

### Pattern A — Direct bundle
Used by: **Trivy**, **cosign**

cosign signs the tarball itself. One verification step.

```
cosign verify-blob <binary.tar.gz> \
  --bundle <binary.tar.gz>.sigstore.json \
  --certificate-identity <workflow URL> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Lockfile pins: binary SHA256, bundle SHA256, signing timestamp.

### Pattern B — Checksums + certificate + signature
Used by: **TruffleHog**, **crane**

cosign signs a `checksums.txt` file (not the binary directly). Two steps: cosign verifies the checksums file, then `sha256sum` verifies the binary against it.

```
# Step 1: verify the checksums file
cosign verify-blob checksums.txt \
  --certificate checksums.txt.pem \
  --signature   checksums.txt.sig \
  --certificate-identity-regexp <workflow regexp> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Step 2: verify the binary
sha256sum --ignore-missing -c checksums.txt
```

Lockfile pins: binary SHA256, checksums SHA256, certificate SHA256, signing timestamp.

### Pattern C — Checksums + sigstore bundle
Used by: **Grype**, **Syft**

Same two-step chain as Pattern B, but uses a `.sigstore.json` bundle instead of separate `.pem` and `.sig` files.

```
# Step 1: verify the checksums file
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp <workflow regexp> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Step 2: verify the binary
sha256sum --ignore-missing -c checksums.txt
```

Lockfile pins: binary SHA256, checksums SHA256, bundle SHA256, signing timestamp.

### Pattern D — Checksums only (no cosign)
Fallback for tools that don't yet support cosign.

SHA256 only — verifies **integrity** (file wasn't corrupted) but not **provenance** (who built it). The script warns clearly when this pattern is used.

---

## Lockfile pinning

On first install the script writes a lockfile:

```
~/.local/share/oss-verify/trufflehog-3.95.3-linux-amd64.lock
```

```json
{
  "version": "3.95.3",
  "signing_epoch": "1746000000",
  "signing_date": "2026-04-30 12:00:00 UTC",
  "pattern": "checksum_certsig",
  "binary_sha256": "abc123...",
  "checksums_sha256": "def456...",
  "cert_sha256": "ghi789..."
}
```

On subsequent installs of the same version, every value is compared against the lockfile. If anything differs — the binary, the checksums file, the certificate, or the signing timestamp — the install is aborted.

### Sharing lockfiles across a team

Commit the lockfile to your repository. Every developer and CI run will verify against the binary you personally reviewed.

```bash
# Developer machine — first install
./oss-verify.sh --tool trufflehog --version 3.95.3 \
  --lock-dir ./lockfiles

# Commit the lockfile
git add lockfiles/trufflehog-3.95.3-linux-amd64.lock
git commit -m "pin trufflehog 3.95.3"

# CI — uses the committed lockfile
./oss-verify.sh --tool trufflehog --version 3.95.3 \
  --lock-dir ./lockfiles
```

Or via environment variable:

```bash
export OSS_VERIFY_LOCK_DIR="$(pwd)/lockfiles"
./oss-verify.sh --tool trufflehog --version 3.95.3
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

## Adding a new tool

Add a block to the `register_tools()` function in `oss-verify.sh`:

```bash
# ── mytool (Pattern A: direct bundle) ─────────────────────────────────────────
TOOL_DESCRIPTION[mytool]="My tool description"
TOOL_PATTERN[mytool]="direct_bundle"
TOOL_URL[mytool]="https://github.com/org/mytool/releases/download/v{VERSION}/mytool_{VERSION}_{OS}_{ARCH}.tar.gz"
TOOL_BUNDLE_SUFFIX[mytool]=".sigstore.json"
TOOL_BINARY_NAME[mytool]="mytool"
TOOL_BINARY_IN_ARCHIVE[mytool]="mytool"
TOOL_IDENTITY_REGEXP[mytool]='https://github\.com/org/mytool/\.github/workflows/.+'
TOOL_OIDC_ISSUER[mytool]="https://token.actions.githubusercontent.com"
```

To find the correct `TOOL_IDENTITY_REGEXP`, inspect the signing certificate from a known-good release:

```bash
# From a .pem file
openssl x509 -in checksums.txt.pem -noout -text | grep URI

# From a .sigstore.json bundle
jq -r '.verificationMaterial.certificate.rawBytes' bundle.sigstore.json \
  | base64 -d | openssl x509 -noout -text | grep URI
```

---

## What cosign actually checks

When cosign verifies a blob it confirms:

1. The cryptographic signature over the file is valid
2. The signing certificate was issued by Fulcio (Sigstore's CA) to a GitHub Actions OIDC identity
3. The certificate identity matches the workflow URL you specified
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
