# oss-verify

A supply chain verification script for OSS tools. Downloads, cryptographically verifies, and installs binaries — with no GitHub login required.

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

Adding support for a new tool is a five-step process. Take your time on steps 1 and 2 — getting the signing pattern and identity wrong means verification silently passes when it shouldn't.

### Step 1 — Find out if the tool uses cosign

Go to the tool's GitHub releases page and look at the assets for a recent release. You are looking for any of:

| File pattern | Means |
|---|---|
| `<binary>.sigstore.json` | Pattern A — direct bundle |
| `checksums.txt` + `checksums.txt.pem` + `checksums.txt.sig` | Pattern B — checksums + cert/sig |
| `checksums.txt` + `checksums.txt.sigstore.json` | Pattern C — checksums + bundle |
| `checksums.txt` only, no signing files | Pattern D — no cosign |

If none of these match, check the tool's README or INSTALL docs — some tools use different naming conventions.

### Step 2 — Find the signing identity

The identity is the GitHub Actions workflow URL that cosign will accept. Getting this wrong is a security issue — too broad and you accept signatures from any workflow in the repo; too narrow and legitimate releases fail verification.

**From a `.pem` file (Pattern B):**

```bash
# Download the .pem from the releases page, then:
openssl x509 -in checksums.txt.pem -noout -text | grep URI
```

Look for a line like:
```
URI:https://github.com/org/tool/.github/workflows/release.yaml@refs/tags/v1.2.3
```

**From a `.sigstore.json` bundle (Pattern A or C):**

```bash
jq -r '.verificationMaterial.certificate.rawBytes' bundle.sigstore.json \
  | base64 -d | openssl x509 -noout -text | grep URI
```

**Decide: exact identity or regexp?**

- Use an **exact identity** (`TOOL_IDENTITY_EXACT`) when the workflow file is always the same and includes the version tag, e.g.:
  `https://github.com/org/tool/.github/workflows/release.yaml@refs/tags/v{VERSION}`

- Use a **regexp identity** (`TOOL_IDENTITY_REGEXP`) when the workflow path varies or you want to accept any workflow under `.github/workflows/`, e.g.:
  `https://github\.com/org/tool/\.github/workflows/.+`

The regexp is more permissive. Prefer the exact identity where possible — it pins to a specific workflow file, making it harder for an attacker who only compromises one workflow to pass verification.

### Step 3 — Build the URL template

Look at the download URL for the binary on the releases page. Replace the version, OS, and arch with template variables:

```
# Actual URL:
https://github.com/org/tool/releases/download/v1.2.3/tool_1.2.3_linux_amd64.tar.gz

# Template:
https://github.com/org/tool/releases/download/v{VERSION}/tool_{VERSION}_{OS}_{ARCH}.tar.gz
```

The script resolves `{VERSION}`, `{OS}` (linux/darwin), and `{ARCH}` (amd64/arm64) automatically.

Check that the tool uses the same naming on macOS — some use `darwin`, some use `macos`. If naming differs by platform you may need to add a custom resolution case in `resolve_url()`.

### Step 4 — Add the profile block

Add a block to the `register_tools()` function in `oss-verify.sh`. Choose the template that matches your pattern:

**Pattern A — direct bundle:**
```bash
TOOL_DESCRIPTION[mytool]="Short description of what mytool does"
TOOL_PATTERN[mytool]="direct_bundle"
TOOL_URL[mytool]="https://github.com/org/mytool/releases/download/v{VERSION}/mytool_{VERSION}_{OS}_{ARCH}.tar.gz"
TOOL_BUNDLE_SUFFIX[mytool]=".sigstore.json"
TOOL_BINARY_NAME[mytool]="mytool"
TOOL_BINARY_IN_ARCHIVE[mytool]="mytool"        # filename inside the tarball
TOOL_IDENTITY_REGEXP[mytool]='https://github\.com/org/mytool/\.github/workflows/.+'
TOOL_OIDC_ISSUER[mytool]="https://token.actions.githubusercontent.com"
```

**Pattern B — checksums + cert/sig:**
```bash
TOOL_DESCRIPTION[mytool]="Short description of what mytool does"
TOOL_PATTERN[mytool]="checksum_certsig"
TOOL_URL[mytool]="https://github.com/org/mytool/releases/download/v{VERSION}/mytool_{VERSION}_{OS}_{ARCH}.tar.gz"
TOOL_CHECKSUMS_URL[mytool]="https://github.com/org/mytool/releases/download/v{VERSION}/mytool_{VERSION}_checksums.txt"
TOOL_CERT_SUFFIX[mytool]=".pem"
TOOL_SIG_SUFFIX[mytool]=".sig"
TOOL_BINARY_NAME[mytool]="mytool"
TOOL_BINARY_IN_ARCHIVE[mytool]="mytool"
TOOL_IDENTITY_REGEXP[mytool]='https://github\.com/org/mytool/\.github/workflows/.+'
TOOL_OIDC_ISSUER[mytool]="https://token.actions.githubusercontent.com"
```

**Pattern C — checksums + bundle:**
```bash
TOOL_DESCRIPTION[mytool]="Short description of what mytool does"
TOOL_PATTERN[mytool]="checksum_bundle"
TOOL_URL[mytool]="https://github.com/org/mytool/releases/download/v{VERSION}/mytool_{VERSION}_{OS}_{ARCH}.tar.gz"
TOOL_CHECKSUMS_URL[mytool]="https://github.com/org/mytool/releases/download/v{VERSION}/mytool_{VERSION}_checksums.txt"
TOOL_BUNDLE_SUFFIX[mytool]=".sigstore.json"
TOOL_BINARY_NAME[mytool]="mytool"
TOOL_BINARY_IN_ARCHIVE[mytool]="mytool"
TOOL_IDENTITY_REGEXP[mytool]='https://github\.com/org/mytool/\.github/workflows/.+'
TOOL_OIDC_ISSUER[mytool]="https://token.actions.githubusercontent.com"
```

**Pattern D — checksums only (no cosign):**
```bash
TOOL_DESCRIPTION[mytool]="Short description of what mytool does"
TOOL_PATTERN[mytool]="checksum_only"
TOOL_URL[mytool]="https://github.com/org/mytool/releases/download/v{VERSION}/mytool_{VERSION}_{OS}_{ARCH}.tar.gz"
TOOL_CHECKSUMS_URL[mytool]="https://github.com/org/mytool/releases/download/v{VERSION}/mytool_{VERSION}_checksums.txt"
TOOL_BINARY_NAME[mytool]="mytool"
TOOL_BINARY_IN_ARCHIVE[mytool]="mytool"
```

**If the binary is not inside a tarball** (raw binary download, like cosign itself), set `TOOL_BINARY_IN_ARCHIVE` to empty:
```bash
TOOL_BINARY_IN_ARCHIVE[mytool]=""
```

**If the tool uses an exact identity** (version-pinned workflow URL), use `TOOL_IDENTITY_EXACT` instead of `TOOL_IDENTITY_REGEXP`:
```bash
TOOL_IDENTITY_EXACT[mytool]="https://github.com/org/mytool/.github/workflows/release.yaml@refs/tags/v{VERSION}"
```

### Step 5 — Test it

Always test against a known-good version before relying on it:

```bash
# Verify only first — don't install until you're confident
./oss-verify.sh --tool mytool --version 1.2.3 --no-install

# Check the lockfile was written correctly
cat ~/.local/share/oss-verify/mytool-1.2.3-linux-amd64.lock

# Run again to confirm lockfile comparison passes
./oss-verify.sh --tool mytool --version 1.2.3 --no-install

# Test that a tampered binary is rejected
# (copy the lockfile, change the binary hash manually, confirm abort)

# Install for real
./oss-verify.sh --tool mytool --version 1.2.3
```

Also verify that cosign would have caught a bad identity by temporarily changing `TOOL_IDENTITY_REGEXP` to something that won't match and confirming it fails.

### Common issues

**Download 404** — the URL template doesn't match the actual release filename. Check the releases page carefully; some tools use `Linux` (capital L), `x86_64` instead of `amd64`, or different separators.

**cosign identity mismatch** — the identity you extracted from the cert doesn't match what you put in the profile. Re-run the `openssl` command above and copy the URI exactly.

**sha256sum fails** — the checksums file uses a different format or only covers some platforms. Open the file and check whether the binary filename is listed. Some tools only include certain platforms in their checksums.

**Binary not found in archive** — after `tar -xzf`, the binary might be in a subdirectory or have a different name. Run `tar -tzf <tarball>` to list the archive contents and update `TOOL_BINARY_IN_ARCHIVE` accordingly.

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
