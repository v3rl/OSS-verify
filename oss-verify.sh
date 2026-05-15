#!/usr/bin/env bash
# oss-verify.sh — Auto-detecting supply chain verification for any OSS tool on GitHub


# ── Require bash 4+ ───────────────────────────────────────────────────────────
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  for candidate in /opt/homebrew/bin/bash /usr/local/bin/bash; do
    if [[ -x "$candidate" && "$("$candidate" -c 'echo ${BASH_VERSINFO[0]}')" -ge 4 ]]; then
      exec "$candidate" "$0" "$@"
    fi
  done
  echo "[FAIL]  bash 4+ is required. On macOS: brew install bash" >&2
  exit 1
fi

set -euo pipefail

# ── Early --help exit (before dependency checks) ──────────────────────────────
# Must be defined here so --help works even when cosign/jq are not installed
usage() {
  cat << 'END_USAGE'
oss-verify — Supply chain verification for any OSS tool on GitHub

Fetches release assets, auto-detects the signing pattern, verifies with cosign,
and pins all hashes to a lockfile. Works with any public GitHub repo that signs
releases with Sigstore. No hardcoded tool list. No GitHub login required.

USAGE
  ./oss-verify.sh --repo <owner/repo> --version <x.y.z> [OPTIONS]

OPTIONS
  --repo        GitHub repo in owner/repo format (required)
                  e.g. aquasecurity/trivy
  --version     Exact version to install, e.g. 0.70.0 (required)
                  No auto-fetch by design — pin an explicit reviewed version
  --binary      Binary name if it differs from the repo name
                  e.g. --binary gh for repo cli/cli
  --cutoff      Reject if signed after this date (YYYY-MM-DD)
                  e.g. --cutoff 2026-03-18 to enforce a pre-compromise window
  --lock-dir    Lockfile directory (default: ~/.local/share/oss-verify)
                  Override with OSS_VERIFY_LOCK_DIR env var
  --install-dir Install directory (default: ~/.local/bin)
  --no-install  Verify only — download and check but do not install
  --dry-run     Print detected pattern and asset URLs then exit
  --verbose     Show detailed detection and certificate parsing steps
  --help        Show this message

SIGNING PATTERNS (auto-detected from release assets)
  A  direct_bundle    binary.sigstore.json
                        cosign verifies the tarball directly
  B  checksum_certsig checksums.txt + .pem + .sig
                        cosign verifies checksums, sha256sum verifies binary
  C  checksum_bundle  checksums.txt + .sigstore.json
                        same two-step chain, bundle format
  D  checksum_only    checksums.txt only
                        SHA256 integrity only — no provenance (warns)

EXAMPLES
  ./oss-verify.sh --repo aquasecurity/trivy --version 0.70.0
  ./oss-verify.sh --repo trufflesecurity/trufflehog --version 3.95.3
  ./oss-verify.sh --repo anchore/grype --version 0.112.0 --cutoff 2026-03-01
  ./oss-verify.sh --repo cli/cli --binary gh --version 2.49.0
  ./oss-verify.sh --repo aquasecurity/trivy --version 0.70.0 --dry-run
  ./oss-verify.sh --repo anchore/syft --version 1.19.0 --no-install

LIMITATION
  Cannot protect against an attacker with live CI credentials publishing a
  fresh signed release — cosign passes because the signature is legitimate.
  The lockfile protects re-installs of previously verified versions.
  Human process (monitoring advisories, not auto-upgrading) is the last line
  of defence. See README for the full threat model.
END_USAGE
}

for arg in "$@"; do
  [[ "$arg" == "--help" || "$arg" == "-h" ]] && { usage; exit 0; }
done

# ── Colour output ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
abort() { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }
step()  { echo -e "${CYAN}[STEP]${NC}  $*"; }
debug() { [[ "${VERBOSE}" == "1" ]] && echo -e "       $*" || true; }

# ── Dependencies ──────────────────────────────────────────────────────────────
MISSING_DEPS=()
for cmd in curl jq cosign openssl; do
  command -v "$cmd" &>/dev/null || MISSING_DEPS+=("$cmd")
done

# sha256sum vs shasum (macOS) — detect busybox sha256sum too
if command -v sha256sum &>/dev/null; then
  if sha256sum --ignore-missing /dev/null &>/dev/null; then
    SHA256_IGNORE_MISSING=1
  else
    SHA256_IGNORE_MISSING=0   # busybox
  fi
  SHA256_TOOL="sha256sum"
elif command -v shasum &>/dev/null; then
  SHA256_TOOL="shasum"
  SHA256_IGNORE_MISSING=0
else
  MISSING_DEPS+=("sha256sum or shasum")
  SHA256_TOOL=""
  SHA256_IGNORE_MISSING=0
fi

[[ ${#MISSING_DEPS[@]} -gt 0 ]] \
  && abort "Missing required tools: ${MISSING_DEPS[*]}"

# base64 decode — Linux uses -d, macOS uses -D
# Returns decoded bytes or empty string; caller must check output is non-empty
base64_decode() {
  local input="${1:-}" output=""
  [[ -z "$input" ]] && { echo ""; return 0; }
  output=$(printf '%s' "$input" | base64 -d 2>/dev/null) \
    || output=$(printf '%s' "$input" | base64 -D 2>/dev/null) \
    || true
  echo "${output:-}"
}

# sha256 of a single file — returns hex digest only
file_sha256() {
  local file="$1"
  if [[ "$SHA256_TOOL" == "sha256sum" ]]; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

# ── FIX #3 + #4 (original): anchored, presence-confirmed checksum verification ──
verify_checksums() {
  local checksums_file="$1" binary_file="$2"
  local binary_basename; binary_basename=$(basename "$binary_file")

  # FIX #3: confirm binary is actually listed in checksums before trusting
  # --ignore-missing exits 0 even when the file isn't mentioned at all
  local binary_present=0
  if grep -qF "$binary_basename" "$checksums_file" 2>/dev/null; then
    binary_present=1
  fi

  if [[ "$binary_present" -eq 0 ]]; then
    warn "Binary '$binary_basename' not found in checksums file."
    warn "Available entries:"
    awk '{print "    "$2}' "$checksums_file" >&2
    return 1
  fi

  # Approach 1: sha256sum --ignore-missing (GNU coreutils, confirmed binary present)
  if [[ "$SHA256_TOOL" == "sha256sum" && "$SHA256_IGNORE_MISSING" -eq 1 ]]; then
    if sha256sum --ignore-missing -c "$checksums_file" &>/dev/null; then
      return 0
    fi
  fi

  # Approach 2: shasum (macOS, confirmed binary present)
  if [[ "$SHA256_TOOL" == "shasum" ]]; then
    if shasum -a 256 --ignore-missing -c "$checksums_file" &>/dev/null; then
      return 0
    fi
  fi

  # Approach 3: manual anchored grep — binary_basename already confirmed present
  # FIX #4 (original): anchored so 'go' doesn't match 'golang'
  local expected_hash
  expected_hash=$(grep -E "(^|[[:space:]])${binary_basename}([[:space:]]|$)" \
    "$checksums_file" | awk '{print $1}' | head -1)

  if [[ -z "$expected_hash" ]]; then
    warn "Could not extract hash for '$binary_basename' from checksums file."
    return 1
  fi

  # Validate it looks like a sha256 hash (64 hex chars)
  if ! [[ "$expected_hash" =~ ^[0-9a-fA-F]{64}$ ]]; then
    abort "Extracted value for '$binary_basename' is not a valid SHA256 hash: '$expected_hash'"
  fi

  local actual_hash; actual_hash=$(file_sha256 "$binary_file")
  if [[ "$actual_hash" == "$expected_hash" ]]; then
    return 0
  fi

  warn "SHA256 mismatch for $binary_basename"
  warn "  Expected: $expected_hash"
  warn "  Actual:   $actual_hash"
  return 1
}

# ── Argument parsing ──────────────────────────────────────────────────────────
REPO=""
VERSION=""
BINARY_NAME=""
TRUST_CUTOFF_DATE=""
LOCK_DIR="${OSS_VERIFY_LOCK_DIR:-${HOME}/.local/share/oss-verify}"
# Note: OSS_VERIFY_LOCK_DIR is accepted from the environment here but is
# validated by validate_path below — dangerous values like /etc/cron.d are caught.
INSTALL_DIR="${HOME}/.local/bin"
NO_INSTALL=0
DRY_RUN=0
VERBOSE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      [[ $# -ge 2 ]] || abort "--repo requires a value (e.g. --repo aquasecurity/trivy)"
      REPO="$2"; shift 2 ;;
    --version)
      [[ $# -ge 2 ]] || abort "--version requires a value (e.g. --version 0.70.0)"
      VERSION="$2"; shift 2 ;;
    --binary)
      [[ $# -ge 2 ]] || abort "--binary requires a value (e.g. --binary gh)"
      BINARY_NAME="$2"; shift 2 ;;
    --cutoff)
      [[ $# -ge 2 ]] || abort "--cutoff requires a value (e.g. --cutoff 2026-03-01)"
      TRUST_CUTOFF_DATE="$2"; shift 2 ;;
    --lock-dir)
      [[ $# -ge 2 ]] || abort "--lock-dir requires a value"
      LOCK_DIR="$2"; shift 2 ;;
    --install-dir)
      [[ $# -ge 2 ]] || abort "--install-dir requires a value"
      INSTALL_DIR="$2"; shift 2 ;;
    --no-install)  NO_INSTALL=1;           shift   ;;
    --dry-run)     DRY_RUN=1;             shift   ;;
    --verbose)     VERBOSE=1;             shift   ;;
    --help|-h)
      usage; exit 0 ;;
    *) abort "Unknown argument: $1. Use --help for usage." ;;
  esac
done

# ── Validate required args ────────────────────────────────────────────────────
[[ -z "$REPO" ]] && abort "--repo is required (e.g. --repo aquasecurity/trivy)"

if [[ -z "$VERSION" ]]; then
  echo -e "${RED}[FAIL]${NC}  --version is required. Auto-fetching latest is disabled by design." >&2
  echo         "        Check https://github.com/${REPO}/releases and pin an explicit version." >&2
  exit 1
fi

[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
  || abort "Invalid --repo format. Expected owner/repo (e.g. aquasecurity/trivy)"

VERSION="${VERSION#v}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([._-][a-zA-Z0-9]+)*$ ]] \
  || abort "Invalid version format: '$VERSION'"

if [[ -n "$BINARY_NAME" ]]; then
  [[ "$BINARY_NAME" =~ ^[A-Za-z0-9_.-]+$ ]] \
    || abort "Invalid --binary name: '$BINARY_NAME'. Alphanumeric, hyphen, underscore, dot only."
fi

# FIX #2: OWNER removed — was declared but never used, dead code
REPO_NAME="${REPO##*/}"

# ── FIX #7: validate_path checks prefixes, not just exact matches ─────────────
validate_path() {
  local label="$1" path="$2"

  # Must be absolute
  [[ "$path" == /* ]] \
    || abort "$label must be an absolute path, got: '$path'"

  # Must not contain .. components
  [[ "$path" == *..* ]] \
    && abort "$label must not contain '..', got: '$path'"

  # FIX #7: prefix check — /etc/cron.d starts with /etc so is forbidden
  for forbidden in / /etc /usr /bin /sbin /boot /sys /proc /dev /root; do
    if [[ "$path" == "$forbidden" || "$path" == "${forbidden}/"* ]]; then
      abort "$label cannot be inside system directory '$forbidden', got: '$path'"
    fi
  done
}
validate_path "--lock-dir"    "$LOCK_DIR"
validate_path "--install-dir" "$INSTALL_DIR"

# ── Detect OS and architecture ────────────────────────────────────────────────
RAW_OS=$(uname -s)
RAW_ARCH=$(uname -m)

case "$RAW_OS" in
  Linux)  OS="linux"  ;;
  Darwin) OS="darwin" ;;
  *)      abort "Unsupported OS: $RAW_OS" ;;
esac

case "$RAW_ARCH" in
  x86_64)        ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  i386|i686)     ARCH="386"   ;;
  *)             abort "Unsupported architecture: $RAW_ARCH" ;;
esac

info "Repo:    $REPO"
info "Version: v${VERSION}"
info "OS/Arch: ${OS}/${ARCH}"

# ── curl helpers ──────────────────────────────────────────────────────────────
# FIX #8: separate caps for API calls (1MB) vs binary downloads (uncapped)
# Many security tool binaries are 80-150MB — the previous 10MB cap broke all downloads

# For GitHub API calls and small signing files (bundles, certs, checksums)
# FIX #2: --proto "=https" ensures protocol restriction matches binary_curl
# --location follows GitHub's CDN redirect; --proto-redir "=https" keeps it HTTPS-only
api_curl() {
  curl -sf --proto "=https" --location --proto-redir "=https" --max-filesize 1048576 "$@"
}

# For binary/archive downloads — no size cap, tools can be 100MB+
# --location follows GitHub's CDN redirect (github.com → objects.githubusercontent.com)
# --proto-redir "=https" ensures the redirect destination must be HTTPS — no downgrade
binary_curl() {
  curl -sf --proto "=https" --location --proto-redir "=https" "$@"
}

# ── Fetch release assets from GitHub API ──────────────────────────────────────
step "Fetching release asset list from GitHub API..."

API_URL="https://api.github.com/repos/${REPO}/releases/tags/v${VERSION}"
CURL_ERR=$(mktemp)
RELEASE_JSON=$(api_curl "$API_URL" 2>"$CURL_ERR") || {
  CURL_MSG=$(cat "$CURL_ERR"); rm -f "$CURL_ERR"
  abort "Could not fetch release info for v${VERSION}.\n\
        URL: https://github.com/${REPO}/releases/tag/v${VERSION}\n\
        curl error: ${CURL_MSG:-unknown}"
}
rm -f "$CURL_ERR"

ASSET_COUNT=$(printf '%s' "$RELEASE_JSON" | jq '.assets | length')
[[ "$ASSET_COUNT" -eq 0 ]] && abort "Release v${VERSION} has no assets."

mapfile -t ASSET_NAMES < <(printf '%s' "$RELEASE_JSON" | jq -r '.assets[].name')
mapfile -t ASSET_URLS  < <(printf '%s' "$RELEASE_JSON" | jq -r '.assets[].browser_download_url')

debug "Found ${#ASSET_NAMES[@]} assets"
if [[ "$VERBOSE" == "1" ]]; then
  for name in "${ASSET_NAMES[@]}"; do debug "  asset: $name"; done
fi

# Validate all asset URLs before storing — must be genuine GitHub URLs
for url in "${ASSET_URLS[@]}"; do
  [[ "$url" =~ ^https://github\.com/ || "$url" =~ ^https://objects\.githubusercontent\.com/ ]] \
    || abort "Unexpected asset URL (not from github.com): $url"
done

# ── Asset lookup ──────────────────────────────────────────────────────────────
# FIX #1: use grep -F (literal string match) when matching asset names directly
# Only fall back to -E regexp when we are building a structural pattern

# Literal match — for exact filename lookups (pattern detection)
find_asset_url_literal() {
  local target="$1"
  for i in "${!ASSET_NAMES[@]}"; do
    if [[ "${ASSET_NAMES[$i]}" == "$target" ]]; then
      echo "${ASSET_URLS[$i]}"
      return 0
    fi
  done
  return 1
}

# Suffix match — for "filename + known suffix" lookups (safe, controlled pattern)
find_asset_url_suffix() {
  local prefix="$1" suffix="$2"
  local target="${prefix}${suffix}"
  find_asset_url_literal "$target"
}

# Regexp match — only used for binary detection where structural patterns are needed
# Pattern is always built internally from validated inputs, never from raw user data
find_asset_url_regexp() {
  local pattern="$1"
  for i in "${!ASSET_NAMES[@]}"; do
    if echo "${ASSET_NAMES[$i]}" | grep -qE "$pattern"; then
      echo "${ASSET_URLS[$i]}"
      return 0
    fi
  done
  return 1
}

# Substring match — for checksums presence check (grep -F, no regexp)
find_asset_url_contains() {
  local substring="$1"
  for i in "${!ASSET_NAMES[@]}"; do
    if echo "${ASSET_NAMES[$i]}" | grep -qF "$substring"; then
      echo "${ASSET_URLS[$i]}"
      return 0
    fi
  done
  return 1
}

# FIX #3 (asset): ends-with match using glob — prevents matching foo_checksums.txt.sig
# when looking for foo_checksums.txt, since the glob requires the suffix at the exact end.
find_asset_url_endswith() {
  local suffix="$1"
  for i in "${!ASSET_NAMES[@]}"; do
    # Glob *"${suffix}" guarantees name ends exactly with suffix — no redundant inner check needed
    if [[ "${ASSET_NAMES[$i]}" == *"${suffix}" ]]; then
      echo "${ASSET_URLS[$i]}"
      return 0
    fi
  done
  return 1
}

has_asset_literal()   { find_asset_url_literal   "$1" &>/dev/null; }
has_asset_suffix()    { find_asset_url_suffix     "$1" "$2" &>/dev/null; }
has_asset_contains()  { find_asset_url_contains   "$1" &>/dev/null; }

# ── Binary asset detection ────────────────────────────────────────────────────
step "Detecting binary asset for ${OS}/${ARCH}..."

case "$OS" in
  linux)  OS_LABELS=("linux" "Linux" "LINUX") ;;
  darwin) OS_LABELS=("darwin" "Darwin" "macos" "macOS" "MacOS" "osx" "OSX" "apple") ;;
esac

case "$ARCH" in
  amd64) ARCH_LABELS=("amd64" "x86_64" "x86-64" "64bit" "64-bit" "amd-64") ;;
  arm64) ARCH_LABELS=("arm64" "aarch64" "ARM64" "arm-64") ;;
  386)   ARCH_LABELS=("386" "i386" "i686" "32bit") ;;
esac

EXTENSIONS=("tar.gz" "tgz" "tar.bz2" "tar.xz" "tar.zst" "zip")

BINARY_CANDIDATES=("$REPO_NAME")
[[ -n "$BINARY_NAME" && "$BINARY_NAME" != "$REPO_NAME" ]] \
  && BINARY_CANDIDATES=("$BINARY_NAME" "$REPO_NAME")

BINARY_URL=""
BINARY_FILENAME=""
BINARY_EXT=""
IS_RAW_BINARY=0
DETECTED_BINARY_NAME=""

# FIX #1: try_match uses find_asset_url_regexp — pattern built only from
# validated inputs (binary_candidate, os_label, arch_label, ext) — never from
# raw asset names or user data that could cause backtracking
try_match() {
  local name_hint="$1" os_label="$2" arch_label="$3" ext="$4"
  local url ext_escaped="${ext//./\\.}"

  # Pattern 1: name_version_os_arch.ext  (trivy, grype, syft)
  url=$(find_asset_url_regexp \
    "^${name_hint}[_.-][^/]*${os_label}[_.-]${arch_label}[^/]*\\.${ext_escaped}$") \
    && { BINARY_URL="$url"; debug "Matched p1: ${url##*/}"; return 0; }

  # Pattern 2: name_version_arch_os.ext
  url=$(find_asset_url_regexp \
    "^${name_hint}[_.-][^/]*${arch_label}[_.-]${os_label}[^/]*\\.${ext_escaped}$") \
    && { BINARY_URL="$url"; debug "Matched p2: ${url##*/}"; return 0; }

  # Pattern 3: name-version-os-arch.ext  (ripgrep style)
  url=$(find_asset_url_regexp \
    "^${name_hint}-[0-9][^/]*-${os_label}-${arch_label}[^/]*\\.${ext_escaped}$") \
    && { BINARY_URL="$url"; debug "Matched p3: ${url##*/}"; return 0; }

  # Pattern 4: name-version-arch-os.ext
  url=$(find_asset_url_regexp \
    "^${name_hint}-[0-9][^/]*-${arch_label}-${os_label}[^/]*\\.${ext_escaped}$") \
    && { BINARY_URL="$url"; debug "Matched p4: ${url##*/}"; return 0; }

  # Pattern 5: name_os_arch.ext  (no version — crane)
  url=$(find_asset_url_regexp \
    "^${name_hint}[_.-]${os_label}[_.-]${arch_label}\\.${ext_escaped}$") \
    && { BINARY_URL="$url"; debug "Matched p5: ${url##*/}"; return 0; }

  # Pattern 6: name_arch_os.ext
  url=$(find_asset_url_regexp \
    "^${name_hint}[_.-]${arch_label}[_.-]${os_label}\\.${ext_escaped}$") \
    && { BINARY_URL="$url"; debug "Matched p6: ${url##*/}"; return 0; }

  return 1
}

outer_break=0
for binary_candidate in "${BINARY_CANDIDATES[@]}"; do
  for os_label in "${OS_LABELS[@]}"; do
    for arch_label in "${ARCH_LABELS[@]}"; do
      for ext in "${EXTENSIONS[@]}"; do
        if try_match "$binary_candidate" "$os_label" "$arch_label" "$ext"; then
          BINARY_FILENAME="${BINARY_URL##*/}"
          BINARY_EXT="$ext"
          DETECTED_BINARY_NAME="$binary_candidate"
          outer_break=1; break
        fi
      done
      [[ "$outer_break" -eq 1 ]] && break
    done
    [[ "$outer_break" -eq 1 ]] && break
  done
  [[ "$outer_break" -eq 1 ]] && break
done

# Fallback: raw binary (no archive) — e.g. cosign-linux-amd64
if [[ -z "$BINARY_URL" ]]; then
  debug "No archive found — trying raw binary patterns"
  for binary_candidate in "${BINARY_CANDIDATES[@]}"; do
    for os_label in "${OS_LABELS[@]}"; do
      for arch_label in "${ARCH_LABELS[@]}"; do
        for sep in "-" "_" "."; do
          url=$(find_asset_url_regexp \
            "^${binary_candidate}[_.-]${os_label}${sep}${arch_label}$") \
            && { BINARY_URL="$url"; BINARY_FILENAME="${url##*/}";
                 DETECTED_BINARY_NAME="$binary_candidate"; IS_RAW_BINARY=1;
                 debug "Matched raw binary: $BINARY_FILENAME"; break 4; }
          url=$(find_asset_url_regexp \
            "^${binary_candidate}[_.-]${arch_label}${sep}${os_label}$") \
            && { BINARY_URL="$url"; BINARY_FILENAME="${url##*/}";
                 DETECTED_BINARY_NAME="$binary_candidate"; IS_RAW_BINARY=1;
                 debug "Matched raw binary (arch-os): $BINARY_FILENAME"; break 4; }
        done
      done
    done
  done
fi

[[ -z "$BINARY_URL" ]] && abort \
  "Could not find a binary asset for ${OS}/${ARCH} in release v${VERSION}.\n\
        Run with --verbose to list all available assets.\n\
        If the binary name differs from the repo name, use --binary <name>.\n\
        All assets:\n$(printf '          %s\n' "${ASSET_NAMES[@]}")"

BINARY_NAME="${BINARY_NAME:-${DETECTED_BINARY_NAME:-$REPO_NAME}}"

info "Binary:  $BINARY_FILENAME"
info "Name:    $BINARY_NAME"

# ── Signing pattern detection ─────────────────────────────────────────────────
# FIX #1: pattern detection uses find_asset_url_literal and find_asset_url_suffix
# (exact string comparisons) — no regexp against asset names from the API
step "Detecting signing pattern..."

PATTERN=""
BUNDLE_URL=""
CHECKSUMS_URL=""
CHECKSUMS_FILENAME=""
CHECKSUMS_PEM_URL=""
CHECKSUMS_SIG_URL=""
CHECKSUMS_BUNDLE_URL=""

# Pattern A: sigstore bundle attached directly to binary — literal suffix lookup
for bundle_suffix in ".sigstore.json" ".sigstore" ".bundle" ".jsonl"; do
  url=$(find_asset_url_suffix "$BINARY_FILENAME" "$bundle_suffix") && {
    BUNDLE_URL="$url"; PATTERN="direct_bundle"
    debug "Pattern A: ${url##*/}"; break
  }
done

# Pattern B/C: checksums file — use contains match (grep -F) for naming variants
if [[ -z "$PATTERN" ]]; then
  for checksums_name in \
    "checksums.txt" "sha256sums.txt" "SHA256SUMS" "checksums" "sha256sums"
  do
    # Try exact name first
    url=$(find_asset_url_literal "$checksums_name") && {
      CHECKSUMS_URL="$url"; CHECKSUMS_FILENAME="$checksums_name"
      debug "Checksums (exact): $checksums_name"; break
    }
    # Try with version prefix (e.g. trivy_0.70.0_checksums.txt)
    # Use ends-with match so checksums.txt.sig is NOT mistaken for checksums.txt
    url=$(find_asset_url_endswith "_${checksums_name}") && {
      CHECKSUMS_URL="$url"; CHECKSUMS_FILENAME="${url##*/}"
      debug "Checksums (versioned): $CHECKSUMS_FILENAME"; break
    }
  done

  if [[ -n "$CHECKSUMS_URL" ]]; then
    PEM_URL=""; SIG_URL=""

    # FIX #1: suffix lookups — exact string, no regexp
    for cert_suffix in ".pem" ".crt" ".cert"; do
      url=$(find_asset_url_suffix "$CHECKSUMS_FILENAME" "$cert_suffix") && {
        PEM_URL="$url"; debug "Cert: ${url##*/}"; break
      }
    done

    for sig_suffix in ".sig" ".signature" ".asc"; do
      url=$(find_asset_url_suffix "$CHECKSUMS_FILENAME" "$sig_suffix") && {
        SIG_URL="$url"; debug "Sig: ${url##*/}"; break
      }
    done

    if [[ -n "$PEM_URL" && -n "$SIG_URL" ]]; then
      CHECKSUMS_PEM_URL="$PEM_URL"; CHECKSUMS_SIG_URL="$SIG_URL"
      PATTERN="checksum_certsig"
    else
      for bundle_suffix in ".sigstore.json" ".sigstore" ".bundle"; do
        url=$(find_asset_url_suffix "$CHECKSUMS_FILENAME" "$bundle_suffix") && {
          CHECKSUMS_BUNDLE_URL="$url"; PATTERN="checksum_bundle"
          debug "Pattern C: ${url##*/}"; break
        }
      done
      [[ -z "$PATTERN" ]] && PATTERN="checksum_only"
    fi
  fi
fi

[[ -z "$PATTERN" ]] && abort \
  "Could not detect a signing pattern.\n\
        No sigstore bundle, checksums, or signature files found.\n\
        Run --verbose to see all assets."

info "Pattern: $PATTERN"

# ── Dry run ───────────────────────────────────────────────────────────────────
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo ""
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${CYAN}  Dry run — detected configuration${NC}"
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo "  Repo:             $REPO"
  echo "  Version:          v${VERSION}"
  echo "  OS/Arch:          ${OS}/${ARCH}"
  echo "  Pattern:          $PATTERN"
  echo "  Binary URL:       $BINARY_URL"
  [[ -n "$BUNDLE_URL" ]]           && echo "  Bundle URL:       $BUNDLE_URL"
  [[ -n "$CHECKSUMS_URL" ]]        && echo "  Checksums URL:    $CHECKSUMS_URL"
  [[ -n "$CHECKSUMS_PEM_URL" ]]    && echo "  Cert URL:         $CHECKSUMS_PEM_URL"
  [[ -n "$CHECKSUMS_SIG_URL" ]]    && echo "  Sig URL:          $CHECKSUMS_SIG_URL"
  [[ -n "$CHECKSUMS_BUNDLE_URL" ]] && echo "  Bundle URL:       $CHECKSUMS_BUNDLE_URL"
  echo "  Raw binary:       ${IS_RAW_BINARY}"
  echo ""
  echo "  All release assets:"
  for name in "${ASSET_NAMES[@]}"; do echo "    $name"; done
  echo ""
  exit 0
fi

# ── Work in temp dir ──────────────────────────────────────────────────────────
WORKDIR=$(mktemp -d)
chmod 700 "$WORKDIR"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"
mkdir -p "$LOCK_DIR"
chmod 700 "$LOCK_DIR"

# ── Download helpers ──────────────────────────────────────────────────────────
# Validate URL is a genuine GitHub URL before downloading
assert_github_url() {
  local url="$1"
  [[ "$url" =~ ^https://github\.com/ || "$url" =~ ^https://objects\.githubusercontent\.com/ ]] \
    || abort "Refusing to download from non-GitHub URL: $url"
}

# Download a signing file (bundle, cert, checksums) — capped at 1MB
download_signing_file() {
  local url="$1" dest="$2" label="${3:-${url##*/}}"
  info "Downloading $label ..."
  assert_github_url "$url"
  api_curl "$url" -o "$dest" \
    || abort "Failed to download signing file: $url"
  [[ -s "$dest" ]] || abort "Downloaded signing file is empty: $dest"
}

# FIX #8: Download a binary/archive — no size cap
download_binary() {
  local url="$1" dest="$2" label="${3:-${url##*/}}"
  info "Downloading $label ..."
  assert_github_url "$url"
  binary_curl "$url" -o "$dest" \
    || abort "Failed to download binary: $url"
  [[ -s "$dest" ]] || abort "Downloaded binary is empty: $dest"
}

# ── Extract cosign identity from cert/bundle ──────────────────────────────────
extract_identity() {
  local file="$1" file_type="${2:-auto}"

  if [[ "$file_type" == "auto" ]]; then
    case "$file" in
      *.pem|*.crt|*.cert) file_type="pem" ;;
      *.json|*.sigstore|*.bundle) file_type="bundle" ;;
      *) abort "Cannot determine file type for identity extraction: $file" ;;
    esac
  fi

  local san=""

  if [[ "$file_type" == "pem" ]]; then
    # Strategy 1: standard X.509 text output — works for most single-cert PEM files
    san=$(openssl x509 -in "$file" -noout -text 2>/dev/null \
      | grep -A2 "Subject Alternative Name" \
      | grep -oE 'URI:[^,]+' | sed 's/URI://' | tr -d ' ' | head -1) || true

    # Strategy 2: some tools ship a certificate chain — try each cert in the PEM
    if [[ -z "$san" ]]; then
      local cert_block=""
      while IFS= read -r line; do
        cert_block+="${line}"$'\n'
        if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
          local candidate
          candidate=$(printf '%s' "$cert_block" | openssl x509 -noout -text 2>/dev/null \
            | grep -A2 "Subject Alternative Name" \
            | grep -oE 'URI:[^,]+' | sed 's/URI://' | tr -d ' ' | head -1) || true
          if [[ -n "$candidate" ]]; then
            san="$candidate"
            break
          fi
          cert_block=""
        fi
      done < "$file"
    fi

    # Strategy 3: the entire PEM file is itself base64-encoded (e.g. Grype)
    # The file contains base64(-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----)
    # Decode the whole file content and then parse the resulting PEM normally
    if [[ -z "$san" ]]; then
      local b64_content decoded_pem
      b64_content=$(tr -d '[:space:]' < "$file")
      decoded_pem=$(base64_decode "$b64_content") || true
      if [[ -n "$decoded_pem" ]]; then
        # Try parsing the decoded content as a standard PEM certificate
        san=$(printf '%s' "$decoded_pem" \
          | openssl x509 -noout -text 2>/dev/null \
          | grep -A2 "Subject Alternative Name" \
          | grep -oE 'URI:[^,]+' | sed 's/URI://' | tr -d ' ' | head -1) || true
        # Also try each cert block in case it's a chain
        if [[ -z "$san" ]]; then
          local cert_block2=""
          while IFS= read -r line; do
            cert_block2+="${line}"$'\n'
            if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
              local candidate2
              candidate2=$(printf '%s' "$cert_block2" | openssl x509 -noout -text 2>/dev/null \
                | grep -A2 "Subject Alternative Name" \
                | grep -oE 'URI:[^,]+' | sed 's/URI://' | tr -d ' ' | head -1) || true
              if [[ -n "$candidate2" ]]; then
                san="$candidate2"
                break
              fi
              cert_block2=""
            fi
          done <<< "$decoded_pem"
        fi
      fi
    fi

    # Strategy 4: the .pem may actually be a Sigstore bundle JSON — try parsing as bundle
    if [[ -z "$san" ]]; then
      local raw_bytes=""
      raw_bytes=$(jq -r \
        '.verificationMaterial.certificate.rawBytes // empty' "$file" 2>/dev/null) || true
      if [[ -z "$raw_bytes" ]]; then
        raw_bytes=$(jq -r \
          '.verificationMaterial.x509CertificateChain.certificates[0].rawBytes // empty' \
          "$file" 2>/dev/null) || true
      fi
      if [[ -n "$raw_bytes" ]]; then
        local decoded2; decoded2=$(base64_decode "$raw_bytes")
        if [[ -n "$decoded2" ]]; then
          san=$(printf '%s' "$decoded2" \
            | openssl x509 -noout -text 2>/dev/null \
            | grep -A2 "Subject Alternative Name" \
            | grep -oE 'URI:[^,]+' | sed 's/URI://' | tr -d ' ' | head -1) || true
        fi
      fi
    fi

  elif [[ "$file_type" == "bundle" ]]; then
    local raw_bytes=""

    raw_bytes=$(jq -r \
      '.verificationMaterial.certificate.rawBytes // empty' "$file" 2>/dev/null) || true

    if [[ -z "$raw_bytes" ]]; then
      raw_bytes=$(jq -r \
        '.verificationMaterial.x509CertificateChain.certificates[0].rawBytes // empty' \
        "$file" 2>/dev/null) || true
    fi

    if [[ -z "$raw_bytes" ]]; then
      raw_bytes=$(jq -r '.cert // empty' "$file" 2>/dev/null) || true
    fi

    if [[ -n "$raw_bytes" ]]; then
      local decoded; decoded=$(base64_decode "$raw_bytes")
      if [[ -z "$decoded" ]]; then
        abort "base64 decoding of certificate bytes produced empty output — bundle may be corrupt."
      fi
      san=$(echo "$decoded" \
        | openssl x509 -noout -text 2>/dev/null \
        | grep -A2 "Subject Alternative Name" \
        | grep -oE 'URI:[^,]+' | sed 's/URI://' | tr -d ' ' | head -1) || true
    fi
  fi

  if [[ -z "$san" ]]; then
    # Show diagnostic info in verbose mode to help identify the file format
    if [[ "${VERBOSE}" == "1" ]]; then
      warn "PEM/bundle file head:"
      head -5 "$file" >&2 || true
      warn "openssl x509 output:"
      openssl x509 -in "$file" -noout -text 2>&1 | head -20 >&2 || true
    fi
    abort "Could not extract signing identity from $file.\n\
        Run with --verbose for diagnostic output.\n\
        Bundle format may be unsupported or file is malformed.\n\
        Do not proceed without a verified identity."
  fi

  # Validate the SAN looks like a GitHub Actions URL
  if ! [[ "$san" =~ ^https://github\.com/.+/\.github/workflows/.+ ]]; then
    abort "Extracted identity is not a GitHub Actions workflow URL:\n        '$san'\n\
        Expected: https://github.com/<owner>/<repo>/.github/workflows/<file>@refs/...\n\
        Aborting — do not proceed with an unrecognised identity."
  fi

  echo "$san"
}

identity_to_regexp() {
  local uri="$1"
  uri="${uri%%@refs/*}"
  uri="${uri//./\\.}"
  echo "$uri"
}

# ── Timestamp helpers ─────────────────────────────────────────────────────────
timestamp_from_bundle() {
  local file="$1" epoch=""

  epoch=$(jq -r \
    '.verificationMaterial.tlogEntries[0].integratedTime // empty' \
    "$file" 2>/dev/null) || true

  if [[ -z "$epoch" ]]; then
    epoch=$(jq -r '.[0].integratedTime // empty' "$file" 2>/dev/null) || true
  fi

  if [[ -n "$epoch" ]] && ! [[ "$epoch" =~ ^[0-9]+$ ]]; then
    warn "Unexpected timestamp format in bundle: '$epoch' — ignoring"
    epoch=""
  fi

  echo "${epoch:-}"
}

timestamp_from_pem() {
  local pem="$1" raw epoch="" decoded_pem=""

  # Helper: extract notBefore from a PEM string using openssl x509 or asn1parse fallback
  _extract_notbefore() {
    local pem_str="$1"

    # Strategy A: standard -startdate (works for most certs)
    local date_str
    date_str=$(printf '%s' "$pem_str" \
      | openssl x509 -noout -startdate 2>/dev/null \
      | sed 's/notBefore=//') || true
    if [[ -n "$date_str" ]]; then echo "$date_str"; return 0; fi

    # Strategy B: asn1parse — works even when Subject is empty (e.g. Grype/Fulcio certs)
    # UTCTIME format is YYMMDDHHmmSSZ — pick the first UTCTIME which is notBefore
    # FIX: use [[:space:]] not \s for POSIX sed compatibility (BSD sed on macOS)
    # FIX: also handle GENERALIZEDTIME (YYYYMMDDHHMMSSZ) for completeness
    local asn1_line asn1_date
    asn1_line=$(printf '%s' "$pem_str" \
      | openssl asn1parse -inform PEM 2>/dev/null \
      | grep -E "UTCTIME|GENERALIZEDTIME" | head -1) || true
    if [[ -n "$asn1_line" ]]; then
      # Extract the date value after the last colon
      asn1_date="${asn1_line##*:}"
      asn1_date="${asn1_date// /}"   # strip spaces
      if [[ ${#asn1_date} -eq 13 && "$asn1_date" =~ ^[0-9]{12}Z$ ]]; then
        # UTCTIME: YYMMDDHHMMSSZ
        local yy mm dd hh mi ss full_year
        yy="${asn1_date:0:2}"; mm="${asn1_date:2:2}"; dd="${asn1_date:4:2}"
        hh="${asn1_date:6:2}"; mi="${asn1_date:8:2}"; ss="${asn1_date:10:2}"
        if [[ "$yy" -lt 50 ]]; then full_year="20${yy}"; else full_year="19${yy}"; fi
        echo "${full_year}-${mm}-${dd} ${hh}:${mi}:${ss} UTC"
        return 0
      elif [[ ${#asn1_date} -eq 15 && "$asn1_date" =~ ^[0-9]{14}Z$ ]]; then
        # GENERALIZEDTIME: YYYYMMDDHHMMSSZ
        local ymd_y ymd_m ymd_d ymd_h ymd_mi ymd_s
        ymd_y="${asn1_date:0:4}"; ymd_m="${asn1_date:4:2}"; ymd_d="${asn1_date:6:2}"
        ymd_h="${asn1_date:8:2}"; ymd_mi="${asn1_date:10:2}"; ymd_s="${asn1_date:12:2}"
        echo "${ymd_y}-${ymd_m}-${ymd_d} ${ymd_h}:${ymd_mi}:${ymd_s} UTC"
        return 0
      fi
    fi

    return 1
  }

  # First try reading the file directly as a standard PEM certificate
  raw=$(_extract_notbefore "$(cat "$pem")") || true

  # If that failed, the file may be base64-encoded PEM (e.g. Grype)
  if [[ -z "$raw" ]]; then
    local b64_content
    b64_content=$(tr -d '[:space:]' < "$pem")
    decoded_pem=$(base64_decode "$b64_content") || true
    if [[ -n "$decoded_pem" ]]; then
      raw=$(_extract_notbefore "$decoded_pem") || true
    fi
  fi

  [[ -z "$raw" ]] && { echo ""; return; }

  # Convert to Unix epoch — try GNU date then BSD date
  epoch=$(date -u -d "$raw" '+%s' 2>/dev/null) \
    || epoch=$(date -u -j -f "%Y-%m-%d %H:%M:%S %Z" "$raw" '+%s' 2>/dev/null) \
    || epoch=$(date -u -j -f "%b %d %T %Y %Z" "$raw" '+%s' 2>/dev/null) \
    || true

  echo "${epoch:-}"
}

epoch_to_date() {
  local epoch="$1"
  date -u -d "@${epoch}" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null \
    || date -u -r "$epoch" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null \
    || echo "unknown (epoch: $epoch)"
}

# ── FIX #6: require a real non-zero epoch — abort if empty or zero ────────────
require_epoch() {
  local signing_epoch="$1" context="$2"
  if [[ -z "$signing_epoch" || "$signing_epoch" == "0" ]]; then
    abort "Could not extract a valid signing timestamp from $context.\n\
        A zero or missing timestamp would produce a meaningless lockfile entry.\n\
        Aborting to avoid writing unverifiable data."
  fi
}

check_cutoff() {
  local signing_epoch="$1"

  if [[ -z "$TRUST_CUTOFF_DATE" ]]; then
    warn "No --cutoff set — skipping timestamp window check."
    return 0
  fi

  if [[ -z "$signing_epoch" || "$signing_epoch" == "0" ]]; then
    abort "--cutoff was set but signing timestamp could not be extracted.\n\
        Cannot enforce cutoff without a verified timestamp. Aborting."
  fi

  # FIX #4: validate cutoff is strictly YYYY-MM-DD before passing to date -d
  # Prevents relative strings like "yesterday" or "next friday" being accepted
  [[ "$TRUST_CUTOFF_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] \
    || abort "Invalid --cutoff date '$TRUST_CUTOFF_DATE'. Must be YYYY-MM-DD (e.g. 2026-03-01)."

  # Also validate it represents a real calendar date
  local cutoff_epoch
  cutoff_epoch=$(date -u -d "$TRUST_CUTOFF_DATE" '+%s' 2>/dev/null) \
    || cutoff_epoch=$(date -u -j -f "%Y-%m-%d" "$TRUST_CUTOFF_DATE" '+%s' 2>/dev/null) \
    || abort "Invalid --cutoff date '$TRUST_CUTOFF_DATE' — not a valid calendar date."

  if [[ "$signing_epoch" -gt "$cutoff_epoch" ]]; then
    abort "Binary was signed AFTER trust cutoff ($TRUST_CUTOFF_DATE). Refusing to install."
  fi
  info "Timestamp check passed — signed before cutoff ($TRUST_CUTOFF_DATE)"
}

# ── cosign verify — two attempts, both with pinned issuer ────────────────────
run_cosign_verify() {
  local subject="$1" identity="$2" issuer="$3"
  shift 3
  local extra_flags=("$@")
  local regexp; regexp=$(identity_to_regexp "$identity")

  debug "cosign subject:           $subject"
  debug "cosign identity (exact):  $identity"
  debug "cosign identity (regexp): $regexp"
  debug "cosign issuer:            $issuer"

  # Attempt 1: exact identity + pinned issuer
  if cosign verify-blob "$subject" \
      --certificate-identity="$identity" \
      --certificate-oidc-issuer="$issuer" \
      "${extra_flags[@]}" 2>/dev/null; then
    info "cosign: verified OK (exact identity)"
    return 0
  fi

  # Attempt 2: regexp identity + pinned issuer
  # Needed when tools embed the version tag in the identity URI
  if cosign verify-blob "$subject" \
      --certificate-identity-regexp="$regexp" \
      --certificate-oidc-issuer="$issuer" \
      "${extra_flags[@]}" 2>/dev/null; then
    info "cosign: verified OK (regexp identity)"
    return 0
  fi

  # No issuer-free fallback — dropping the issuer accepts any OIDC provider
  abort "cosign verification FAILED for $(basename "$subject").\n\
        Identity tried (exact):  $identity\n\
        Identity tried (regexp): $regexp\n\
        Issuer:                  $issuer\n\
        The binary may be compromised or the signing identity has changed.\n\
        Investigate before proceeding."
}

# ── Lockfile ──────────────────────────────────────────────────────────────────
LOCKFILE="${LOCK_DIR}/${REPO_NAME}-${VERSION}-${OS}-${ARCH}.lock"

check_or_write_lockfile() {
  local signing_epoch="$1" signing_date="$2" identity="$3"
  shift 3
  local -A hashes=()
  while [[ $# -ge 2 ]]; do hashes["$1"]="$2"; shift 2; done

  if [[ -f "$LOCKFILE" ]]; then
    # FIX #3 + #5 (lockfile): verify lockfile is owned by current user before trusting it
    local lockfile_owner current_uid
    current_uid=$(id -u)   # FIX #8: capture once into variable, not inside comparison
    lockfile_owner=$(stat -c '%u' "$LOCKFILE" 2>/dev/null \
      || stat -f '%u' "$LOCKFILE" 2>/dev/null \
      || echo "")
    # FIX #3: distinguish stat failure from genuine ownership mismatch
    if [[ -z "$lockfile_owner" ]]; then
      abort "Could not determine owner of lockfile '$LOCKFILE'.\n\
        stat failed on this system. Cannot safely verify lockfile ownership."
    fi
    if [[ "$lockfile_owner" != "$current_uid" ]]; then
      abort "Lockfile is not owned by current user.\n\
        Owner uid: $lockfile_owner  Current uid: $current_uid\n\
        This could indicate tampering. Remove and re-run to re-pin:\n\
        rm '$LOCKFILE'"
    fi
    info "Lockfile found — verifying pinned values..."
    local mismatch=0
    local pinned_epoch; pinned_epoch=$(jq -r '.signing_epoch' "$LOCKFILE")

    if [[ "$signing_epoch" != "$pinned_epoch" ]]; then
      warn "Signing epoch MISMATCH  pinned=$pinned_epoch  current=$signing_epoch"
      mismatch=1
    fi

    for label in "${!hashes[@]}"; do
      local current="${hashes[$label]}"
      local pinned; pinned=$(jq -r --arg k "${label}_sha256" '.[$k] // empty' "$LOCKFILE")
      if [[ -z "$pinned" ]]; then
        warn "No pinned value for '$label' in lockfile — skipping"
        continue
      fi
      if [[ "$current" != "$pinned" ]]; then
        warn "${label} SHA256 MISMATCH"
        warn "  Pinned:  $pinned"
        warn "  Current: $current"
        mismatch=1
      fi
    done

    [[ "$mismatch" -eq 1 ]] && \
      abort "Lockfile mismatch — values differ from first install. Investigate before proceeding."
    info "Lockfile check passed"
  else
    info "First install — writing lockfile..."
    local json="{}"
    json=$(echo "$json" | jq \
      --arg repo  "$REPO"     --arg ver  "$VERSION" \
      --arg os    "$OS/$ARCH" --arg pat  "$PATTERN" \
      --arg epoch "$signing_epoch" \
      --arg date  "$signing_date" \
      --arg id    "$identity" \
      '. + {repo:$repo,version:$ver,os_arch:$os,pattern:$pat,
            signing_epoch:$epoch,signing_date:$date,identity:$id}')
    for label in "${!hashes[@]}"; do
      json=$(echo "$json" | jq \
        --arg k "${label}_sha256" --arg v "${hashes[$label]}" \
        '. + {($k): $v}')
    done
    echo "$json" | jq '.' > "$LOCKFILE"
    chmod 600 "$LOCKFILE"
    warn "Lockfile: $LOCKFILE"
    warn "Commit to your repo to share pinned trust across your team."
  fi
}

# ── FIX #4 + #5: safe archive extraction ─────────────────────────────────────
# FIX #5: scan archive for path traversal entries BEFORE extracting anything
# FIX #4: after extraction, reject symlinks — find with -not -type l
extract_binary() {
  local archive="$1" binary="$2" dest="$3"

  # FIX #5: inspect archive contents for path traversal before touching them
  local entries
  case "$archive" in
    *.tar.gz|*.tgz)   entries=$(tar -tzf "$archive" 2>/dev/null) ;;
    *.tar.bz2)        entries=$(tar -tjf "$archive" 2>/dev/null) ;;
    *.tar.xz)         entries=$(tar -tJf "$archive" 2>/dev/null) ;;
    *.tar.zst)
      command -v zstd &>/dev/null \
        || abort "zstd not found — required for $archive. Install: apt/brew install zstd"
      entries=$(tar --zstd -tf "$archive" 2>/dev/null) ;;
    *.zip)
      command -v unzip &>/dev/null \
        || abort "unzip not found — required for $archive."
      entries=$(unzip -Z1 "$archive" 2>/dev/null) ;;
    *) abort "Unsupported archive format: $archive" ;;
  esac

  # Reject any entry that starts with / or contains .. (including bare ".." directory)
  while IFS= read -r entry; do
    if [[ "$entry" == /* || \
          "$entry" == ".." || \
          "$entry" == *"/../"* || \
          "$entry" == *"/.." || \
          "$entry" == "../"* || \
          "$entry" == *"../"* ]]; then
      abort "Archive contains unsafe path: '$entry'\n\
          This archive may be malicious — refusing to extract."
    fi
  done <<< "$entries"

  # Now safe to extract
  # Note: --wildcards is GNU tar only and silently fails on macOS BSD tar.
  # Instead we try exact name first, then full extraction, and locate by find.
  case "$archive" in
    *.tar.gz|*.tgz)
      tar -xzf "$archive" "$binary" 2>/dev/null \
        || tar -xzf "$archive" 2>/dev/null ;;
    *.tar.bz2)
      tar -xjf "$archive" "$binary" 2>/dev/null \
        || tar -xjf "$archive" 2>/dev/null ;;
    *.tar.xz)
      tar -xJf "$archive" "$binary" 2>/dev/null \
        || tar -xJf "$archive" 2>/dev/null ;;
    *.tar.zst)
      tar --zstd -xf "$archive" "$binary" 2>/dev/null \
        || tar --zstd -xf "$archive" 2>/dev/null ;;
    *.zip)
      unzip -q "$archive" "$binary" 2>/dev/null \
        || unzip -q "$archive" 2>/dev/null ;;
  esac

  # FIX #4: find by exact name, explicitly exclude symlinks (-not -type l)
  # -type f alone follows symlinks on some systems; -not -type l makes it unambiguous
  local found
  found=$(find . \
    -name "$binary" \
    -not -name "$archive" \
    -type f \
    -not -type l \
    2>/dev/null | head -1)

  if [[ -z "$found" ]]; then
    abort "Binary '$binary' not found as a regular file after extraction.\n\
        Archive contents:\n$(echo "$entries" | head -20)\n\
        Use --binary to specify the correct binary name inside the archive."
  fi

  # FIX #4: confirm resolved path stays within WORKDIR — no symlink escape
  local real_found real_workdir
  real_found=$(cd "$(dirname "$found")" && pwd -P)/$(basename "$found")
  real_workdir=$(pwd -P)
  if [[ "$real_found" != "${real_workdir}/"* ]]; then
    abort "Extracted binary path escapes the working directory.\n\
        Expected prefix: $real_workdir\n\
        Resolved path:   $real_found\n\
        The archive may contain a malicious symlink. Refusing to install."
  fi

  mv "$found" "$dest"
}

# ── Pattern A ─────────────────────────────────────────────────────────────────
run_pattern_A() {
  local bundle_filename="${BUNDLE_URL##*/}"
  download_binary       "$BINARY_URL" "$BINARY_FILENAME" "binary"
  download_signing_file "$BUNDLE_URL" "$bundle_filename" "sigstore bundle"

  local identity; identity=$(extract_identity "$bundle_filename" "bundle")
  info "Identity: $identity"

  step "cosign verify-blob (Pattern A — direct bundle)..."
  run_cosign_verify "$BINARY_FILENAME" "$identity" \
    "https://token.actions.githubusercontent.com" \
    --bundle "$bundle_filename"

  local signing_epoch; signing_epoch=$(timestamp_from_bundle "$bundle_filename")
  # FIX #6: require real epoch before writing lockfile
  require_epoch "$signing_epoch" "$bundle_filename"
  local signing_date; signing_date=$(epoch_to_date "$signing_epoch")
  info "Signed at: $signing_date"
  check_cutoff "$signing_epoch"

  local binary_sha256; binary_sha256=$(file_sha256 "$BINARY_FILENAME")
  local bundle_sha256; bundle_sha256=$(file_sha256 "$bundle_filename")

  check_or_write_lockfile "$signing_epoch" "$signing_date" "$identity" \
    "binary" "$binary_sha256" "bundle" "$bundle_sha256"
}

# ── Pattern B ─────────────────────────────────────────────────────────────────
run_pattern_B() {
  local checksums_filename="${CHECKSUMS_URL##*/}"
  local pem_filename="${CHECKSUMS_PEM_URL##*/}"
  local sig_filename="${CHECKSUMS_SIG_URL##*/}"

  download_binary       "$BINARY_URL"        "$BINARY_FILENAME"    "binary"
  download_signing_file "$CHECKSUMS_URL"     "$checksums_filename" "checksums"
  download_signing_file "$CHECKSUMS_PEM_URL" "$pem_filename"       "certificate"
  download_signing_file "$CHECKSUMS_SIG_URL" "$sig_filename"       "signature"

  local identity; identity=$(extract_identity "$pem_filename" "pem")
  info "Identity: $identity"

  step "Step 1/2: cosign verify-blob on checksums (Pattern B)..."
  run_cosign_verify "$checksums_filename" "$identity" \
    "https://token.actions.githubusercontent.com" \
    --certificate "$pem_filename" \
    --signature   "$sig_filename"

  step "Step 2/2: sha256sum verify binary..."
  verify_checksums "$checksums_filename" "$BINARY_FILENAME" \
    || abort "SHA256 mismatch — binary does not match signed checksums"
  info "sha256sum: binary integrity verified OK"

  local signing_epoch; signing_epoch=$(timestamp_from_pem "$pem_filename")
  require_epoch "$signing_epoch" "$pem_filename"
  local signing_date; signing_date=$(epoch_to_date "$signing_epoch")
  info "Signed at: $signing_date"
  check_cutoff "$signing_epoch"

  local binary_sha256;    binary_sha256=$(file_sha256    "$BINARY_FILENAME")
  local checksums_sha256; checksums_sha256=$(file_sha256 "$checksums_filename")
  local cert_sha256;      cert_sha256=$(file_sha256      "$pem_filename")

  check_or_write_lockfile "$signing_epoch" "$signing_date" "$identity" \
    "binary" "$binary_sha256" "checksums" "$checksums_sha256" "cert" "$cert_sha256"
}

# ── Pattern C ─────────────────────────────────────────────────────────────────
run_pattern_C() {
  local checksums_filename="${CHECKSUMS_URL##*/}"
  local bundle_filename="${CHECKSUMS_BUNDLE_URL##*/}"

  download_binary       "$BINARY_URL"           "$BINARY_FILENAME"    "binary"
  download_signing_file "$CHECKSUMS_URL"         "$checksums_filename" "checksums"
  download_signing_file "$CHECKSUMS_BUNDLE_URL"  "$bundle_filename"    "sigstore bundle"

  local identity; identity=$(extract_identity "$bundle_filename" "bundle")
  info "Identity: $identity"

  step "Step 1/2: cosign verify-blob on checksums (Pattern C)..."
  run_cosign_verify "$checksums_filename" "$identity" \
    "https://token.actions.githubusercontent.com" \
    --bundle "$bundle_filename"

  step "Step 2/2: sha256sum verify binary..."
  verify_checksums "$checksums_filename" "$BINARY_FILENAME" \
    || abort "SHA256 mismatch — binary does not match signed checksums"
  info "sha256sum: binary integrity verified OK"

  local signing_epoch; signing_epoch=$(timestamp_from_bundle "$bundle_filename")
  require_epoch "$signing_epoch" "$bundle_filename"
  local signing_date; signing_date=$(epoch_to_date "$signing_epoch")
  info "Signed at: $signing_date"
  check_cutoff "$signing_epoch"

  local binary_sha256;    binary_sha256=$(file_sha256    "$BINARY_FILENAME")
  local checksums_sha256; checksums_sha256=$(file_sha256 "$checksums_filename")
  local bundle_sha256;    bundle_sha256=$(file_sha256    "$bundle_filename")

  check_or_write_lockfile "$signing_epoch" "$signing_date" "$identity" \
    "binary" "$binary_sha256" "checksums" "$checksums_sha256" "bundle" "$bundle_sha256"
}

# ── Pattern D ─────────────────────────────────────────────────────────────────
run_pattern_D() {
  local checksums_filename="${CHECKSUMS_URL##*/}"
  warn "Pattern D: no cosign signing assets found."
  warn "SHA256 verifies integrity only — NOT provenance (who built it)."
  warn "Consider asking the project to add cosign/sigstore support."

  if [[ -n "$TRUST_CUTOFF_DATE" ]]; then
    abort "--cutoff requires a signed release with a verifiable timestamp.\n\
        Pattern D (checksum only) has no signing timestamp."
  fi

  download_binary       "$BINARY_URL"    "$BINARY_FILENAME"    "binary"
  download_signing_file "$CHECKSUMS_URL" "$checksums_filename" "checksums"

  verify_checksums "$checksums_filename" "$BINARY_FILENAME" \
    || abort "SHA256 mismatch."
  info "sha256sum: binary integrity verified OK"

  local install_epoch; install_epoch=$(date -u +%s)
  local install_date; install_date=$(epoch_to_date "$install_epoch")
  local binary_sha256; binary_sha256=$(file_sha256 "$BINARY_FILENAME")

  check_or_write_lockfile "$install_epoch" "$install_date" "none (checksum_only)" \
    "binary" "$binary_sha256"
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
case "$PATTERN" in
  direct_bundle)    run_pattern_A ;;
  checksum_certsig) run_pattern_B ;;
  checksum_bundle)  run_pattern_C ;;
  checksum_only)    run_pattern_D ;;
  *) abort "Unknown pattern: $PATTERN" ;;
esac

# ── Install ───────────────────────────────────────────────────────────────────
if [[ "$NO_INSTALL" -eq 1 ]]; then
  info "Verification complete. Skipping install (--no-install)."
  exit 0
fi

mkdir -p "$INSTALL_DIR"

if [[ "$IS_RAW_BINARY" -eq 1 ]]; then
  # FIX #9: validate BINARY_FILENAME contains no path separators before moving
  # BINARY_NAME is validated to ^[A-Za-z0-9_.-]+$ but BINARY_FILENAME comes from the URL
  [[ "$BINARY_FILENAME" =~ ^[A-Za-z0-9_.,+=-]+$ ]] \
    || abort "Raw binary filename contains unexpected characters: '$BINARY_FILENAME'\n\
        Expected only alphanumeric, hyphen, underscore, dot, plus, equals."
  mv "${WORKDIR}/${BINARY_FILENAME}" "${INSTALL_DIR}/${BINARY_NAME}"
else
  extract_binary "$BINARY_FILENAME" "$BINARY_NAME" "${INSTALL_DIR}/${BINARY_NAME}"
fi

chmod 755 "${INSTALL_DIR}/${BINARY_NAME}"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ${BINARY_NAME} v${VERSION} installed and verified${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo   "  Repo:     $REPO"
echo   "  Binary:   ${INSTALL_DIR}/${BINARY_NAME}"
echo   "  Pattern:  $PATTERN"
echo   "  Lockfile: $LOCKFILE"
echo ""
echo   "  Ensure ${INSTALL_DIR} is in your PATH:"
echo   "  export PATH=\"\$HOME/.local/bin:\$PATH\""
echo ""
