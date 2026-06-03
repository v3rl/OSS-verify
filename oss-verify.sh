#!/usr/bin/env bash
# oss-verify.sh — Auto-detecting supply chain verification for any OSS tool on GitHub

# ── Bash version ──────────────────────────────────────────────────────────────
# mapfile and associative arrays require bash 4+.
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

# ── Usage ─────────────────────────────────────────────────────────────────────
# Defined before dependency checks so --help works even without cosign/jq installed.
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

# Handle --help before anything else
for arg in "$@"; do
  [[ "$arg" == "--help" || "$arg" == "-h" ]] && { usage; exit 0; }
done

# ── Output helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
abort() { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }
step()  { echo -e "${CYAN}[STEP]${NC}  $*"; }
debug() { [[ "${VERBOSE:-0}" == "1" ]] && echo -e "       $*" || true; }

# ── Dependency checks ─────────────────────────────────────────────────────────
MISSING_DEPS=()
for cmd in curl jq cosign openssl; do
  command -v "$cmd" &>/dev/null || MISSING_DEPS+=("$cmd")
done

# sha256sum (Linux/GNU) vs shasum (macOS); also detect busybox sha256sum
# which lacks --ignore-missing
SHA256_TOOL="" SHA256_IGNORE_MISSING=0
if command -v sha256sum &>/dev/null; then
  SHA256_TOOL="sha256sum"
  sha256sum --ignore-missing /dev/null &>/dev/null && SHA256_IGNORE_MISSING=1
elif command -v shasum &>/dev/null; then
  SHA256_TOOL="shasum"
else
  MISSING_DEPS+=("sha256sum or shasum")
fi

[[ ${#MISSING_DEPS[@]} -gt 0 ]] \
  && abort "Missing required tools: ${MISSING_DEPS[*]}\n        Install them and re-run."

# FIX #6: validate $HOME is set before using it in default paths
[[ -z "${HOME:-}" ]] \
  && abort "\$HOME is not set. Cannot determine default paths.\n        Set HOME or use --lock-dir and --install-dir explicitly."

# ── Helper functions ──────────────────────────────────────────────────────────

# base64 decode — tries -d (Linux) then -D (macOS); returns empty string on failure
base64_decode() {
  local input="${1:-}" output=""
  [[ -z "$input" ]] && { echo ""; return 0; }
  output=$(printf '%s' "$input" | base64 -d 2>/dev/null) \
    || output=$(printf '%s' "$input" | base64 -D 2>/dev/null) \
    || true
  echo "${output:-}"
}

# SHA256 of a single file — validates result is 64 hex chars before returning
# FIX #7: return value validated so empty/failed hash is caught immediately
file_sha256() {
  local file="$1" hash=""
  if [[ "$SHA256_TOOL" == "sha256sum" ]]; then
    hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
  else
    hash=$(shasum -a 256 "$file" 2>/dev/null | awk '{print $1}')
  fi
  if ! [[ "$hash" =~ ^[0-9a-fA-F]{64}$ ]]; then
    abort "Could not compute SHA256 of '$file'.\n        File may be unreadable or the hash tool failed."
  fi
  echo "$hash"
}

# Verify a binary against a checksums file — presence-confirmed, anchored match
verify_checksums() {
  local checksums_file="$1" binary_file="$2"
  local binary_basename; binary_basename=$(basename "$binary_file")

  # Confirm the binary filename is actually listed before trusting --ignore-missing
  # (sha256sum --ignore-missing exits 0 even when the file is not mentioned at all)
  if ! grep -qF "$binary_basename" "$checksums_file" 2>/dev/null; then
    warn "Binary '$binary_basename' not found in checksums file."
    warn "Available entries:"
    awk '{print "    "$2}' "$checksums_file" >&2
    return 1
  fi

  # Approach 1: sha256sum --ignore-missing (GNU coreutils)
  if [[ "$SHA256_TOOL" == "sha256sum" && "$SHA256_IGNORE_MISSING" -eq 1 ]]; then
    sha256sum --ignore-missing -c "$checksums_file" &>/dev/null && return 0
  fi

  # Approach 2: shasum (macOS)
  if [[ "$SHA256_TOOL" == "shasum" ]]; then
    shasum -a 256 --ignore-missing -c "$checksums_file" &>/dev/null && return 0
  fi

  # Approach 3: manual anchored grep — 'go' must not match 'golang'
  local expected_hash
  expected_hash=$(grep -E "(^|[[:space:]])${binary_basename}([[:space:]]|$)" \
    "$checksums_file" | awk '{print $1}' | head -1)

  if [[ -z "$expected_hash" ]]; then
    warn "Could not extract hash for '$binary_basename' from checksums file."
    return 1
  fi
  if ! [[ "$expected_hash" =~ ^[0-9a-fA-F]{64}$ ]]; then
    abort "Value for '$binary_basename' in checksums file is not a valid SHA256 hash:\n        '$expected_hash'"
  fi

  local actual_hash; actual_hash=$(file_sha256 "$binary_file")
  if [[ "$actual_hash" == "$expected_hash" ]]; then return 0; fi

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
# OSS_VERIFY_LOCK_DIR is accepted from the environment but validated below
LOCK_DIR="${OSS_VERIFY_LOCK_DIR:-${HOME}/.local/share/oss-verify}"
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
    --no-install)  NO_INSTALL=1;  shift ;;
    --dry-run)     DRY_RUN=1;    shift ;;
    --verbose)     VERBOSE=1;    shift ;;
    --help|-h)     usage; exit 0 ;;
    *) abort "Unknown argument: $1\n        Run --help for usage." ;;
  esac
done

# ── Input validation ──────────────────────────────────────────────────────────
[[ -z "$REPO" ]] && abort "--repo is required.\n        Example: --repo aquasecurity/trivy"

if [[ -z "$VERSION" ]]; then
  echo -e "${RED}[FAIL]${NC}  --version is required. Auto-fetching latest is disabled by design." >&2
  echo         "        Check https://github.com/${REPO}/releases and pin an explicit version." >&2
  exit 1
fi

[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
  || abort "Invalid --repo format: '$REPO'\n        Expected: owner/repo (e.g. aquasecurity/trivy)"

VERSION="${VERSION#v}"   # strip leading v if supplied (v0.70.0 → 0.70.0)
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([._-][a-zA-Z0-9]+)*$ ]] \
  || abort "Invalid --version format: '$VERSION'\n        Expected: x.y.z (e.g. 0.70.0)"

if [[ -n "$BINARY_NAME" ]]; then
  [[ "$BINARY_NAME" =~ ^[A-Za-z0-9_.-]+$ ]] \
    || abort "Invalid --binary name: '$BINARY_NAME'\n        Use alphanumeric characters, hyphens, underscores, or dots only."
fi

REPO_NAME="${REPO##*/}"

# Path validation — must be absolute, no .., not inside a system directory
# Checks by prefix so /etc/cron.d is caught as well as /etc itself
validate_path() {
  local label="$1" path="$2"
  [[ "$path" == /* ]] \
    || abort "$label must be an absolute path, got: '$path'"
  [[ "$path" == *..* ]] \
    && abort "$label must not contain '..', got: '$path'"
  for forbidden in / /etc /usr /bin /sbin /boot /sys /proc /dev /root; do
    if [[ "$path" == "$forbidden" || "$path" == "${forbidden}/"* ]]; then
      abort "$label cannot be inside system directory '$forbidden', got: '$path'\n\
        Use a path under your home directory instead."
    fi
  done
}
validate_path "--lock-dir"    "$LOCK_DIR"
validate_path "--install-dir" "$INSTALL_DIR"

# ── FIX #3: check INSTALL_DIR is writable before doing any work ───────────────
# mkdir -p succeeds even on a non-writable existing directory; we check explicitly
mkdir -p "$INSTALL_DIR" 2>/dev/null || true
if [[ ! -w "$INSTALL_DIR" ]]; then
  abort "Install directory is not writable: $INSTALL_DIR\n\
        Either create it with write permission or use --install-dir to choose another path."
fi

# ── Platform detection ────────────────────────────────────────────────────────
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

# ── Network helpers ───────────────────────────────────────────────────────────
# Both functions enforce HTTPS and restrict CDN redirects to HTTPS destinations.
# --location is required because GitHub release asset URLs redirect to
# objects.githubusercontent.com for the actual file content.

# For API calls and signing files — 1MB cap prevents DoS via huge response
api_curl() {
  curl -sf --proto "=https" --location --proto-redir "=https" --max-filesize 1048576 "$@"
}

# For binary/archive downloads — no size cap (tools can be 100MB+)
binary_curl() {
  curl -sf --proto "=https" --location --proto-redir "=https" "$@"
}

# ── GitHub API — fetch release assets ────────────────────────────────────────
step "Fetching release asset list from GitHub API..."

API_URL="https://api.github.com/repos/${REPO}/releases/tags/v${VERSION}"
CURL_ERR=$(mktemp)
RELEASE_JSON=$(api_curl "$API_URL" 2>"$CURL_ERR") || {
  CURL_MSG=$(cat "$CURL_ERR"); rm -f "$CURL_ERR"
  abort "Could not fetch release info for v${VERSION}.\n\
        URL: https://github.com/${REPO}/releases/tag/v${VERSION}\n\
        curl error: ${CURL_MSG:-unknown}\n\
        Check the repo name and version are correct."
}
rm -f "$CURL_ERR"

# FIX #1: validate the API response is a JSON object with an assets key
# before using it — catches "Not Found", rate-limit responses, and malformed JSON
if ! printf '%s' "$RELEASE_JSON" | jq -e 'type == "object" and has("assets")' &>/dev/null; then
  API_MSG=$(printf '%s' "$RELEASE_JSON" | jq -r '.message // empty' 2>/dev/null || true)
  abort "GitHub API returned an unexpected response for v${VERSION}.\n\
        ${API_MSG:+API message: $API_MSG\n        }URL: https://github.com/${REPO}/releases/tag/v${VERSION}\n\
        Check the version exists and the repo is public."
fi

ASSET_COUNT=$(printf '%s' "$RELEASE_JSON" | jq '.assets | length')
[[ "$ASSET_COUNT" -eq 0 ]] \
  && abort "Release v${VERSION} exists but has no assets.\n\
        Check https://github.com/${REPO}/releases/tag/v${VERSION}"

mapfile -t ASSET_NAMES < <(printf '%s' "$RELEASE_JSON" | jq -r '.assets[].name')
mapfile -t ASSET_URLS  < <(printf '%s' "$RELEASE_JSON" | jq -r '.assets[].browser_download_url')

debug "Found ${#ASSET_NAMES[@]} assets"
if [[ "$VERBOSE" == "1" ]]; then
  for name in "${ASSET_NAMES[@]}"; do debug "  asset: $name"; done
fi

# Validate all asset URLs are genuine GitHub URLs before storing
for url in "${ASSET_URLS[@]}"; do
  [[ "$url" =~ ^https://github\.com/ || "$url" =~ ^https://objects\.githubusercontent\.com/ ]] \
    || abort "Unexpected asset URL in API response (not from github.com):\n        $url"
done

# ── Asset lookup functions ────────────────────────────────────────────────────
# Use the most restrictive match possible to avoid false positives.
# Literal == for exact names; glob suffix for suffix matches;
# regexp only for binary detection where structural patterns are needed.

# Exact filename match
find_asset_url_literal() {
  local target="$1"
  for i in "${!ASSET_NAMES[@]}"; do
    [[ "${ASSET_NAMES[$i]}" == "$target" ]] && { echo "${ASSET_URLS[$i]}"; return 0; }
  done
  return 1
}

# Exact filename + known suffix (e.g. binary.sigstore.json)
find_asset_url_suffix() {
  local prefix="$1" suffix="$2"
  find_asset_url_literal "${prefix}${suffix}"
}

# Structural regexp — patterns are built from validated internal inputs only,
# never from raw API data, to prevent backtracking or injection
find_asset_url_regexp() {
  local pattern="$1"
  for i in "${!ASSET_NAMES[@]}"; do
    echo "${ASSET_NAMES[$i]}" | grep -qE "$pattern" && { echo "${ASSET_URLS[$i]}"; return 0; }
  done
  return 1
}

# Substring match (grep -F, no regexp)
find_asset_url_contains() {
  local substring="$1"
  for i in "${!ASSET_NAMES[@]}"; do
    echo "${ASSET_NAMES[$i]}" | grep -qF "$substring" && { echo "${ASSET_URLS[$i]}"; return 0; }
  done
  return 1
}

# Glob suffix match — prevents foo_checksums.txt.sig matching suffix _checksums.txt
find_asset_url_endswith() {
  local suffix="$1"
  for i in "${!ASSET_NAMES[@]}"; do
    [[ "${ASSET_NAMES[$i]}" == *"${suffix}" ]] && { echo "${ASSET_URLS[$i]}"; return 0; }
  done
  return 1
}

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

BINARY_URL="" BINARY_FILENAME="" BINARY_EXT="" IS_RAW_BINARY=0 DETECTED_BINARY_NAME=""

# try_match: attempt to find a binary archive matching a specific naming convention.
# All patterns are built from validated inputs — never from raw API data.
try_match() {
  local name_hint="$1" os_label="$2" arch_label="$3" ext="$4"
  local url ext_esc="${ext//./\\.}"

  url=$(find_asset_url_regexp "^${name_hint}[_.-][^/]*${os_label}[_.-]${arch_label}[^/]*\\.${ext_esc}$") \
    && { BINARY_URL="$url"; debug "Matched (os_arch): ${url##*/}"; return 0; }
  url=$(find_asset_url_regexp "^${name_hint}[_.-][^/]*${arch_label}[_.-]${os_label}[^/]*\\.${ext_esc}$") \
    && { BINARY_URL="$url"; debug "Matched (arch_os): ${url##*/}"; return 0; }
  url=$(find_asset_url_regexp "^${name_hint}-[0-9][^/]*-${os_label}-${arch_label}[^/]*\\.${ext_esc}$") \
    && { BINARY_URL="$url"; debug "Matched (dash os_arch): ${url##*/}"; return 0; }
  url=$(find_asset_url_regexp "^${name_hint}-[0-9][^/]*-${arch_label}-${os_label}[^/]*\\.${ext_esc}$") \
    && { BINARY_URL="$url"; debug "Matched (dash arch_os): ${url##*/}"; return 0; }
  url=$(find_asset_url_regexp "^${name_hint}[_.-]${os_label}[_.-]${arch_label}\\.${ext_esc}$") \
    && { BINARY_URL="$url"; debug "Matched (no version os_arch): ${url##*/}"; return 0; }
  url=$(find_asset_url_regexp "^${name_hint}[_.-]${arch_label}[_.-]${os_label}\\.${ext_esc}$") \
    && { BINARY_URL="$url"; debug "Matched (no version arch_os): ${url##*/}"; return 0; }
  return 1
}

# Try every combination of binary name candidate, OS label, arch label, extension
outer_break=0
for binary_candidate in "${BINARY_CANDIDATES[@]}"; do
  for os_label in "${OS_LABELS[@]}"; do
    for arch_label in "${ARCH_LABELS[@]}"; do
      for ext in "${EXTENSIONS[@]}"; do
        if try_match "$binary_candidate" "$os_label" "$arch_label" "$ext"; then
          BINARY_FILENAME="${BINARY_URL##*/}"; BINARY_EXT="$ext"
          DETECTED_BINARY_NAME="$binary_candidate"; outer_break=1; break
        fi
      done
      [[ "$outer_break" -eq 1 ]] && break
    done
    [[ "$outer_break" -eq 1 ]] && break
  done
  [[ "$outer_break" -eq 1 ]] && break
done

# Fallback: raw binary (no archive), e.g. cosign-linux-amd64
if [[ -z "$BINARY_URL" ]]; then
  debug "No archive found — trying raw binary patterns"
  for binary_candidate in "${BINARY_CANDIDATES[@]}"; do
    for os_label in "${OS_LABELS[@]}"; do
      for arch_label in "${ARCH_LABELS[@]}"; do
        for sep in "-" "_" "."; do
          url=$(find_asset_url_regexp "^${binary_candidate}[_.-]${os_label}${sep}${arch_label}$") \
            && { BINARY_URL="$url"; BINARY_FILENAME="${url##*/}"
                 DETECTED_BINARY_NAME="$binary_candidate"; IS_RAW_BINARY=1
                 debug "Matched raw binary: $BINARY_FILENAME"; break 4; }
          url=$(find_asset_url_regexp "^${binary_candidate}[_.-]${arch_label}${sep}${os_label}$") \
            && { BINARY_URL="$url"; BINARY_FILENAME="${url##*/}"
                 DETECTED_BINARY_NAME="$binary_candidate"; IS_RAW_BINARY=1
                 debug "Matched raw binary (arch-os): $BINARY_FILENAME"; break 4; }
        done
      done
    done
  done
fi

[[ -z "$BINARY_URL" ]] && abort \
  "Could not find a binary asset for ${OS}/${ARCH} in release v${VERSION}.\n\
        Tips:\n\
          • Run with --verbose to see all available assets\n\
          • If the binary name differs from the repo name, use --binary <name>\n\
        Available assets:\n$(printf '          %s\n' "${ASSET_NAMES[@]}")"

BINARY_NAME="${BINARY_NAME:-${DETECTED_BINARY_NAME:-$REPO_NAME}}"
info "Binary:  $BINARY_FILENAME"
info "Name:    $BINARY_NAME"

# ── Signing pattern detection ─────────────────────────────────────────────────
# Uses exact/suffix/endswith matching against API data — no regexp on untrusted input
step "Detecting signing pattern..."

PATTERN="" BUNDLE_URL="" CHECKSUMS_URL="" CHECKSUMS_FILENAME=""
CHECKSUMS_PEM_URL="" CHECKSUMS_SIG_URL="" CHECKSUMS_BUNDLE_URL=""

# Pattern A: sigstore bundle attached directly to binary
for bundle_suffix in ".sigstore.json" ".sigstore" ".bundle" ".jsonl"; do
  url=$(find_asset_url_suffix "$BINARY_FILENAME" "$bundle_suffix") && {
    BUNDLE_URL="$url"; PATTERN="direct_bundle"
    debug "Pattern A: ${url##*/}"; break
  }
done

# Pattern B/C: checksums file + signing material
if [[ -z "$PATTERN" ]]; then
  for checksums_name in "checksums.txt" "sha256sums.txt" "SHA256SUMS" "checksums" "sha256sums"; do
    url=$(find_asset_url_literal "$checksums_name") && {
      CHECKSUMS_URL="$url"; CHECKSUMS_FILENAME="$checksums_name"
      debug "Checksums (exact): $checksums_name"; break
    }
    # Versioned prefix e.g. trivy_0.70.0_checksums.txt
    # endswith prevents checksums.txt.sig from matching _checksums.txt
    url=$(find_asset_url_endswith "_${checksums_name}") && {
      CHECKSUMS_URL="$url"; CHECKSUMS_FILENAME="${url##*/}"
      debug "Checksums (versioned): $CHECKSUMS_FILENAME"; break
    }
  done

  if [[ -n "$CHECKSUMS_URL" ]]; then
    PEM_URL="" SIG_URL=""

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
  "Could not detect a signing pattern for this release.\n\
        No sigstore bundle, checksums, or signature files were found.\n\
        Run with --verbose to see all available assets."

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

# ── Working directory ─────────────────────────────────────────────────────────
WORKDIR=$(mktemp -d)
chmod 700 "$WORKDIR"
trap 'rm -rf "$WORKDIR"' EXIT

# FIX #8: cd into WORKDIR and abort clearly on failure
# Without this, a failed cd would leave relative paths broken while set -e exits
cd "$WORKDIR" || abort "Failed to enter working directory: $WORKDIR"

mkdir -p "$LOCK_DIR"
chmod 700 "$LOCK_DIR"

# ── Download helpers ──────────────────────────────────────────────────────────
# Both validate the URL is a genuine GitHub URL before downloading

assert_github_url() {
  local url="$1"
  [[ "$url" =~ ^https://github\.com/ || "$url" =~ ^https://objects\.githubusercontent\.com/ ]] \
    || abort "Refusing to download from unexpected URL (not from github.com):\n        $url"
}

# Signing files: certs, checksums, bundles — 1MB cap
download_signing_file() {
  local url="$1" dest="$2" label="${3:-${url##*/}}"
  info "Downloading $label ..."
  assert_github_url "$url"
  api_curl "$url" -o "$dest" \
    || abort "Failed to download: $label\n        URL: $url"
  [[ -s "$dest" ]] || abort "Downloaded file is empty: $label\n        URL: $url"
}

# Binary/archive downloads — no size cap
download_binary() {
  local url="$1" dest="$2" label="${3:-${url##*/}}"
  info "Downloading $label ..."
  assert_github_url "$url"
  binary_curl "$url" -o "$dest" \
    || abort "Failed to download: $label\n        URL: $url"
  [[ -s "$dest" ]] || abort "Downloaded binary is empty: $label\n        URL: $url"
}

# ── Identity extraction ───────────────────────────────────────────────────────
# Extracts the GitHub Actions workflow URI from a signing cert or bundle.
# Tries multiple strategies to handle different cert formats in the wild.
# Aborts if the identity cannot be extracted — no fallback to a broad regexp.

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
    # Strategy 1: standard X.509 PEM — works for most tools
    san=$(openssl x509 -in "$file" -noout -text 2>/dev/null \
      | grep -A2 "Subject Alternative Name" \
      | grep -oE 'URI:[^,]+' | sed 's/URI://' | tr -d ' ' | head -1) || true

    # Strategy 2: certificate chain — try each cert block individually
    if [[ -z "$san" ]]; then
      local cert_block=""
      while IFS= read -r line; do
        cert_block+="${line}"$'\n'
        if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
          local candidate
          candidate=$(printf '%s' "$cert_block" | openssl x509 -noout -text 2>/dev/null \
            | grep -A2 "Subject Alternative Name" \
            | grep -oE 'URI:[^,]+' | sed 's/URI://' | tr -d ' ' | head -1) || true
          [[ -n "$candidate" ]] && { san="$candidate"; break; }
          cert_block=""
        fi
      done < "$file"
    fi

    # Strategy 3: base64-encoded PEM (e.g. Grype)
    # The entire file content is base64(-----BEGIN CERTIFICATE-----...END-----)
    if [[ -z "$san" ]]; then
      local b64_content decoded_pem
      b64_content=$(tr -d '[:space:]' < "$file")
      decoded_pem=$(base64_decode "$b64_content") || true
      if [[ -n "$decoded_pem" ]]; then
        san=$(printf '%s' "$decoded_pem" \
          | openssl x509 -noout -text 2>/dev/null \
          | grep -A2 "Subject Alternative Name" \
          | grep -oE 'URI:[^,]+' | sed 's/URI://' | tr -d ' ' | head -1) || true
        if [[ -z "$san" ]]; then
          local cert_block2=""
          while IFS= read -r line; do
            cert_block2+="${line}"$'\n'
            if [[ "$line" == "-----END CERTIFICATE-----" ]]; then
              local candidate2
              candidate2=$(printf '%s' "$cert_block2" | openssl x509 -noout -text 2>/dev/null \
                | grep -A2 "Subject Alternative Name" \
                | grep -oE 'URI:[^,]+' | sed 's/URI://' | tr -d ' ' | head -1) || true
              [[ -n "$candidate2" ]] && { san="$candidate2"; break; }
              cert_block2=""
            fi
          done <<< "$decoded_pem"
        fi
      fi
    fi

    # Strategy 4: file is actually a Sigstore JSON bundle with a .pem extension
    if [[ -z "$san" ]]; then
      local raw_bytes=""
      raw_bytes=$(jq -r '.verificationMaterial.certificate.rawBytes // empty' "$file" 2>/dev/null) || true
      [[ -z "$raw_bytes" ]] && \
        raw_bytes=$(jq -r '.verificationMaterial.x509CertificateChain.certificates[0].rawBytes // empty' \
          "$file" 2>/dev/null) || true
      if [[ -n "$raw_bytes" ]]; then
        local decoded2; decoded2=$(base64_decode "$raw_bytes")
        [[ -n "$decoded2" ]] || abort "base64 decoding of certificate bytes produced empty output — bundle may be corrupt."
        san=$(printf '%s' "$decoded2" \
          | openssl x509 -noout -text 2>/dev/null \
          | grep -A2 "Subject Alternative Name" \
          | grep -oE 'URI:[^,]+' | sed 's/URI://' | tr -d ' ' | head -1) || true
      fi
    fi

  elif [[ "$file_type" == "bundle" ]]; then
    local raw_bytes=""
    raw_bytes=$(jq -r '.verificationMaterial.certificate.rawBytes // empty' "$file" 2>/dev/null) || true
    [[ -z "$raw_bytes" ]] && \
      raw_bytes=$(jq -r '.verificationMaterial.x509CertificateChain.certificates[0].rawBytes // empty' \
        "$file" 2>/dev/null) || true
    [[ -z "$raw_bytes" ]] && \
      raw_bytes=$(jq -r '.cert // empty' "$file" 2>/dev/null) || true

    if [[ -n "$raw_bytes" ]]; then
      local decoded; decoded=$(base64_decode "$raw_bytes")
      [[ -n "$decoded" ]] || abort "base64 decoding of certificate bytes produced empty output — bundle may be corrupt."
      san=$(echo "$decoded" \
        | openssl x509 -noout -text 2>/dev/null \
        | grep -A2 "Subject Alternative Name" \
        | grep -oE 'URI:[^,]+' | sed 's/URI://' | tr -d ' ' | head -1) || true
    fi
  fi

  # Show diagnostic detail in verbose mode to help identify unsupported cert formats
  if [[ -z "$san" ]]; then
    if [[ "${VERBOSE:-0}" == "1" ]]; then
      warn "File head (first 5 lines):"
      head -5 "$file" >&2 || true
      warn "openssl x509 output:"
      openssl x509 -in "$file" -noout -text 2>&1 | head -20 >&2 || true
    fi
    abort "Could not extract signing identity from $(basename "$file").\n\
        All known cert formats were tried.\n\
        Run with --verbose for diagnostic output."
  fi

  # Identity must look like a GitHub Actions workflow URL
  if ! [[ "$san" =~ ^https://github\.com/.+/\.github/workflows/.+ ]]; then
    abort "Extracted identity is not a GitHub Actions workflow URL:\n\
        Got:      '$san'\n\
        Expected: https://github.com/<owner>/<repo>/.github/workflows/<file>@refs/...\n\
        This may indicate the release was not signed by a standard GitHub Actions workflow."
  fi

  echo "$san"
}

# Strip the version-specific @refs/... suffix and escape dots for use as a regexp.
# e.g. https://github.com/org/tool/.github/workflows/release.yaml@refs/tags/v1.2.3
#   → https://github\.com/org/tool/\.github/workflows/release\.yaml
identity_to_regexp() {
  local uri="$1"
  uri="${uri%%@refs/*}"
  uri="${uri//./\\.}"
  # FIX #5: validate result is non-empty before returning
  # An empty regexp passed to cosign --certificate-identity-regexp would match anything
  [[ -z "$uri" ]] && abort "identity_to_regexp produced an empty regexp — identity was: '$1'"
  echo "$uri"
}

# ── Timestamp extraction ──────────────────────────────────────────────────────

# Extract integratedTime (Unix epoch) from a Rekor entry in a sigstore bundle
timestamp_from_bundle() {
  local file="$1" epoch=""

  epoch=$(jq -r '.verificationMaterial.tlogEntries[0].integratedTime // empty' \
    "$file" 2>/dev/null) || true
  [[ -z "$epoch" ]] && \
    epoch=$(jq -r '.[0].integratedTime // empty' "$file" 2>/dev/null) || true

  # Validate it looks like a Unix timestamp (numeric only)
  if [[ -n "$epoch" ]] && ! [[ "$epoch" =~ ^[0-9]+$ ]]; then
    warn "Unexpected timestamp format in bundle: '$epoch' — ignoring"
    epoch=""
  fi
  echo "${epoch:-}"
}

# Extract notBefore from a PEM signing certificate.
# Uses openssl x509 first, then asn1parse as a fallback for Fulcio P-384 certs
# that OpenSSL 3.0 refuses to parse via the x509 subcommand.
timestamp_from_pem() {
  local pem="$1"

  # Inner helper: given a PEM string, return the notBefore as a parseable date string
  _extract_notbefore() {
    local pem_str="$1"

    # Strategy A: standard -startdate
    local date_str
    date_str=$(printf '%s' "$pem_str" \
      | openssl x509 -noout -startdate 2>/dev/null \
      | sed 's/notBefore=//') || true
    [[ -n "$date_str" ]] && { echo "$date_str"; return 0; }

    # Strategy B: asn1parse — reads raw ASN.1 structure without chain validation
    # Safe because this is called after cosign has already verified the cert.
    # Handles UTCTIME (YYMMDDHHMMSSZ, length 13) and GENERALIZEDTIME (length 15)
    local asn1_line asn1_date
    asn1_line=$(printf '%s' "$pem_str" \
      | openssl asn1parse -inform PEM 2>/dev/null \
      | grep -E "UTCTIME|GENERALIZEDTIME" | head -1) || true
    if [[ -n "$asn1_line" ]]; then
      asn1_date="${asn1_line##*:}"
      asn1_date="${asn1_date// /}"
      if [[ ${#asn1_date} -eq 13 && "$asn1_date" =~ ^[0-9]{12}Z$ ]]; then
        local yy mm dd hh mi ss fy
        yy="${asn1_date:0:2}"; mm="${asn1_date:2:2}"; dd="${asn1_date:4:2}"
        hh="${asn1_date:6:2}"; mi="${asn1_date:8:2}"; ss="${asn1_date:10:2}"
        [[ "$yy" -lt 50 ]] && fy="20${yy}" || fy="19${yy}"
        echo "${fy}-${mm}-${dd} ${hh}:${mi}:${ss} UTC"; return 0
      elif [[ ${#asn1_date} -eq 15 && "$asn1_date" =~ ^[0-9]{14}Z$ ]]; then
        echo "${asn1_date:0:4}-${asn1_date:4:2}-${asn1_date:6:2} ${asn1_date:8:2}:${asn1_date:10:2}:${asn1_date:12:2} UTC"
        return 0
      fi
    fi
    return 1
  }

  local raw="" epoch="" decoded_pem=""

  # Try the file directly as a standard PEM certificate
  raw=$(_extract_notbefore "$(cat "$pem")") || true

  # If that failed, try decoding as base64-encoded PEM (e.g. Grype)
  if [[ -z "$raw" ]]; then
    local b64_content
    b64_content=$(tr -d '[:space:]' < "$pem")
    decoded_pem=$(base64_decode "$b64_content") || true
    [[ -n "$decoded_pem" ]] && raw=$(_extract_notbefore "$decoded_pem") || true
  fi

  [[ -z "$raw" ]] && { echo ""; return; }

  # Convert the date string to a Unix epoch — try GNU date then BSD date (macOS)
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

# Abort if the signing epoch is missing or zero — prevents meaningless lockfile entries
require_epoch() {
  local epoch="$1" context="$2"
  if [[ -z "$epoch" || "$epoch" == "0" ]]; then
    abort "Could not extract a valid signing timestamp from $context.\n\
        Aborting to avoid writing an unverifiable lockfile entry.\n\
        Run with --verbose for diagnostic detail."
  fi
}

# ── Trust cutoff ──────────────────────────────────────────────────────────────
check_cutoff() {
  local signing_epoch="$1"

  [[ -z "$TRUST_CUTOFF_DATE" ]] && {
    warn "No --cutoff set — skipping timestamp window check."
    return 0
  }

  if [[ -z "$signing_epoch" || "$signing_epoch" == "0" ]]; then
    abort "--cutoff is set but the signing timestamp could not be extracted.\n\
        Cannot enforce the cutoff without a verified timestamp."
  fi

  # Strictly YYYY-MM-DD only — prevents relative strings like "yesterday"
  [[ "$TRUST_CUTOFF_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] \
    || abort "Invalid --cutoff date: '$TRUST_CUTOFF_DATE'\n        Required format: YYYY-MM-DD (e.g. 2026-03-01)"

  local cutoff_epoch
  cutoff_epoch=$(date -u -d "$TRUST_CUTOFF_DATE" '+%s' 2>/dev/null) \
    || cutoff_epoch=$(date -u -j -f "%Y-%m-%d" "$TRUST_CUTOFF_DATE" '+%s' 2>/dev/null) \
    || abort "Invalid --cutoff date: '$TRUST_CUTOFF_DATE' is not a valid calendar date."

  [[ "$signing_epoch" -gt "$cutoff_epoch" ]] \
    && abort "Binary was signed AFTER trust cutoff ($TRUST_CUTOFF_DATE). Refusing to install."
  info "Timestamp check passed — signed before cutoff ($TRUST_CUTOFF_DATE)"
}

# ── cosign verification ───────────────────────────────────────────────────────
# Two attempts, both pinning --certificate-oidc-issuer.
# No issuer-free fallback — dropping the issuer would accept any OIDC provider.
run_cosign_verify() {
  local subject="$1" identity="$2" issuer="$3"
  shift 3
  local extra_flags=("$@")

  # FIX #5: validate identity_to_regexp produces a non-empty value
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
  # Some tools embed the version tag in the identity URI; regexp strips it
  if cosign verify-blob "$subject" \
      --certificate-identity-regexp="$regexp" \
      --certificate-oidc-issuer="$issuer" \
      "${extra_flags[@]}" 2>/dev/null; then
    info "cosign: verified OK (regexp identity)"
    return 0
  fi

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
    # Verify lockfile is owned by the current user before trusting its contents
    local lockfile_owner current_uid
    current_uid=$(id -u)
    lockfile_owner=$(stat -c '%u' "$LOCKFILE" 2>/dev/null \
      || stat -f '%u' "$LOCKFILE" 2>/dev/null \
      || echo "")
    if [[ -z "$lockfile_owner" ]]; then
      abort "Could not determine ownership of lockfile: $LOCKFILE\n\
        stat failed on this system. Cannot safely verify lockfile ownership."
    fi
    if [[ "$lockfile_owner" != "$current_uid" ]]; then
      abort "Lockfile is not owned by the current user.\n\
        Lockfile owner uid: $lockfile_owner  Your uid: $current_uid\n\
        This may indicate tampering. Remove and re-run to re-pin:\n\
        rm '$LOCKFILE'"
    fi

    info "Lockfile found — verifying pinned values..."
    local mismatch=0

    # FIX #4: use // empty consistently so missing keys return "" not "null"
    local pinned_epoch; pinned_epoch=$(jq -r '.signing_epoch // empty' "$LOCKFILE")
    local pinned_identity; pinned_identity=$(jq -r '.identity // empty' "$LOCKFILE")

    if [[ "$signing_epoch" != "$pinned_epoch" ]]; then
      warn "Signing epoch MISMATCH"
      warn "  Pinned:  $pinned_epoch"
      warn "  Current: $signing_epoch"
      mismatch=1
    fi

    # Identity check — catches a different workflow signing the same version tag
    if [[ -n "$pinned_identity" && "$identity" != "$pinned_identity" ]]; then
      warn "Signing identity MISMATCH"
      warn "  Pinned:  $pinned_identity"
      warn "  Current: $identity"
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

    [[ "$mismatch" -eq 1 ]] && abort \
      "Lockfile mismatch — downloaded files differ from the pinned first install.\n\
        Investigate before proceeding.\n\
        To re-pin after a confirmed legitimate change:\n\
          rm '$LOCKFILE' && $0 --repo $REPO --version $VERSION"
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
    warn "Lockfile written: $LOCKFILE"
    warn "Commit it to your repo to share pinned trust across your team."
  fi
}

# ── Archive extraction ────────────────────────────────────────────────────────
# Scans archive entries for path traversal BEFORE extracting anything.
# After extraction, rejects symlinks and confirms the binary path stays inside WORKDIR.
extract_binary() {
  local archive="$1" binary="$2" dest="$3"

  # List archive contents first — FIX #2: abort if listing fails (empty entries)
  local entries=""
  case "$archive" in
    *.tar.gz|*.tgz)   entries=$(tar -tzf "$archive" 2>/dev/null) ;;
    *.tar.bz2)        entries=$(tar -tjf "$archive" 2>/dev/null) ;;
    *.tar.xz)         entries=$(tar -tJf "$archive" 2>/dev/null) ;;
    *.tar.zst)
      command -v zstd &>/dev/null \
        || abort "zstd not found — required to extract $archive.\n        Install: apt/brew install zstd"
      entries=$(tar --zstd -tf "$archive" 2>/dev/null) ;;
    *.zip)
      command -v unzip &>/dev/null \
        || abort "unzip not found — required to extract $archive."
      entries=$(unzip -Z1 "$archive" 2>/dev/null) ;;
    *) abort "Unsupported archive format: $archive" ;;
  esac

  # FIX #2: empty entries means the archive could not be read — abort before extraction
  if [[ -z "$entries" ]]; then
    abort "Could not list archive contents: $archive\n\
        The archive may be corrupt, truncated, or in an unexpected format.\n\
        Path traversal check cannot be performed — refusing to extract."
  fi

  # Reject path traversal entries — covers absolute paths, .., and bare ..
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

  # Extract — try by exact name first (faster), fall back to full extraction
  # Note: --wildcards is GNU tar only; omitted for macOS portability
  case "$archive" in
    *.tar.gz|*.tgz)
      tar -xzf "$archive" "$binary" 2>/dev/null || tar -xzf "$archive" 2>/dev/null ;;
    *.tar.bz2)
      tar -xjf "$archive" "$binary" 2>/dev/null || tar -xjf "$archive" 2>/dev/null ;;
    *.tar.xz)
      tar -xJf "$archive" "$binary" 2>/dev/null || tar -xJf "$archive" 2>/dev/null ;;
    *.tar.zst)
      tar --zstd -xf "$archive" "$binary" 2>/dev/null || tar --zstd -xf "$archive" 2>/dev/null ;;
    *.zip)
      unzip -q "$archive" "$binary" 2>/dev/null || unzip -q "$archive" 2>/dev/null ;;
  esac

  # Locate the binary by exact name — reject symlinks explicitly (-not -type l)
  local found
  found=$(find . -name "$binary" -not -name "$archive" -type f -not -type l \
    2>/dev/null | head -1)

  if [[ -z "$found" ]]; then
    abort "Binary '$binary' not found as a regular file after extraction.\n\
        Archive contents (first 20):\n$(echo "$entries" | head -20)\n\
        If the binary has a different name inside the archive, use --binary <name>."
  fi

  # Confirm the resolved path stays inside WORKDIR — catches malicious symlinks
  local real_found real_workdir
  real_found=$(cd "$(dirname "$found")" && pwd -P)/$(basename "$found")
  real_workdir=$(pwd -P)
  if [[ "$real_found" != "${real_workdir}/"* ]]; then
    abort "Extracted binary path escapes the working directory.\n\
        Expected inside: $real_workdir\n\
        Resolved to:     $real_found\n\
        The archive may contain a malicious symlink."
  fi

  mv "$found" "$dest"
}

# ── Pattern handlers ──────────────────────────────────────────────────────────

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
  require_epoch "$signing_epoch" "$bundle_filename"
  local signing_date; signing_date=$(epoch_to_date "$signing_epoch")
  info "Signed at: $signing_date"
  check_cutoff "$signing_epoch"

  local binary_sha256; binary_sha256=$(file_sha256 "$BINARY_FILENAME")
  local bundle_sha256; bundle_sha256=$(file_sha256 "$bundle_filename")

  check_or_write_lockfile "$signing_epoch" "$signing_date" "$identity" \
    "binary" "$binary_sha256" "bundle" "$bundle_sha256"
}

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

  step "Step 2/2: sha256sum verify binary against signed checksums..."
  verify_checksums "$checksums_filename" "$BINARY_FILENAME" \
    || abort "SHA256 mismatch — binary does not match the signed checksums file."
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

  step "Step 2/2: sha256sum verify binary against signed checksums..."
  verify_checksums "$checksums_filename" "$BINARY_FILENAME" \
    || abort "SHA256 mismatch — binary does not match the signed checksums file."
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

run_pattern_D() {
  local checksums_filename="${CHECKSUMS_URL##*/}"
  warn "Pattern D: no cosign signing assets found for this release."
  warn "SHA256 verifies integrity only — provenance (who built it) is NOT verified."
  warn "Consider opening an issue asking the project to add cosign/sigstore support."

  [[ -n "$TRUST_CUTOFF_DATE" ]] && abort \
    "--cutoff requires a signed release with a verifiable timestamp.\n\
        Pattern D has no signing timestamp — cutoff cannot be enforced."

  download_binary       "$BINARY_URL"    "$BINARY_FILENAME"    "binary"
  download_signing_file "$CHECKSUMS_URL" "$checksums_filename" "checksums"

  verify_checksums "$checksums_filename" "$BINARY_FILENAME" \
    || abort "SHA256 mismatch — binary does not match the checksums file."
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
  *) abort "Unknown pattern: $PATTERN — this is a bug, please report it." ;;
esac

# ── Install ───────────────────────────────────────────────────────────────────
if [[ "$NO_INSTALL" -eq 1 ]]; then
  info "Verification complete. Skipping install (--no-install)."
  exit 0
fi

if [[ "$IS_RAW_BINARY" -eq 1 ]]; then
  # Validate filename has no path separators before moving
  [[ "$BINARY_FILENAME" =~ ^[A-Za-z0-9_.,+=-]+$ ]] \
    || abort "Raw binary filename contains unexpected characters: '$BINARY_FILENAME'\n\
        Expected only alphanumeric, hyphens, underscores, dots, plus, equals."
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
if [[ ":${PATH}:" != *":${INSTALL_DIR}:"* ]]; then
  echo   "  Add to your PATH:"
  echo   "  export PATH=\"${INSTALL_DIR}:\$PATH\""
  echo ""
fi
