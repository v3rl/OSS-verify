#!/usr/bin/env bash
# oss-verify.sh — Generic supply chain verification for OSS tools
# Supports cosign patterns used across major projects (no GitHub login required)
#
# Usage:
#   ./oss-verify.sh --tool <tool> --version <version> [OPTIONS]
#
# Options:
#   --tool        Tool name matching a profile in TOOL_PROFILES below (required)
#   --version     Exact version to install, e.g. 3.95.3 (required, no auto-fetch)
#   --cutoff      Reject if signed after this date, e.g. 2026-03-01 (optional)
#   --lock-dir    Override lockfile directory (default: ~/.local/share/oss-verify)
#   --install-dir Override install directory (default: ~/.local/bin)
#   --no-install  Verify only, do not install the binary
#   --list        List all supported tools and exit
#
# Examples:
#   ./oss-verify.sh --tool trufflehog --version 3.95.3
#   ./oss-verify.sh --tool trivy --version 0.70.0 --cutoff 2026-03-01
#   ./oss-verify.sh --tool cosign --version 2.4.1
#   ./oss-verify.sh --list
#
# Adding a new tool:
#   Add a block to the register_tools() function below following the pattern.
#   Each tool needs: url_template, binary_name, signing pattern, and identity.
#
# Signing patterns supported:
#   A  direct_bundle    cosign verify-blob <binary> --bundle <binary>.sigstore.json
#   B  checksum_certsig cosign verify-blob <checksums> --certificate <.pem> --signature <.sig>
#                       then sha256sum verifies the binary
#   C  checksum_bundle  cosign verify-blob <checksums> --bundle <checksums>.sigstore.json
#                       then sha256sum verifies the binary
#   D  checksum_only    No cosign — SHA256 only (warn, but allow)
#
# Lockfile pinning:
#   First install writes a lockfile pinning all hashes + signing epoch.
#   Subsequent installs of the same version compare against pinned values.
#   Set TOOL_LOCK_DIR or --lock-dir to a repo path and commit lockfiles.

set -euo pipefail

# ── Colour output ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
abort() { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }
step()  { echo -e "${CYAN}[STEP]${NC}  $*"; }

# ── Tool profile registry ─────────────────────────────────────────────────────
# Each tool is registered as a set of variables stored in associative arrays.
# Keys: pattern, url, checksums_url, bundle_suffix, cert_suffix, sig_suffix,
#       binary_name, binary_in_archive, identity_regexp, identity_exact, oidc_issuer

declare -A TOOL_PATTERN TOOL_URL TOOL_CHECKSUMS_URL TOOL_BUNDLE_SUFFIX
declare -A TOOL_CERT_SUFFIX TOOL_SIG_SUFFIX TOOL_BINARY_NAME TOOL_BINARY_IN_ARCHIVE
declare -A TOOL_IDENTITY_REGEXP TOOL_IDENTITY_EXACT TOOL_OIDC_ISSUER TOOL_DESCRIPTION

register_tools() {

  # ── TruffleHog (Pattern B: checksums + cert/sig) ───────────────────────────
  # cosign signs checksums.txt; sha256sum verifies the binary
  TOOL_DESCRIPTION[trufflehog]="Secret scanner by TruffleSecurity"
  TOOL_PATTERN[trufflehog]="checksum_certsig"
  TOOL_URL[trufflehog]="https://github.com/trufflesecurity/trufflehog/releases/download/v{VERSION}/trufflehog_{VERSION}_{OS}_{ARCH}.tar.gz"
  TOOL_CHECKSUMS_URL[trufflehog]="https://github.com/trufflesecurity/trufflehog/releases/download/v{VERSION}/trufflehog_{VERSION}_checksums.txt"
  TOOL_CERT_SUFFIX[trufflehog]=".pem"
  TOOL_SIG_SUFFIX[trufflehog]=".sig"
  TOOL_BINARY_NAME[trufflehog]="trufflehog"
  TOOL_BINARY_IN_ARCHIVE[trufflehog]="trufflehog"
  TOOL_IDENTITY_REGEXP[trufflehog]='https://github\.com/trufflesecurity/trufflehog/\.github/workflows/.+'
  TOOL_OIDC_ISSUER[trufflehog]="https://token.actions.githubusercontent.com"

  # ── Trivy (Pattern A: direct bundle on tarball) ────────────────────────────
  # cosign signs the tarball directly via .sigstore.json bundle
  TOOL_DESCRIPTION[trivy]="Vulnerability scanner by Aqua Security"
  TOOL_PATTERN[trivy]="direct_bundle"
  TOOL_URL[trivy]="https://github.com/aquasecurity/trivy/releases/download/v{VERSION}/trivy_{VERSION}_{OS}-{ARCH}.tar.gz"
  TOOL_BUNDLE_SUFFIX[trivy]=".sigstore.json"
  TOOL_BINARY_NAME[trivy]="trivy"
  TOOL_BINARY_IN_ARCHIVE[trivy]="trivy"
  TOOL_IDENTITY_EXACT[trivy]="https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v{VERSION}"
  TOOL_OIDC_ISSUER[trivy]="https://token.actions.githubusercontent.com"

  # ── cosign itself (Pattern A: direct bundle) ───────────────────────────────
  TOOL_DESCRIPTION[cosign]="Sigstore cosign signing tool"
  TOOL_PATTERN[cosign]="direct_bundle"
  TOOL_URL[cosign]="https://github.com/sigstore/cosign/releases/download/v{VERSION}/cosign-{OS}-{ARCH}"
  TOOL_BUNDLE_SUFFIX[cosign]=".sigstore.json"
  TOOL_BINARY_NAME[cosign]="cosign"
  TOOL_BINARY_IN_ARCHIVE[cosign]=""   # not a tarball, raw binary
  TOOL_IDENTITY_REGEXP[cosign]='https://github\.com/sigstore/cosign/\.github/workflows/.+'
  TOOL_OIDC_ISSUER[cosign]="https://token.actions.githubusercontent.com"

  # ── Grype (Pattern C: checksums + bundle) ─────────────────────────────────
  # cosign signs checksums.txt via bundle; sha256sum verifies the binary
  TOOL_DESCRIPTION[grype]="Vulnerability scanner by Anchore"
  TOOL_PATTERN[grype]="checksum_bundle"
  TOOL_URL[grype]="https://github.com/anchore/grype/releases/download/v{VERSION}/grype_{VERSION}_{OS}_{ARCH}.tar.gz"
  TOOL_CHECKSUMS_URL[grype]="https://github.com/anchore/grype/releases/download/v{VERSION}/grype_{VERSION}_checksums.txt"
  TOOL_BUNDLE_SUFFIX[grype]=".pem"   # grype uses .pem bundle naming — overridden below
  TOOL_BINARY_NAME[grype]="grype"
  TOOL_BINARY_IN_ARCHIVE[grype]="grype"
  TOOL_IDENTITY_REGEXP[grype]='https://github\.com/anchore/grype/\.github/workflows/.+'
  TOOL_OIDC_ISSUER[grype]="https://token.actions.githubusercontent.com"

  # ── Syft (Pattern C: checksums + bundle, same as grype) ───────────────────
  TOOL_DESCRIPTION[syft]="SBOM generator by Anchore"
  TOOL_PATTERN[syft]="checksum_bundle"
  TOOL_URL[syft]="https://github.com/anchore/syft/releases/download/v{VERSION}/syft_{VERSION}_{OS}_{ARCH}.tar.gz"
  TOOL_CHECKSUMS_URL[syft]="https://github.com/anchore/syft/releases/download/v{VERSION}/syft_{VERSION}_checksums.txt"
  TOOL_BINARY_NAME[syft]="syft"
  TOOL_BINARY_IN_ARCHIVE[syft]="syft"
  TOOL_IDENTITY_REGEXP[syft]='https://github\.com/anchore/syft/\.github/workflows/.+'
  TOOL_OIDC_ISSUER[syft]="https://token.actions.githubusercontent.com"

  # ── Crane (Pattern B: checksums + cert/sig) ───────────────────────────────
  TOOL_DESCRIPTION[crane]="OCI registry tool by Google"
  TOOL_PATTERN[crane]="checksum_certsig"
  TOOL_URL[crane]="https://github.com/google/go-containerregistry/releases/download/v{VERSION}/go-containerregistry_{OS}_{ARCH}.tar.gz"
  TOOL_CHECKSUMS_URL[crane]="https://github.com/google/go-containerregistry/releases/download/v{VERSION}/go-containerregistry_{OS}_{ARCH}.tar.gz.sha256"
  TOOL_CERT_SUFFIX[crane]=".pem"
  TOOL_SIG_SUFFIX[crane]=".sig"
  TOOL_BINARY_NAME[crane]="crane"
  TOOL_BINARY_IN_ARCHIVE[crane]="crane"
  TOOL_IDENTITY_REGEXP[crane]='https://github\.com/google/go-containerregistry/\.github/workflows/.+'
  TOOL_OIDC_ISSUER[crane]="https://token.actions.githubusercontent.com"

}

# ── OS / arch normalisation ───────────────────────────────────────────────────
# Different tools use different OS/arch label conventions.
# We expose both raw uname values and normalised forms;
# each URL template uses the naming that tool's releases actually use.

detect_platform() {
  RAW_OS=$(uname -s)
  RAW_ARCH=$(uname -m)

  case "$RAW_OS" in
    Linux)  OS_linux="linux";  OS_Linux="Linux";  OS_darwin="linux";  OS="linux"  ;;
    Darwin) OS_linux="darwin"; OS_Linux="macOS";  OS_darwin="darwin"; OS="darwin" ;;
    *)      abort "Unsupported OS: $RAW_OS" ;;
  esac

  case "$RAW_ARCH" in
    x86_64)        ARCH_amd64="amd64"; ARCH_64bit="64bit"; ARCH_x86_64="x86_64"; ARCH="amd64" ;;
    aarch64|arm64) ARCH_amd64="arm64"; ARCH_64bit="ARM64"; ARCH_x86_64="arm64";  ARCH="arm64" ;;
    *)             abort "Unsupported arch: $RAW_ARCH" ;;
  esac
}

# Replace {VERSION}, {OS}, {ARCH} in a URL template
resolve_url() {
  local template="$1" version="$2"
  local url="$template"
  url="${url//\{VERSION\}/$version}"
  url="${url//\{OS\}/$OS}"
  url="${url//\{ARCH\}/$ARCH}"

  # Trivy uses Linux/macOS capitalised and 64bit/ARM64
  url="${url//Linux-64bit/${OS_Linux}-${ARCH_64bit}}"
  url="${url//linux-amd64/${OS}-${ARCH}}"
  echo "$url"
}

# ── Argument parsing ──────────────────────────────────────────────────────────
TOOL=""
VERSION=""
TRUST_CUTOFF_DATE=""
LOCK_DIR="${OSS_VERIFY_LOCK_DIR:-${HOME}/.local/share/oss-verify}"
INSTALL_DIR="${HOME}/.local/bin"
NO_INSTALL=0
LIST_TOOLS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tool)        TOOL="$2";               shift 2 ;;
    --version)     VERSION="$2";            shift 2 ;;
    --cutoff)      TRUST_CUTOFF_DATE="$2";  shift 2 ;;
    --lock-dir)    LOCK_DIR="$2";           shift 2 ;;
    --install-dir) INSTALL_DIR="$2";        shift 2 ;;
    --no-install)  NO_INSTALL=1;            shift   ;;
    --list)        LIST_TOOLS=1;            shift   ;;
    --help|-h)
      sed -n '2,40p' "$0" | grep '^#' | sed 's/^# \?//'
      exit 0 ;;
    *) abort "Unknown argument: $1. Use --help for usage." ;;
  esac
done

register_tools
detect_platform

# ── List tools ────────────────────────────────────────────────────────────────
if [[ "$LIST_TOOLS" -eq 1 ]]; then
  echo ""
  echo -e "${CYAN}Supported tools:${NC}"
  echo ""
  for t in "${!TOOL_DESCRIPTION[@]}"; do
    printf "  %-20s %s  [pattern: %s]\n" \
      "$t" "${TOOL_DESCRIPTION[$t]}" "${TOOL_PATTERN[$t]}"
  done | sort
  echo ""
  echo "Signing patterns:"
  echo "  A  direct_bundle    cosign verifies the binary tarball directly"
  echo "  B  checksum_certsig cosign verifies checksums.txt via .pem + .sig"
  echo "  C  checksum_bundle  cosign verifies checksums.txt via .sigstore.json bundle"
  echo "  D  checksum_only    SHA256 only, no cosign (warn)"
  echo ""
  exit 0
fi

# ── Validate required args ────────────────────────────────────────────────────
[[ -z "$TOOL" ]] && abort "--tool is required. Run --list to see supported tools."

if [[ -z "${TOOL_PATTERN[$TOOL]:-}" ]]; then
  abort "Unknown tool: '$TOOL'. Run --list to see supported tools."
fi

if [[ -z "$VERSION" ]]; then
  echo -e "${RED}[FAIL]${NC}  --version is required. Auto-fetching latest is disabled by design." >&2
  echo         "" >&2
  echo         "        Installing an unreviewed 'latest' defeats supply chain pinning." >&2
  echo         "        Check the releases page and pick an explicit version." >&2
  echo         "" >&2
  echo         "        Usage: $0 --tool $TOOL --version <x.y.z> [--cutoff YYYY-MM-DD]" >&2
  exit 1
fi

VERSION="${VERSION#v}"   # strip leading v if present

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  abort "Invalid version format: '$VERSION'. Expected x.y.z (e.g. 1.2.3)"
fi

# ── Resolve tool config ───────────────────────────────────────────────────────
PATTERN="${TOOL_PATTERN[$TOOL]}"
BINARY_NAME="${TOOL_BINARY_NAME[$TOOL]}"
BINARY_IN_ARCHIVE="${TOOL_BINARY_IN_ARCHIVE[$TOOL]:-$BINARY_NAME}"
OIDC_ISSUER="${TOOL_OIDC_ISSUER[$TOOL]:-https://token.actions.githubusercontent.com}"
IDENTITY_REGEXP="${TOOL_IDENTITY_REGEXP[$TOOL]:-}"
IDENTITY_EXACT="${TOOL_IDENTITY_EXACT[$TOOL]:-}"
# Substitute version into exact identity if present
IDENTITY_EXACT="${IDENTITY_EXACT//\{VERSION\}/$VERSION}"

BINARY_URL=$(resolve_url "${TOOL_URL[$TOOL]}" "$VERSION")
BINARY_FILENAME="${BINARY_URL##*/}"

mkdir -p "$LOCK_DIR"
LOCKFILE="${LOCK_DIR}/${TOOL}-${VERSION}-${OS}-${ARCH}.lock"

info "Tool:     $TOOL v${VERSION} (${OS}/${ARCH})"
info "Pattern:  $PATTERN"

# ── Work in a temp dir ────────────────────────────────────────────────────────
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

# ── Download helper ───────────────────────────────────────────────────────────
download() {
  local url="$1" dest="$2" label="${3:-$2}"
  info "Downloading $label ..."
  curl -sL --fail "$url" -o "$dest" \
    || abort "Failed to download: $url"
}

# ── cosign identity flags ─────────────────────────────────────────────────────
cosign_identity_flags() {
  if [[ -n "$IDENTITY_EXACT" ]]; then
    echo "--certificate-identity=${IDENTITY_EXACT}"
  elif [[ -n "$IDENTITY_REGEXP" ]]; then
    echo "--certificate-identity-regexp=${IDENTITY_REGEXP}"
  else
    abort "No cosign identity configured for tool: $TOOL"
  fi
}

# ── Run cosign verify-blob ────────────────────────────────────────────────────
run_cosign_verify() {
  local subject="$1" flags=("${@:2}")
  local identity_flag
  identity_flag=$(cosign_identity_flags)

  if cosign verify-blob "$subject" \
      $identity_flag \
      --certificate-oidc-issuer="$OIDC_ISSUER" \
      "${flags[@]}" 2>/dev/null; then
    info "cosign: verified OK"
  else
    abort "cosign verification FAILED for $subject — do not use this binary"
  fi
}

# ── Extract timestamp from sigstore bundle ────────────────────────────────────
timestamp_from_bundle() {
  local bundle="$1"
  jq -r '.verificationMaterial.tlogEntries[0].integratedTime // empty' "$bundle"
}

# ── Extract timestamp from PEM certificate ────────────────────────────────────
timestamp_from_pem() {
  local pem="$1"
  local raw
  raw=$(openssl x509 -in "$pem" -noout -startdate 2>/dev/null | sed 's/notBefore=//')
  if [[ "$RAW_OS" == "Darwin" ]]; then
    date -u -j -f "%b %d %T %Y %Z" "$raw" '+%s' 2>/dev/null
  else
    date -u -d "$raw" '+%s' 2>/dev/null
  fi
}

# ── Human-readable date from epoch ────────────────────────────────────────────
epoch_to_date() {
  local epoch="$1"
  if [[ "$RAW_OS" == "Darwin" ]]; then
    date -u -r "$epoch" '+%Y-%m-%d %H:%M:%S UTC'
  else
    date -u -d "@${epoch}" '+%Y-%m-%d %H:%M:%S UTC'
  fi
}

# ── Trust cutoff check ────────────────────────────────────────────────────────
check_cutoff() {
  local signing_epoch="$1"
  if [[ -z "$TRUST_CUTOFF_DATE" ]]; then
    warn "No --cutoff date set. Skipping timestamp window check."
    warn "To enforce: add --cutoff YYYY-MM-DD"
    return
  fi

  local cutoff_epoch
  if [[ "$RAW_OS" == "Darwin" ]]; then
    cutoff_epoch=$(date -u -j -f "%Y-%m-%d" "$TRUST_CUTOFF_DATE" '+%s' 2>/dev/null) \
      || abort "Invalid --cutoff date: $TRUST_CUTOFF_DATE. Use YYYY-MM-DD."
  else
    cutoff_epoch=$(date -u -d "$TRUST_CUTOFF_DATE" '+%s' 2>/dev/null) \
      || abort "Invalid --cutoff date: $TRUST_CUTOFF_DATE. Use YYYY-MM-DD."
  fi

  if [[ "$signing_epoch" -gt "$cutoff_epoch" ]]; then
    abort "Binary was signed AFTER trust cutoff ($TRUST_CUTOFF_DATE). Refusing to install."
  else
    info "Timestamp check passed — signed before cutoff ($TRUST_CUTOFF_DATE)"
  fi
}

# ── Lockfile pinning ──────────────────────────────────────────────────────────
check_or_write_lockfile() {
  local signing_epoch="$1"
  local signing_date="$2"
  shift 2
  # Remaining args: alternating "label" "sha256" pairs to pin
  # e.g. "binary" "<hash>" "checksums" "<hash>" "cert" "<hash>"
  local -A hashes=()
  while [[ $# -ge 2 ]]; do
    hashes["$1"]="$2"; shift 2
  done

  if [[ -f "$LOCKFILE" ]]; then
    info "Lockfile found — verifying pinned values..."
    local mismatch=0

    local pinned_epoch
    pinned_epoch=$(jq -r '.signing_epoch' "$LOCKFILE")
    if [[ "$signing_epoch" != "$pinned_epoch" ]]; then
      warn "Signing epoch MISMATCH  pinned=$pinned_epoch  current=$signing_epoch"
      mismatch=1
    fi

    for label in "${!hashes[@]}"; do
      local current="${hashes[$label]}"
      local pinned
      pinned=$(jq -r ".\"${label}_sha256\"" "$LOCKFILE")
      if [[ "$current" != "$pinned" ]]; then
        warn "${label} SHA256 MISMATCH"
        warn "  Pinned:  $pinned"
        warn "  Current: $current"
        mismatch=1
      fi
    done

    [[ "$mismatch" -eq 1 ]] && abort "Lockfile mismatch — refusing to install. Investigate before proceeding."
    info "Lockfile check passed — all pinned values match"
  else
    info "First install — writing lockfile to $LOCKFILE"
    local json="{}"
    json=$(echo "$json" | jq --arg v "$VERSION"       '. + {version: $v}')
    json=$(echo "$json" | jq --arg v "$signing_epoch" '. + {signing_epoch: $v}')
    json=$(echo "$json" | jq --arg v "$signing_date"  '. + {signing_date: $v}')
    json=$(echo "$json" | jq --arg v "$PATTERN"       '. + {pattern: $v}')
    for label in "${!hashes[@]}"; do
      json=$(echo "$json" | jq --arg k "${label}_sha256" --arg v "${hashes[$label]}" \
        '. + {($k): $v}')
    done
    echo "$json" | jq '.' > "$LOCKFILE"
    warn "Commit $LOCKFILE to your repo to share pinned trust across your team."
  fi
}

# ── Pattern A: direct bundle on binary ───────────────────────────────────────
verify_direct_bundle() {
  local bundle_suffix="${TOOL_BUNDLE_SUFFIX[$TOOL]:-.sigstore.json}"
  local bundle_url="${BINARY_URL}${bundle_suffix}"
  local bundle_file="${BINARY_FILENAME}${bundle_suffix}"

  download "$BINARY_URL"  "$BINARY_FILENAME" "binary"
  download "$bundle_url"  "$bundle_file"     "sigstore bundle"

  step "cosign verify-blob (direct bundle) ..."
  run_cosign_verify "$BINARY_FILENAME" --bundle "$bundle_file"

  local signing_epoch
  signing_epoch=$(timestamp_from_bundle "$bundle_file")
  [[ -z "$signing_epoch" ]] && abort "Could not extract timestamp from bundle"
  local signing_date; signing_date=$(epoch_to_date "$signing_epoch")
  info "Signed at: $signing_date"

  check_cutoff "$signing_epoch"

  local binary_sha256; binary_sha256=$(sha256sum "$BINARY_FILENAME" | awk '{print $1}')
  local bundle_sha256; bundle_sha256=$(sha256sum "$bundle_file"      | awk '{print $1}')

  check_or_write_lockfile "$signing_epoch" "$signing_date" \
    "binary" "$binary_sha256" \
    "bundle" "$bundle_sha256"
}

# ── Pattern B: checksums + cert + sig ─────────────────────────────────────────
verify_checksum_certsig() {
  local checksums_url="${TOOL_CHECKSUMS_URL[$TOOL]}"
  checksums_url=$(resolve_url "$checksums_url" "$VERSION")
  local checksums_file="${checksums_url##*/}"
  local cert_suffix="${TOOL_CERT_SUFFIX[$TOOL]:-.pem}"
  local sig_suffix="${TOOL_SIG_SUFFIX[$TOOL]:-.sig}"
  local cert_url="${checksums_url}${cert_suffix}"
  local sig_url="${checksums_url}${sig_suffix}"
  local cert_file="${checksums_file}${cert_suffix}"
  local sig_file="${checksums_file}${sig_suffix}"

  download "$BINARY_URL"   "$BINARY_FILENAME" "binary"
  download "$checksums_url" "$checksums_file" "checksums"
  download "$cert_url"      "$cert_file"      "certificate (.pem)"
  download "$sig_url"       "$sig_file"       "signature (.sig)"

  step "Step 1/2: cosign verify-blob on checksums file ..."
  run_cosign_verify "$checksums_file" \
    --certificate "$cert_file" \
    --signature   "$sig_file"

  step "Step 2/2: sha256sum verify binary against signed checksums ..."
  if sha256sum --ignore-missing -c "$checksums_file" 2>/dev/null; then
    info "sha256sum: binary integrity verified OK"
  else
    abort "SHA256 mismatch — binary does not match signed checksums"
  fi

  local signing_epoch; signing_epoch=$(timestamp_from_pem "$cert_file")
  [[ -z "$signing_epoch" ]] && abort "Could not extract timestamp from certificate"
  local signing_date; signing_date=$(epoch_to_date "$signing_epoch")
  info "Signed at: $signing_date"

  check_cutoff "$signing_epoch"

  local binary_sha256;   binary_sha256=$(sha256sum "$BINARY_FILENAME" | awk '{print $1}')
  local checksums_sha256; checksums_sha256=$(sha256sum "$checksums_file" | awk '{print $1}')
  local cert_sha256;     cert_sha256=$(sha256sum "$cert_file" | awk '{print $1}')

  check_or_write_lockfile "$signing_epoch" "$signing_date" \
    "binary"    "$binary_sha256" \
    "checksums" "$checksums_sha256" \
    "cert"      "$cert_sha256"
}

# ── Pattern C: checksums + sigstore bundle on checksums ───────────────────────
verify_checksum_bundle() {
  local checksums_url="${TOOL_CHECKSUMS_URL[$TOOL]}"
  checksums_url=$(resolve_url "$checksums_url" "$VERSION")
  local checksums_file="${checksums_url##*/}"
  local bundle_suffix="${TOOL_BUNDLE_SUFFIX[$TOOL]:-.sigstore.json}"
  local bundle_url="${checksums_url}${bundle_suffix}"
  local bundle_file="${checksums_file}${bundle_suffix}"

  download "$BINARY_URL"    "$BINARY_FILENAME"  "binary"
  download "$checksums_url" "$checksums_file"   "checksums"
  download "$bundle_url"    "$bundle_file"      "sigstore bundle"

  step "Step 1/2: cosign verify-blob on checksums file ..."
  run_cosign_verify "$checksums_file" --bundle "$bundle_file"

  step "Step 2/2: sha256sum verify binary against signed checksums ..."
  if sha256sum --ignore-missing -c "$checksums_file" 2>/dev/null; then
    info "sha256sum: binary integrity verified OK"
  else
    abort "SHA256 mismatch — binary does not match signed checksums"
  fi

  local signing_epoch; signing_epoch=$(timestamp_from_bundle "$bundle_file")
  [[ -z "$signing_epoch" ]] && abort "Could not extract timestamp from bundle"
  local signing_date; signing_date=$(epoch_to_date "$signing_epoch")
  info "Signed at: $signing_date"

  check_cutoff "$signing_epoch"

  local binary_sha256;    binary_sha256=$(sha256sum "$BINARY_FILENAME"  | awk '{print $1}')
  local checksums_sha256;  checksums_sha256=$(sha256sum "$checksums_file" | awk '{print $1}')
  local bundle_sha256;    bundle_sha256=$(sha256sum "$bundle_file"      | awk '{print $1}')

  check_or_write_lockfile "$signing_epoch" "$signing_date" \
    "binary"    "$binary_sha256" \
    "checksums" "$checksums_sha256" \
    "bundle"    "$bundle_sha256"
}

# ── Pattern D: checksum only (no cosign) ──────────────────────────────────────
verify_checksum_only() {
  local checksums_url="${TOOL_CHECKSUMS_URL[$TOOL]}"
  checksums_url=$(resolve_url "$checksums_url" "$VERSION")
  local checksums_file="${checksums_url##*/}"

  download "$BINARY_URL"    "$BINARY_FILENAME" "binary"
  download "$checksums_url" "$checksums_file"  "checksums"

  warn "Pattern D: no cosign signing available for $TOOL — SHA256 only."
  warn "This does NOT verify provenance, only integrity."

  if sha256sum --ignore-missing -c "$checksums_file" 2>/dev/null; then
    info "sha256sum: binary integrity verified OK"
  else
    abort "SHA256 mismatch — binary does not match checksums"
  fi

  local signing_epoch; signing_epoch=$(date -u +%s)
  local signing_date; signing_date=$(epoch_to_date "$signing_epoch")
  local binary_sha256; binary_sha256=$(sha256sum "$BINARY_FILENAME" | awk '{print $1}')

  check_or_write_lockfile "$signing_epoch" "$signing_date" \
    "binary" "$binary_sha256"
}

# ── Dispatch to pattern handler ───────────────────────────────────────────────
# Check cosign is available for patterns that need it
if [[ "$PATTERN" != "checksum_only" ]]; then
  command -v cosign &>/dev/null || abort "cosign not found. Install from https://github.com/sigstore/cosign/releases"
fi
command -v curl      &>/dev/null || abort "curl not found"
command -v jq        &>/dev/null || abort "jq not found"
command -v sha256sum &>/dev/null || abort "sha256sum not found"
command -v openssl   &>/dev/null || abort "openssl not found"

case "$PATTERN" in
  direct_bundle)    verify_direct_bundle    ;;
  checksum_certsig) verify_checksum_certsig ;;
  checksum_bundle)  verify_checksum_bundle  ;;
  checksum_only)    verify_checksum_only    ;;
  *)                abort "Unknown pattern: $PATTERN" ;;
esac

# ── Install ───────────────────────────────────────────────────────────────────
if [[ "$NO_INSTALL" -eq 1 ]]; then
  info "Verification complete. Skipping install (--no-install)"
  exit 0
fi

mkdir -p "$INSTALL_DIR"

if [[ -n "$BINARY_IN_ARCHIVE" ]]; then
  # It's a tarball — extract just the binary
  info "Extracting $BINARY_NAME from archive ..."
  tar -xzf "$BINARY_FILENAME" "$BINARY_IN_ARCHIVE" 2>/dev/null \
    || tar -xzf "$BINARY_FILENAME" 2>/dev/null  # some archives have flat structure
  mv "$BINARY_IN_ARCHIVE" "${INSTALL_DIR}/${BINARY_NAME}"
else
  # Raw binary (e.g. cosign-linux-amd64)
  mv "$BINARY_FILENAME" "${INSTALL_DIR}/${BINARY_NAME}"
fi

chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ${TOOL} v${VERSION} installed and verified${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo   "  Binary:   ${INSTALL_DIR}/${BINARY_NAME}"
echo   "  Pattern:  $PATTERN"
echo   "  Lockfile: $LOCKFILE"
echo ""
echo   "  Ensure $INSTALL_DIR is in your PATH:"
echo   "  export PATH=\"\$HOME/.local/bin:\$PATH\""
echo ""
