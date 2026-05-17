#!/bin/sh
# shtum installer — downloads the latest macOS release tarball,
# verifies SHA256 against the release's published SHA256SUMS, and
# drops the binary on $PATH.
#
# Quick install:
#
#   curl -fsSL https://raw.githubusercontent.com/gididaf/shtum/main/install.sh | sh
#
# Environment overrides:
#
#   SHTUM_VERSION   pin a specific release tag, e.g. SHTUM_VERSION=v0.3.0
#                   (default: "latest" — resolved at install time)
#   INSTALL_DIR     where to drop the binary
#                   (default: /usr/local/bin; falls back to sudo when not writable)
#
# Source: https://github.com/gididaf/shtum

set -eu

REPO="gididaf/shtum"
VERSION="${SHTUM_VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

log() { printf '[shtum installer] %s\n' "$*" >&2; }
die() { printf '[shtum installer] error: %s\n' "$*" >&2; exit 1; }

# -- Platform check ---------------------------------------------------
[ "$(uname -s)" = "Darwin" ] || die "shtum is macOS only (uname -s = $(uname -s))"

arch="$(uname -m)"
case "$arch" in
  arm64)  target="aarch64-apple-darwin" ;;
  x86_64) target="x86_64-apple-darwin" ;;
  *) die "unsupported architecture: $arch (need arm64 or x86_64)" ;;
esac

# -- Resolve URL base + tag name -------------------------------------
if [ "$VERSION" = "latest" ]; then
  url_base="https://github.com/${REPO}/releases/latest/download"
  # Resolve the actual tag once by following the /latest redirect so the
  # download filename matches.
  resolved="$(
    curl -fsSL -o /dev/null -w '%{url_effective}\n' \
      "https://github.com/${REPO}/releases/latest" \
      | sed 's#.*/tag/##'
  )"
  [ -n "$resolved" ] || die "could not resolve latest release tag"
  tag="$resolved"
else
  case "$VERSION" in
    v*) tag="$VERSION" ;;
    *)  tag="v$VERSION" ;;
  esac
  url_base="https://github.com/${REPO}/releases/download/${tag}"
fi
log "installing shtum ${tag} (${target})"

# -- Download + verify -----------------------------------------------
tmp_dir="$(mktemp -d -t shtum-installer.XXXXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT

tarball="shtum-${tag}-${target}.tar.gz"

log "fetching ${tarball}"
curl -fsSL --proto '=https' --tlsv1.2 -o "${tmp_dir}/${tarball}" \
  "${url_base}/${tarball}" \
  || die "download failed: ${url_base}/${tarball}"

log "fetching SHA256SUMS"
curl -fsSL --proto '=https' --tlsv1.2 -o "${tmp_dir}/SHA256SUMS" \
  "${url_base}/SHA256SUMS" \
  || die "download failed: ${url_base}/SHA256SUMS"

log "verifying SHA256"
( cd "$tmp_dir" && shasum -a 256 -c SHA256SUMS --ignore-missing ) \
  || die "SHA256 verification failed"

# -- Extract ----------------------------------------------------------
( cd "$tmp_dir" && tar xzf "$tarball" )
extracted="${tmp_dir}/shtum-${tag}-${target}"
[ -f "${extracted}/shtum" ] || die "binary not found at ${extracted}/shtum"

# Strip Gatekeeper quarantine before move so users don't hit a
# "cannot be verified" prompt on first launch. Harmless if no
# quarantine attribute is set.
xattr -dr com.apple.quarantine "${extracted}/shtum" 2>/dev/null || true

# -- Install ----------------------------------------------------------
target_path="${INSTALL_DIR}/shtum"

# Make sure the install dir exists. If not and the parent isn't
# writable, escalate via sudo.
if [ ! -d "$INSTALL_DIR" ]; then
  log "creating ${INSTALL_DIR}"
  if mkdir -p "$INSTALL_DIR" 2>/dev/null; then
    :
  else
    sudo mkdir -p "$INSTALL_DIR" || die "failed to create $INSTALL_DIR"
  fi
fi

if [ -w "$INSTALL_DIR" ]; then
  mv "${extracted}/shtum" "$target_path"
else
  log "writing to ${INSTALL_DIR} requires sudo"
  sudo mv "${extracted}/shtum" "$target_path"
fi
chmod +x "$target_path" 2>/dev/null || sudo chmod +x "$target_path"

# -- Done -------------------------------------------------------------
log "installed: $("$target_path" --version)"
log "location:  $target_path"

# Heads-up if it's not on PATH.
case ":$PATH:" in
  *":${INSTALL_DIR}:"*) ;;
  *) log "note: ${INSTALL_DIR} is not on your PATH; add it to your shell rc to run \`shtum\` directly" ;;
esac
