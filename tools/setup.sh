#!/usr/bin/env bash
# One-time setup for a session or a CI job: host packages, then the Rust
# targets. Safe to run again; it skips what is already in place.
#
# Cloud sessions run as root without sudo; CI runners need sudo.
# Set SETUP_FORCE_BUILD_STD=1 to exercise the build-std fallback.
set -euo pipefail

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

PACKAGES=(qemu-system-x86 ovmf qemu-utils mtools dosfstools gdisk gdb)
have_tools() {
  for t in qemu-system-x86_64 qemu-img sgdisk mkfs.fat mcopy gdb; do
    command -v "$t" >/dev/null || return 1
  done
  [ -e /usr/share/ovmf/OVMF.fd ] || [ -e /usr/share/OVMF/OVMF.fd ]
}
if have_tools; then
  echo "setup: host packages already installed"
else
  echo "setup: installing ${PACKAGES[*]}"
  # The package lists may be empty on a fresh image; refresh them only if the
  # first attempt fails.
  if ! $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${PACKAGES[@]}" >/dev/null 2>&1; then
    $SUDO apt-get update -qq
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${PACKAGES[@]}" >/dev/null
  fi
fi

TARGETS=(x86_64-unknown-none x86_64-unknown-uefi)
if [ "${SETUP_FORCE_BUILD_STD:-0}" != 1 ] && timeout 180 rustup target add "${TARGETS[@]}"; then
  echo "setup: prebuilt Rust targets installed"
else
  # rustup cannot always reach static.rust-lang.org from the cloud box. Fetch
  # the library source for the installed rustc from GitHub instead; xtask
  # then builds core with build-std (see .cargo/build-std.toml).
  V=$(rustc --version | awk '{print $2}')
  SRC="$(rustc --print sysroot)/lib/rustlib/src/rust"
  if [ -e "$SRC/library/Cargo.lock" ]; then
    echo "setup: Rust $V library source already present"
  else
    echo "setup: fetching Rust $V library source from GitHub for build-std"
    CACHE="$HOME/.cache/rust-src-$V"
    rm -rf "$CACHE"
    git -c advice.detachedHead=false clone -q --depth 1 --filter=blob:none --sparse --branch "$V" \
      https://github.com/rust-lang/rust "$CACHE"
    git -C "$CACHE" sparse-checkout set library
    mkdir -p "$SRC" && ln -sfn "$CACHE/library" "$SRC/library"
  fi
fi

# Lints run in every session; failing to add them is not fatal.
rustup component add clippy rustfmt >/dev/null 2>&1 || echo "setup: could not add clippy/rustfmt"

echo "setup: done ($(rustc --version), $(qemu-system-x86_64 --version | head -1))"
