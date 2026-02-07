#!/usr/bin/env sh
set -eu

REPO="hexajohnny/f2bs"
ASSET_NAME="f2bs-linux-x86_64.zip"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi
if ! command -v unzip >/dev/null 2>&1; then
  echo "unzip is required" >&2
  exit 1
fi

api_url="https://api.github.com/repos/${REPO}/releases/latest"
asset_url=$(curl -fsSL "$api_url" | \
  sed -n "s/.*\\(https:\\/\\/[^\\\"]*${ASSET_NAME}\\).*/\\1/p" | head -n 1)

if [ -z "${asset_url}" ]; then
  echo "Could not find ${ASSET_NAME} in latest release" >&2
  exit 1
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

curl -fsSL -o "$tmp_dir/${ASSET_NAME}" "$asset_url"
( cd "$tmp_dir" && unzip -q "$ASSET_NAME" )

if [ ! -f "$tmp_dir/f2bs" ]; then
  echo "Archive did not contain f2bs binary" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  sudo install -m 0755 "$tmp_dir/f2bs" /usr/local/bin/f2bs
else
  install -m 0755 "$tmp_dir/f2bs" /usr/local/bin/f2bs
fi

echo "Installed /usr/local/bin/f2bs"
