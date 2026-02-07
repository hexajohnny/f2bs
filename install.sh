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

pick_install_dir() {
  for preferred in /usr/local/bin /usr/bin /bin; do
    case ":$PATH:" in
      *":$preferred:"*)
        if [ -d "$preferred" ] && ( [ -w "$preferred" ] || [ "$(id -u)" -eq 0 ] ); then
          printf "%s" "$preferred"
          return
        fi
        ;;
    esac
  done

  printf "%s" "$PATH" | tr ':' '\n' | while read -r dir; do
    [ -z "$dir" ] && continue
    [ -d "$dir" ] || continue
    case "$dir" in
      "$HOME"/*|"$HOME")
        continue
        ;;
    esac
    if [ -w "$dir" ] || [ "$(id -u)" -eq 0 ]; then
      printf "%s" "$dir"
      return
    fi
  done
}

install_dir=$(pick_install_dir)
if [ -z "${install_dir}" ]; then
  echo "No writable directory found on PATH for install" >&2
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

if [ "$(id -u)" -ne 0 ] && [ ! -w "$install_dir" ]; then
  sudo install -m 0755 "$tmp_dir/f2bs" "$install_dir/f2bs"
else
  install -m 0755 "$tmp_dir/f2bs" "$install_dir/f2bs"
fi

echo "Installed $install_dir/f2bs"
