#!/usr/bin/env bash
set -euo pipefail

VERSION=8.30.1
SYSTEM=$(uname -s)
MACHINE=$(uname -m)

case "$SYSTEM/$MACHINE" in
  Linux/x86_64)
    PLATFORM=linux_x64
    SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
    ;;
  Linux/aarch64|Linux/arm64)
    PLATFORM=linux_arm64
    SHA256=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
    ;;
  Darwin/x86_64)
    PLATFORM=darwin_x64
    SHA256=dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709
    ;;
  Darwin/arm64)
    PLATFORM=darwin_arm64
    SHA256=b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5
    ;;
  *)
    printf 'unsupported Gitleaks host: %s/%s\n' "$SYSTEM" "$MACHINE" >&2
    exit 2
    ;;
esac

ARCHIVE="gitleaks_${VERSION}_${PLATFORM}.tar.gz"
TEMP_DIRECTORY=$(mktemp -d)
curl --fail --silent --show-error --location \
  "https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/${ARCHIVE}" \
  --output "$TEMP_DIRECTORY/$ARCHIVE"

if test "$SYSTEM" = "Darwin"; then
  ACTUAL_SHA256=$(shasum -a 256 "$TEMP_DIRECTORY/$ARCHIVE" | awk '{print $1}')
else
  ACTUAL_SHA256=$(sha256sum "$TEMP_DIRECTORY/$ARCHIVE" | awk '{print $1}')
fi
test "$ACTUAL_SHA256" = "$SHA256"

tar --extract --gzip --file "$TEMP_DIRECTORY/$ARCHIVE" --directory "$TEMP_DIRECTORY" gitleaks
printf '[extend]\nuseDefault = true\n' > "$TEMP_DIRECTORY/default-only.toml"
: > "$TEMP_DIRECTORY/empty.gitleaksignore"
unset GITLEAKS_CONFIG GITLEAKS_CONFIG_TOML
"$TEMP_DIRECTORY/gitleaks" git \
  --config "$TEMP_DIRECTORY/default-only.toml" \
  --gitleaks-ignore-path "$TEMP_DIRECTORY/empty.gitleaksignore" \
  --ignore-gitleaks-allow \
  --redact \
  --no-banner \
  --no-color \
  --timeout 300 \
  --log-opts='--all --text --no-textconv --no-ext-diff' \
  .
