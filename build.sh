#!/bin/bash
# Builds the installable ZIP in dist/. Moodle needs the files inside a folder named after the plugin.
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
release="$(sed -n "s/^\$plugin->release = '\(.*\)';/\1/p" "$root/version.php")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/mailhealth" "$root/dist"
tar -C "$root" \
    --exclude=./dist --exclude=./docs --exclude=./.git --exclude=./.github \
    --exclude=./.gitignore --exclude=./build.sh \
    -cf - . | tar -xf - -C "$work/mailhealth"

rm -f "$root/dist/tool_mailhealth-$release.zip"
(cd "$work" && zip -qr "$root/dist/tool_mailhealth-$release.zip" mailhealth)
echo "$root/dist/tool_mailhealth-$release.zip"
