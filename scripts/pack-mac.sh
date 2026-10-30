#!/bin/sh
# From tTerm.app, signed (sign-mac.sh): the disk image people download,
# tTerm.dmg, with Applications beside tTerm to drag it to; and the app for
# updates, tTerm.app.tar.gz, tTerm.app alone, without the Mac's own
# metadata (no ._ files that would break its signature). Each is checked
# as the person's Mac will meet it: the archive unpacked, its signature
# whole, its program saying the version (what an app before it asks before
# it puts it in place: the engine's update.rs).
#
#   sh scripts/pack-mac.sh APP OUT [VERSION]
set -eu
app=$1
out=$2
version=${3:-}
mkdir -p "$out"

stage=$(mktemp -d)
ditto "$app" "$stage/tTerm.app"
ln -s /Applications "$stage/Applications"
# hdiutil is known to fail now and then on the build's Macs (Resource
# busy): a few tries.
made=0
for attempt in 1 2 3; do
  if hdiutil create -volname tTerm -srcfolder "$stage" -ov -format UDZO "$out/tTerm.dmg"; then
    made=1
    break
  fi
  echo "hdiutil create failed (try $attempt)" >&2
  sleep 5
done
[ "$made" = 1 ] || exit 1
rm -rf "$stage"

COPYFILE_DISABLE=1 tar --no-mac-metadata -czf "$out/tTerm.app.tar.gz" -C "$(dirname "$app")" "$(basename "$app")"
check=$(mktemp -d)
tar -xzf "$out/tTerm.app.tar.gz" -C "$check"
[ "$(ls -A "$check")" = "tTerm.app" ] || { echo "tTerm.app.tar.gz holds more than tTerm.app: $(ls -A "$check")" >&2; exit 1; }
codesign --verify --strict --deep --verbose=2 "$check/tTerm.app"
said=$("$check/tTerm.app/Contents/MacOS/tterm" --version)
echo "tTerm.app.tar.gz: tTerm $said"
if [ -n "$version" ] && [ "$said" != "$version" ]; then
  echo "The app says it is $said, not $version" >&2
  exit 1
fi
rm -rf "$check"

mounted=$(mktemp -d)
hdiutil attach -nobrowse -readonly -mountpoint "$mounted" "$out/tTerm.dmg" >/dev/null
codesign --verify --strict --deep "$mounted/tTerm.app"
[ "$(readlink "$mounted/Applications")" = /Applications ]
hdiutil detach "$mounted" >/dev/null || { sleep 3; hdiutil detach -force "$mounted" >/dev/null; }
rmdir "$mounted" 2>/dev/null || true
ls -la "$out"
