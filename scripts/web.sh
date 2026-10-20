#!/bin/sh
# Puts the page of tTerm Web, as it is built, into web-dist: the page the
# app's window shows. It comes from tterm-web at the commit in WEB_COMMIT, so
# that every build of the app has the page it was checked with.
#
#   sh scripts/web.sh                  from GitHub, at WEB_COMMIT
#   TTERM_WEB=../tterm-web sh scripts/web.sh
#                                      from a checkout next to this one, as
#                                      it is: for a page not released yet
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
commit=$(tr -d ' \n' < "$here/WEB_COMMIT")
if [ -n "${TTERM_WEB:-}" ]; then
  src=$(cd "$TTERM_WEB" && pwd)
else
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  git clone --quiet https://github.com/tterm-net/tterm-web.git "$tmp/web"
  git -C "$tmp/web" checkout --quiet "$commit"
  src="$tmp/web"
fi
if [ ! -f "$src/web/dist/index.html" ]; then
  echo "No built page in $src/web/dist" >&2
  exit 1
fi
rm -rf "$here/web-dist"
cp -R "$src/web/dist" "$here/web-dist"
# The one change, the one tTerm Web's core makes too each time it serves the
# page (_with_nonce in tterm/api/page.py): a meta tag right after the
# charset with a one-time number for the style elements the page makes, so
# that the policy allows those and no others (web/src/styleNonce.ts). The
# core writes a fresh number in; here Tauri does, each time the window loads
# the page, in place of its placeholder.
page="$here/web-dist/index.html"
awk '
  !done && index($0, "<meta charset") {
    at = index($0, "<meta charset")
    end = index(substr($0, at), ">")
    if (end > 0) {
      cut = at + end - 1
      print substr($0, 1, cut)
      printf "    <meta name=\"tt-style-nonce\" content=\"__TAURI_STYLE_NONCE__\">%s\n", substr($0, cut + 1)
      done = 1
      next
    }
  }
  { print }
  END { if (!done) exit 1 }
' "$page" > "$page.new" || { echo "No <meta charset> in the page: the style number has nowhere to go" >&2; exit 1; }
mv "$page.new" "$page"
echo "web-dist: the page of tterm-web $(git -C "$src" rev-parse --short HEAD 2>/dev/null || echo "from $src")"
