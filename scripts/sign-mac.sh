#!/bin/sh
# Signs tTerm.app or the agent's program with tTerm's own certificate (from
# 0.5.0; the owner, 29.10: «сделать пока свой сертификат»), under a
# requirement of its own: this identifier and this certificate. macOS keeps
# what the person allowed (the folders, the keychain) for code that
# satisfies the requirement, so it holds across versions signed this way,
# where every ad hoc build was a new program to it. Gatekeeper still asks
# once about a copy downloaded with a browser: only Apple's Developer ID,
# notarised, takes that away.
#
# The certificate and its key are in the repository's secrets,
# MACOS_CERTIFICATE (base64 of a .p12) and MACOS_CERTIFICATE_PASSWORD,
# and nowhere else; the certificate's SHA-1 is in macos-cert.sha1, and only
# that certificate signs. Without the secrets (a pull request from
# elsewhere) it signs for this computer only (ad hoc), as before 0.5.0; a
# release (TTERM_RELEASE=1) is refused then.
#
#   sh scripts/sign-mac.sh PATH IDENTIFIER
set -eu
path=$1
identifier=$2
here=$(cd "$(dirname "$0")/.." && pwd)
pin=$(tr -d ' \n' < "$here/macos-cert.sha1" | tr 'A-F' 'a-f')

if [ -z "${MACOS_CERTIFICATE:-}" ]; then
  if [ "${TTERM_RELEASE:-}" = 1 ]; then
    echo "A release is signed with tTerm's certificate, and MACOS_CERTIFICATE is not in the secrets" >&2
    exit 1
  fi
  echo "No MACOS_CERTIFICATE here: $path signed for this computer only"
  codesign --force --sign - --identifier "$identifier" "$path"
  exit 0
fi

work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/tterm-signing.XXXXXX")
keychain="$work/signing.keychain-db"
cleanup() {
  security delete-keychain "$keychain" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
umask 077
# A keychain of this run's own, with a password nobody keeps.
password=$(openssl rand -hex 24)
security create-keychain -p "$password" "$keychain"
security set-keychain-settings -lut 3600 "$keychain"
security unlock-keychain -p "$password" "$keychain"
printf '%s' "$MACOS_CERTIFICATE" | base64 --decode > "$work/id.p12"
security import "$work/id.p12" -k "$keychain" -P "$MACOS_CERTIFICATE_PASSWORD" -T /usr/bin/codesign >/dev/null
rm -f "$work/id.p12"
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain" >/dev/null
# shellcheck disable=SC2046
security list-keychains -d user -s "$keychain" $(security list-keychains -d user | tr -d '"')

found=$(security find-certificate -a -Z "$keychain" | awk '/SHA-1 hash:/ { print tolower($3) }')
if [ "$found" != "$pin" ]; then
  echo "The certificate in MACOS_CERTIFICATE is ${found:-none}, not $pin (macos-cert.sha1)" >&2
  exit 1
fi

requirement="identifier \"$identifier\" and certificate leaf = H\"$pin\""
codesign --force --timestamp=none --keychain "$keychain" --sign "$(printf '%s' "$pin" | tr 'a-f' 'A-F')" \
  --identifier "$identifier" --requirements "=designated => $requirement" "$path"
codesign --verify --strict --verbose=2 "$path"
codesign --verify --strict -R "=$requirement" "$path"
codesign --display --requirements - "$path"
echo "$path signed with tTerm's certificate $pin"
