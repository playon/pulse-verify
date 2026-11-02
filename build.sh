#!/usr/bin/env bash
# Build the zip IT teams download: dist/pulse-verify.zip and its .sha256.
# The release workflow runs this on a version tag; run it locally to check
# what will ship.
#
# Files sit at the root of the zip, since Windows "Extract All" already
# makes a pulse-verify folder. .bat, .ps1 and .txt get CRLF line endings
# for cmd.exe and Notepad.

set -euo pipefail
cd "$(dirname "$0")"

FILES=(Run-PulseVerify.bat Test-PulseVerify.ps1 endpoints.json README.txt)
STAGE=dist/pulse-verify
ZIP=dist/pulse-verify.zip

VERSION=$(sed -n "s/^\$ToolVersion = '\([^']*\)'.*/\1/p" Test-PulseVerify.ps1)
if [ -z "$VERSION" ]; then
  echo "FAIL: no \$ToolVersion = '...' line in Test-PulseVerify.ps1" >&2
  exit 1
fi

# Windows PowerShell 5.1 reads BOM-less files as ANSI, so any non-ASCII
# byte turns into mojibake on the IT team's machine.
perl -ne 'if (/[^\x00-\x7F]/) { print STDERR "$ARGV:$.: non-ASCII: $_"; $bad = 1 } close ARGV if eof; END { exit($bad ? 1 : 0) }' "${FILES[@]}" \
  || { echo "FAIL: shipped files must be pure ASCII" >&2; exit 1; }

rm -rf dist
mkdir -p "$STAGE"
for f in "${FILES[@]}"; do
  case "$f" in
    *.bat|*.ps1|*.txt) perl -pe 's/\r?\n/\r\n/' "$f" > "$STAGE/$f" ;;
    *) cp "$f" "$STAGE/$f" ;;
  esac
done

(cd "$STAGE" && zip -X -q ../pulse-verify.zip "${FILES[@]}")
(cd dist && shasum -a 256 pulse-verify.zip > pulse-verify.zip.sha256)

echo "Built $ZIP (version $VERSION)"
cat dist/pulse-verify.zip.sha256
