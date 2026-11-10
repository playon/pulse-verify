#!/usr/bin/env bash
# Build the zips IT teams download, each with a .sha256:
#   dist/pulse-verify.zip        Windows (runs under built-in PowerShell 5.1)
#   dist/pulse-verify-macos.zip  macOS (bundles Microsoft's portable
#                                PowerShell 7 for Apple Silicon and Intel)
# The release workflow runs this on a version tag; run it locally to check
# what will ship.
#
# Files sit at the root of each zip, since Windows "Extract All" and the
# macOS Archive Utility already make a folder. The Windows .bat, .ps1 and
# .txt get CRLF line endings for cmd.exe and Notepad; the Mac files get LF.

set -euo pipefail
cd "$(dirname "$0")"

# Portable PowerShell for the Mac zip, pinned and checked against the
# SHA-256 Microsoft publishes in the release's hashes.sha256. To update,
# change the version and both hashes together.
PWSH_VERSION=7.6.9
PWSH_SHA256_ARM64=a1c7e98ac403da4be5ba75c1c5855af272de7787a91d478c4267466fe58fc1af
PWSH_SHA256_X64=a5aa2308a7e9664510a5c93d5b337fd524ff7dc14b8a637fb6144a2bbaa298ae
CACHE=.cache/powershell

WIN_FILES=(Run-PulseVerify.bat Test-PulseVerify.ps1 endpoints.json README.txt)
MAC_FILES=(Run-PulseVerify.command Test-PulseVerify.ps1 endpoints.json README-macOS.txt)

VERSION=$(sed -n "s/^\$ToolVersion = '\([^']*\)'.*/\1/p" Test-PulseVerify.ps1)
if [ -z "$VERSION" ]; then
  echo "FAIL: no \$ToolVersion = '...' line in Test-PulseVerify.ps1" >&2
  exit 1
fi

# Windows PowerShell 5.1 reads BOM-less files as ANSI, so any non-ASCII
# byte turns into mojibake on the IT team's machine.
perl -ne 'if (/[^\x00-\x7F]/) { print STDERR "$ARGV:$.: non-ASCII: $_"; $bad = 1 } close ARGV if eof; END { exit($bad ? 1 : 0) }' "${WIN_FILES[@]}" "${MAC_FILES[@]}" \
  || { echo "FAIL: shipped files must be pure ASCII" >&2; exit 1; }

fetch_pwsh() {  # arch sha256 -> path of the verified tarball
  local arch=$1 sha=$2
  local name="powershell-$PWSH_VERSION-osx-$arch.tar.gz"
  local path="$CACHE/$name"
  mkdir -p "$CACHE"
  if [ ! -f "$path" ]; then
    echo "Downloading $name" >&2
    curl -fsSL -o "$path.part" "https://github.com/PowerShell/PowerShell/releases/download/v$PWSH_VERSION/$name"
    mv "$path.part" "$path"
  fi
  if ! echo "$sha  $path" | shasum -a 256 -c - >/dev/null; then
    rm -f "$path"
    echo "FAIL: $name does not match the pinned SHA-256" >&2
    exit 1
  fi
  echo "$path"
}

rm -rf dist
mkdir -p dist

# ---- Windows
STAGE=dist/pulse-verify
mkdir -p "$STAGE"
for f in "${WIN_FILES[@]}"; do
  case "$f" in
    *.bat|*.ps1|*.txt) perl -pe 's/\r?\n/\r\n/' "$f" > "$STAGE/$f" ;;
    *) cp "$f" "$STAGE/$f" ;;
  esac
done
(cd "$STAGE" && zip -X -q ../pulse-verify.zip "${WIN_FILES[@]}")

# ---- macOS
STAGE=dist/pulse-verify-macos
mkdir -p "$STAGE/powershell/arm64" "$STAGE/powershell/x64"
for f in "${MAC_FILES[@]}"; do
  out="$f"; [ "$f" = README-macOS.txt ] && out=README.txt
  perl -pe 's/\r?\n/\n/' "$f" > "$STAGE/$out"
done
chmod 755 "$STAGE/Run-PulseVerify.command"
tar -xzf "$(fetch_pwsh arm64 "$PWSH_SHA256_ARM64")" -C "$STAGE/powershell/arm64"
tar -xzf "$(fetch_pwsh x64 "$PWSH_SHA256_X64")" -C "$STAGE/powershell/x64"
chmod 755 "$STAGE/powershell/arm64/pwsh" "$STAGE/powershell/x64/pwsh"
# -y keeps any symlinks as links; -r for the powershell folders.
(cd "$STAGE" && zip -X -q -r -y ../pulse-verify-macos.zip Run-PulseVerify.command Test-PulseVerify.ps1 endpoints.json README.txt powershell)

(cd dist && shasum -a 256 pulse-verify.zip > pulse-verify.zip.sha256 && shasum -a 256 pulse-verify-macos.zip > pulse-verify-macos.zip.sha256)

echo "Built dist/pulse-verify.zip and dist/pulse-verify-macos.zip (version $VERSION, PowerShell $PWSH_VERSION for macOS)"
cat dist/pulse-verify.zip.sha256 dist/pulse-verify-macos.zip.sha256
ls -lh dist/*.zip | awk '{print $5, $9}'
