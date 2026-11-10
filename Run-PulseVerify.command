#!/bin/zsh
# Double-click launcher for macOS: runs the network check with the
# PowerShell bundled in this folder (nothing is installed), writes the
# report to the reports folder (and the log to the logs folder) next to
# this file, and opens it. The script asks its own questions.

cd "${0:A:h}" || exit 1

# Apple Silicon reports hw.optional.arm64 = 1 even under Rosetta, so the
# native build is picked whenever the hardware can run it.
if [[ "$(sysctl -n hw.optional.arm64 2>/dev/null)" == "1" ]]; then
  PWSH=./powershell/arm64/pwsh
else
  PWSH=./powershell/x64/pwsh
fi

if [[ ! -x "$PWSH" ]]; then
  echo "Cannot find $PWSH next to this file."
  echo "Unzip the whole pulse-verify-macos folder and run Run-PulseVerify.command from inside it."
  read -k1 "?Press any key to close this window..."
  exit 1
fi

# A downloaded zip marks every file it unpacks as "from the internet".
# The Intel build of PowerShell maps each of its .NET .dll files as code,
# and macOS then shows a "Not Opened" box per .dll, since a .dll carries no
# Apple signature. Clear the mark on the bundled PowerShell folder only:
# the person already allowed this launcher (Open Anyway), and the build
# checks these files against Microsoft's published SHA-256 hashes.
/usr/bin/xattr -dr com.apple.quarantine ./powershell 2>/dev/null

# PowerShell sends telemetry and checks for updates when it starts. Turn
# both off: the check should only contact the services it tests.
export POWERSHELL_TELEMETRY_OPTOUT=1
export POWERSHELL_UPDATECHECK=Off
export POWERSHELL_CLI_TELEMETRY_OPTOUT=1

"$PWSH" -NoProfile -NoLogo -File ./Test-PulseVerify.ps1 "$@"
rc=$?

# Exit 0 (ready) or 1 (not ready) means this run wrote a report. 2 and up
# (stopped at a question, missing file, error) wrote none, so don't reopen
# an older report from the folder.
if (( rc <= 1 )); then
  latest=$(ls -t reports/vpu-network-check-*.html 2>/dev/null | head -1)
  [[ -n "$latest" ]] && open "$latest"
fi

echo
read -k1 "?Press any key to close this window..."
echo
