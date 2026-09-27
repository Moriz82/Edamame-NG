#!/usr/bin/env bash
# Run the local PowerShell checks. Set PWSH to choose a PowerShell binary;
# the script only needs one that can parse and run tests/*.ps1 locally.
set -u
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." || exit 2
if [[ -z ${PWSH:-} ]]; then
  if command -v pwsh >/dev/null 2>&1; then PWSH=pwsh; else PWSH=powershell; fi
fi
status=0
for script in "$@"; do
  printf '=== %s ===\n' "$script"
  "$PWSH" -NoProfile -File "tests/$script"
  rc=$?
  printf '%s\n' "--- $script exit $rc ---"
  ((rc == 0)) || status=1
done
exit $status
