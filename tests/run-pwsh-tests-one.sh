#!/usr/bin/env bash
# Run a single PowerShell script, for example to pass a -Runner override.
set -u
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." || exit 2
if [[ -z ${PWSH:-} ]]; then
  if command -v pwsh >/dev/null 2>&1; then PWSH=pwsh; else PWSH=powershell; fi
fi
script=$1
shift
"$PWSH" -NoProfile -File "$script" "$@"
exit $?
