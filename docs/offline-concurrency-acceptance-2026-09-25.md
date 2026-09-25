# Offline catalog and concurrent scan checks, 2026-09-25

The CVE ID/state index contains 397,443 records in 28 year files (9.4 MB on disk). It was generated from the official CVE List V5 `2026-09-25_all_CVEs_at_midnight.zip.zip` baseline. The downloaded ZIP SHA-256 matched the digest published for that release asset; `catalog/cve-ids-source.json` records both the digest and derived index digest. CISA KEV local escalation leads were refreshed separately. Neither source establishes that a scanned host is vulnerable.

Focused local checks passed:

- `bash -n` and ShellCheck at warning severity.
- `tests/test_linux.py`: verified local and cached offline assets without a release request; early proof stopped slow enumerators and marked partial output; `--finish-bg-enum` let both complete; alerts preceded final raw filenames.
- `tests/test_catalog.py`: deterministic nested ZIP ingestion, published-digest rejection, ID/state lookup, local lead precedence, and PoC checksum checks.
- `tests/test_windows_catalog.ps1`, `tests/test_release.ps1`, `tests/test_windows_async.ps1`, and `tests/test_capture_verbose.ps1` under PowerShell 7: catalog and cache behavior, concurrent captured processes, live CVE screening, interrupted partial capture, and verbose output.
- PSScriptAnalyzer `PSUseCompatibleSyntax` for PowerShell 3.0 reported no findings in the runner or weak-service module. Its command profile reported only `Get-FileHash`, for which the runner supplies a SHA-256 fallback.

The new Windows scan path has not yet run under native Windows PowerShell 3.0 or 5.1. An interactive shell overlapping background enumeration has not yet been observed in a guest. These are acceptance gaps for the later disposable-guest matrix. The all-CVE index supplies offline lookup; it does not add unreviewed exploit recipes.
