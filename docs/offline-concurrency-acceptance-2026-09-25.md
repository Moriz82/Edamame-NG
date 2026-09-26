# Offline catalog and concurrent scan checks, 2026-09-25

The CVE ID/state index contains 397,443 records in 28 year files (9.4 MB on disk). It was generated from the official CVE List V5 `2026-09-25_all_CVEs_at_midnight.zip.zip` baseline. The downloaded ZIP SHA-256 matched the digest published for that release asset; `catalog/cve-ids-source.json` records both the digest and derived index digest. CISA KEV local escalation leads were refreshed separately. Neither source establishes that a scanned host is vulnerable.

Focused local checks passed:

- `bash -n` and ShellCheck at warning severity.
- `tests/test_linux.py`: verified local and cached offline assets without a release request; early proof stopped slow enumerators and marked partial output; `--finish-bg-enum` let both complete; alerts preceded final raw filenames.
- `tests/test_catalog.py`: deterministic nested ZIP ingestion, published-digest rejection, ID/state lookup, local lead precedence, and PoC checksum checks.
- `tests/test_windows_catalog.ps1`, `tests/test_release.ps1`, `tests/test_windows_async.ps1`, and `tests/test_capture_verbose.ps1` under PowerShell 7: catalog and cache behavior, concurrent captured processes, live CVE screening, interrupted partial capture, and verbose output.
- PSScriptAnalyzer `PSUseCompatibleSyntax` for PowerShell 3.0 reported no findings in the runner or weak-service module. Its command profile reported only `Get-FileHash`, for which the runner supplies a SHA-256 fallback.

Native guest checks now cover Windows PowerShell 3.0 on a disposable Windows Server 2012 guest and Windows PowerShell 5.1 on a disposable Windows Server 2022 guest. Both passed the capture, live verbose output, concurrent collector, catalog, release/digest, ACL/Resume, and weak-service adapter tests. The 3.0 guest exposed legacy .NET constructor and pipe API differences; the weak-service test now passes there. Windows Server 2012 reported its system binaries as `NotSigned` through `Get-AuthenticodeSignature`; the runner accepts only the three expected paths after Windows Resource Protection, TrustedInstaller ownership, and write-denial checks. The 5.1 guest still passes its signed-binary route.

A standard-user interactive SYSTEM shell was observed while WinPEAS and PrivescCheck were still running on the 5.1 guest. With `-FinishBgEnum`, both completed and saved their named outputs after the shell exited. Resume repeated the route without enumeration and asked for the service change again; removing the fixture caused Resume to refuse. A disposable Linux guest likewise proved an early root shell with LinPEAS and LSE still running, complete background collection, and prerequisite refusal after fixture removal. The [PowerShell 3 acceptance record](windows-powershell-3-acceptance-2026-09-25.md) adds a standard-user SYSTEM proof, interactive Resume, and fixture-removal refusal on Windows Server 2012. That guest used offline mode with enumerators unavailable, so it does not prove modern WinPEAS or PrivescCheck can run on Server 2012.

The all-CVE index supplies offline lookup; it does not add unreviewed exploit recipes.
