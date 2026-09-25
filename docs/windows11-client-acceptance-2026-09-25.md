# Windows 11 client acceptance — 2026-09-25

Disposable VM 1801 ran Windows 11 Enterprise Evaluation 25H2, build 26200, on isolated Proxmox. The ISO came from [Microsoft's Evaluation Center](https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise); its SHA-256 was `a61adeab895ef5a4db436e0a7011c92a2ff17bb0357f58b13bbc4062e535e7b9`, matching [Microsoft's published evaluation hash](https://aka.ms/Win11-Hash-PDF). The VM used temporary `lab-net-10` without an uplink, a static bridge-local address, and a temporary local account. No assessment target or production guest was tested. Credentials and raw enumerator output are excluded from this record.

Windows PowerShell 5.1.26100.6584 passed `tests/test_windows_catalog.ps1` and `tests/test_release.ps1` inside the guest. The transferred tool ZIP matched SHA-256 `c78832f917a63449d14ac876f11066c6dfee41ca26149e361157f445d290ab4c`. It contained locally verified WinPEAS, PrivescCheck, and a pinned Microsoft PsExec64.exe. The host-run tool recorded their adjacent digests in `tools.tsv`.

## Elevated route and replay

At first logon, the local account was a member of Administrators but had a medium-integrity RDP token. Run `20260925T151324Z-EDAMAME-WIN11-1904` alerted on candidate lines before saving `winpeas-output.txt` and `privesccheck-output.txt`. Microsoft Defender quarantined the WinPEAS executable, so the batch fallback ran. PrivescCheck exceeded the deliberate 30-second tool limit and retained partial output. With explicit service approval and Windows UAC consent, the `uac-admin-system` recipe launched the reviewed PsExec route and verified a `S-1-5-18` token. `success.json` recorded only the recipe ID and proof label. Explicit Resume asked for UAC consent again, skipped enumeration, verified SYSTEM again, and appended `resumed-proof` to `attempts.tsv`.

The account was then removed from Administrators, added to Remote Desktop Users, logged off, and logged in again. `whoami /groups` showed Users and Remote Desktop Users but no Administrators. A later Resume rejected the saved admin recipe with `resume-prerequisite-failed`; no SYSTEM action was attempted.

## Standard-user scans

Run `20260925T151908Z-EDAMAME-WIN11-7664` retained batch WinPEAS and 90-second partial PrivescCheck output. It alerted before final filenames, selected no recipe, and wrote no `success.json`. The run directory ACL contained only the current user and SYSTEM; raw files inherited that ACL.

Run `20260925T152256Z-EDAMAME-WIN11-2364` used a 300-second per-tool limit. Defender blocked the copied WinPEAS executable under `.capture`, despite a file exclusion on the original tool path, so the batch fallback ran. PrivescCheck still timed out after 300 seconds. Its one CVE suggestion was indexed for review only; no CVE recipe was selected.

For run `20260925T152856Z-EDAMAME-WIN11-8144`, a temporary Defender exception scoped to the disposable guest's Edamame-NG run directory allowed the SHA-256-verified WinPEAS executable to complete. `coverage.tsv` recorded `winpeas checked` and `privesccheck timeout`. The scanner alerted on 176 WinPEAS candidate lines and 239 PrivescCheck candidate lines, with values withheld from the console, before moving both raw files to final names. It indexed 13 CVE strings as suggestions; three matched review-only Windows records, and ten were unindexed. No build or patch proof established a vulnerable CVE, no exploit was run, and no supported escalation recipe was verified for this standard user. The run took about six minutes, within the target 30-minute window.

This proves the Windows client UAC-to-SYSTEM route, replay, prerequisite rejection, standard-user no-recipe behavior, alert ordering, local asset verification, Defender-blocked fallback, executable WinPEAS path, and private ACLs on this build. It does not establish a standard-user-to-SYSTEM exploit. Extended PrivescCheck did not complete within five minutes on this guest; its output and checklist areas remain marked partial or unsupported. Defender exceptions were confined to the disposable guest and removed with it.

Cleanup readback found no VM 1801 configuration or ZFS volume. The temporary guest ISOs, local answer material, and account were removed with the disposable guest; the isolated bridge remained only for the later Server 2025 test and was removed afterward.
