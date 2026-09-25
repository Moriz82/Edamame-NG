# Workgroup and failure-path acceptance — 2026-09-25

This pass extended the earlier [Linux and Windows matrix](matrix-2026-09-25.md) and [domain-user acceptance](extended-acceptance-2026-09-25.md). It used one disposable Windows Server 2022 clone, VM 1501, from stopped source guest on an isolated `lab-net-02` bridge on `lab-hypervisor`. The clone was removed from its domain and joined to `WORKGROUP`. No current assessment target was selected. Credentials and raw enumerator output are excluded from this record.

## Results

| Context | Observed result |
| --- | --- |
| Linux synthetic fault tests | Valid and invalid local SHA-256, official-release digest parsing, verified-cache fallback, no published LSE digest, incomplete LinPEAS output, alert-before-final-file order, console masking, default Resume without enumeration, foreign-host and unknown-recipe rejection, removed prerequisites, missing success, invalid run ID, and symlinked run base passed. A partial enumerator now leaves broad checklist areas `unsupported`. |
| Windows PowerShell 5.1 functions on VM 1501 | Release/digest and cache tests, subprocess success/failure/timeout tests, ACL reset, and same-host Resume selection passed. ACL reset was exercised under both SYSTEM and a standard local user after adding an explicit Everyone read ACE. The resulting directory had only the current identity and SYSTEM as explicit allow entries. |
| Standard local user on workgroup VM 1501 | Run `20260925T075738Z-LAB-WKS01-2288` completed with `sharphound\tnot-domain-joined`. WinPEAS binary, WinPEAS batch fallback, and PrivescCheck reached the 45-second test limit and retained partial files of 24,162, 36,663, and 389,170 bytes, respectively. Screening alerts preceded the final filenames. The run directory had only the user and SYSTEM as explicit allow entries. No recipe was verified; explicit Resume failed without rescanning. The workgroup guest denied the standard user WMI access, so the domain-check fallback was also exercised. |
| SYSTEM on workgroup VM 1501 | Run `20260925T080529Z-LAB-WKS01-3568` retained labeled partial outputs after alerts and verified `already-system`. Resume rechecked the token, appended `resumed-proof`, and left the run count at one. SharpHound was correctly marked `not-domain-joined`. |

The guest clock was about one hour behind the Proxmox host. Run IDs and guest timestamps above identify exact files but should not be treated as synchronized wall-clock evidence.

The source image's inherited policy did not grant ordinary users batch logon. A disposable scheduled-task test therefore could not start under the standard account. The clone's WinRM root ACL also excluded Remote Management Users. For the workgroup scan only, the test account received batch-logon permission and that group received WinRM root access; the standard account authenticated over isolated WinRM with a non-admin token. Neither change touched a source or production VM.

## Product corrections from this pass

- Windows private-directory setup now replaces the DACL with only the current identity and SYSTEM. Its .NET DACL write works for a standard user; the previous `Set-Acl` method failed because it required `SeSecurityPrivilege` on this guest.
- Automatic Windows Resume chooses the latest success for the current host and skips invalid or foreign success files. Linux and Windows reject `.` and `..` as explicit run IDs. Linux rejects a symlinked run base or cache base.
- Broad checklist rows are `checked` only when both platform enumerators complete. Tool rows retain exact partial, timeout, or unavailable states. Windows' default per-tool timeout is now 300 seconds to keep four sequential external-tool attempts within the intended run-time range when downloads are responsive.

## Remaining acceptance limits

The supported `uac-admin` route still lacks a live interactive consent-and-shell proof. This clone was tested through QEMU Guest Agent and WinRM; those are noninteractive tokens. No reviewed CVE exploit recipe or standard-user-to-SYSTEM recipe is installed. Credential validation is also unimplemented. On this workgroup guest, all three external Windows enumeration attempts were partial at the 45-second test limit, so their checklist areas remain `unsupported`; the files were retained for local review, not counted as complete enumeration. The earlier domain and Linux results remain as recorded in the linked acceptance notes.

## Cleanup

The test account, its generated credential, task, policy changes, WinRM listener, and raw outputs existed only in disposable VM 1501. After testing, the VM, its ZFS volume, isolated bridge, bridge-local transfer server, staging files, SSH port forward, and local temporary credential were removed. The original source guest remained stopped. The production non-test VMs and existing test VMs were not used.
