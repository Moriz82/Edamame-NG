# Windows PowerShell 3 acceptance, 2026-09-25 CDT

## Guest and method

A disposable Windows Server 2012 guest ran native Windows PowerShell 3.0 on an isolated virtual bridge without a physical uplink. The installation source was the [official Microsoft Hyper-V Server 2012 evaluation image](https://www.microsoft.com/en-us/evalcenter/download-hyper-v-server-2012). The local test account was a standard user. An elevated operator created the exact `EdamameWeakSvc` fixture for that account with the repository's fixture script. The fixture was stopped, manual-start, LocalSystem, and bound to a protected marker and the test account's service rights.

The runner, module, fixture, and focused tests were copied into the guest. Native PowerShell 3.0 passed capture and timeout, live verbose output, concurrent collectors and CVE screening, offline CVE catalog, digest/cache, ACL/Resume, and weak-service adapter tests. The weak-service adapter test also passed from the standard-user token with `-ExpectedNotSystem`. The runner checks the three expected system binaries through Authenticode or, on Server 2012 alone, Windows Resource Protection plus TrustedInstaller ownership and write denial. This compatibility path accepted the guest's protected binaries.

## Observed escalation and replay

An offline, standard-user Scan selected `weak-service-lab` after independently checking the fixture. It proved a SYSTEM pipe client token with `-NoShell` and reported restoration of the original service path. The first attempt exposed a cold-start timing failure: the PowerShell 3 watchdog process did not become ready within three seconds. Increasing its bounded readiness wait to fifteen seconds resolved the failure; the service remained at its original path during failed attempts.

Resume selected the saved recipe without repeating enumeration. The approved interactive run showed `[PROOF] SYSTEM token verified; service configuration restored.` At `SYSTEM>`, `whoami` returned `nt authority\system`. The success record contained the recipe ID, fixture ID, proof SID `S-1-5-18`, and restoration flag. It contained no executable command or credential. The service configuration showed its original `svchost.exe` path before fixture removal.

The operator removed the exact fixture and protected marker. A subsequent Resume rejected the saved recipe with `Saved weak-service fixture no longer matches`; no new shell opened. This confirms prerequisite rechecking after a prior success.

The guest had no verified offline WinPEAS or PrivescCheck assets. Their cache checks were unavailable and were recorded as such; this run proves the native recipe and replay path, while the Windows PowerShell 5.1 guest proves real enumerator overlap and `-FinishBgEnum`. It does not establish that current third-party enumerators support Server 2012.

## Cleanup

The fixture service and marker were removed before teardown. The disposable Windows Server 2012 and Windows Server 2022 VMs, Debian test container, their storage volumes, isolated bridge, staged ISOs, temporary transfer server, and associated host staging were removed. Readback found no remaining test VM/container configs, volumes, bridge, transfer listener, or staged ISO. The storage pools reported healthy.
