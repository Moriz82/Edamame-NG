# Edamame-NG

Host-run Linux and Windows privilege escalation assessment scripts. The two supplied checklists are coverage inventories; their example commands are not executed verbatim.

## Run

Linux (Bash, `curl`, GNU `timeout`, `ps` with PGID/STAT/start-time fields, `mkfifo`, `awk`, and `sha256sum` or `shasum`):

```sh
bash edamame-ng.sh --scan --output-dir "$HOME/edamame-ng-runs"
bash edamame-ng.sh --scan --verbose --output-dir "$HOME/edamame-ng-runs"
bash edamame-ng.sh --resume --output-dir "$HOME/edamame-ng-runs"
```

Windows (Windows PowerShell 3.0 or later):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Edamame-NG.ps1 -Scan
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Edamame-NG.ps1 -Scan -Verbose
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Edamame-NG.ps1 -Resume
```

To also try an interactive SYSTEM shell from an administrator token, approve the temporary local PsExec service action for each launch:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Edamame-NG.ps1 -Scan -ApproveSystemService
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Edamame-NG.ps1 -Resume -ApproveSystemService
```

Without the switch, an interactive run asks before accepting the Sysinternals EULA and creating the service. On Scan, a declined or unavailable service action leaves the Administrator-only recipe available; Resume of a saved SYSTEM recipe stops until the action is approved again. The service route requires a signed Microsoft PsExec binary from the [official PsTools download](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec); `-ToolDir` accepts `PsExec64.exe` with an adjacent `.sha256` file. The runner checks Authenticode, product name, and SHA-256, and checks the saved copy again on Resume. The binary is not included in this repository.

For a **disposable Windows weak-service lab only**, an elevated operator can create the fixed `EdamameWeakSvc` fixture for one existing standard-user SID:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\fixtures\windows\WeakServiceLab.ps1 -Create -TestUser '.\edamame_lab'
```

The fixture creates a stopped, manual LocalSystem service and a protected registry marker; it grants that SID only query, change, and start service rights. From the standard-user console, `-Scan -EnableWeakServiceLab -ApproveServiceChange` attempts the exact fixture route. `-Resume -EnableWeakServiceLab -ApproveServiceChange` rechecks the fixture and requests approval again without enumeration. Without `-ApproveServiceChange`, an interactive run requires typing `CHANGE EdamameWeakSvc`. Add `-NoShell` for a bounded proof. Use the fixture ID printed at creation with `WeakServiceLab.ps1 -Remove -FixtureId <id>` from an elevated session after testing. If creation stops before a complete marker exists and the service is absent, `WeakServiceLab.ps1 -RecoverIncomplete` clears that marker. The runner never selects an arbitrary weak service for this recipe.

Without `--scan`/`-Scan` or `--resume`/`-Resume`, a previous success offers Resume as the default. `--no-shell`/`-NoShell` proves a recipe without opening a shell. `--tool-dir`/`-ToolDir` accepts predownloaded assets only when each asset has an adjacent `.sha256` file containing its expected SHA-256. A new scan checks current official releases unless a tool directory is supplied. A failed update uses only a previously verified cache copy and prints a warning.

Scans start supported enumerators while native recipe checks run. A verified route can open a shell before enumeration finishes. By default, remaining collectors stop after a successful interactive proof and their output is labeled partial. Use `--finish-bg-enum` or `-FinishBgEnum` to let them finish while the shell is open; final named output files are saved after the shell exits. With `--no-shell`/`-NoShell`, the runner waits for collectors to finish or reach their per-tool timeouts; check `coverage.tsv` for incomplete runs. Enumerator CVE strings are screened as output grows, but they are review leads and do not trigger unreviewed exploit code.

Linux starts each collector in an isolated, verified process group. It waits for that group to stop before naming a final output file. If it cannot confirm cleanup, it keeps the partial capture private, records `cleanup-failed`, and exits unsuccessfully. Missing process-control commands or unsupported `timeout`/`ps` options make the affected collector unavailable.

For a scan with no network access, supply the verified local assets and the bundled catalog:

```sh
bash edamame-ng.sh --scan --offline --tool-dir ./offline-assets
bash edamame-ng.sh --cve CVE-2025-32463
bash edamame-ng.sh --cve-details CVE-2025-32463
bash edamame-ng.sh --poc CVE-2025-32463
```

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Edamame-NG.ps1 -Scan -Offline -ToolDir .\offline-assets
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Edamame-NG.ps1 -Cve CVE-2021-36934
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Edamame-NG.ps1 -CveDetails CVE-2021-36934
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Edamame-NG.ps1 -Poc CVE-2025-32463
```

`--offline`/`-Offline` prohibits release checks and downloads; only adjacent-digest local assets and previously verified cache copies are used. Windows skips SharpHound domain collection in this mode. Third-party enumerators may still perform their own network checks, so use host network isolation if a strict no-network run is required. `--cve`/`-Cve` reads the local CVE index. `--cve-details`/`-CveDetails` returns source descriptions, affected-product JSON, references, and an optional `source_json` column. When the complete detail pack is installed, it supports every ID in the dated baseline. Otherwise it uses the bundled local review details and reports `details-not-installed` for other IDs. `--poc`/`-Poc` reports an offline PoC file only after checking its SHA-256; it does not execute it. All three query modes work without a scan or network request. Use `--catalog-dir`/`-CatalogDir` to select another local catalog. A scan saves `cve-index.tsv`, which distinguishes local escalation review leads, general published CVEs, rejected or reserved IDs, unindexed IDs, and wrong-platform leads. It also saves `cve-details.tsv` rows for suggested IDs, including IDs from retained partial collector output.

The older LSE release does not publish a SHA-256 in GitHub's release listing. For that asset, Edamame-NG prints a warning, hashes the official HTTPS download, and uses that hash to check later cached copies. This is a recorded digest, not independent upstream checksum validation. Windows has `-ToolTimeoutSeconds` (default 300) to retain partial output when an external enumerator stalls; Linux uses 600 seconds for each enumerator.

Scan and Resume show a startup splash. `--verbose` (or `-v`) on Linux and PowerShell's `-Verbose` show raw enumerator output live during Scan, with a warning because that output may contain credentials. Resume skips enumeration, and CVE detail and PoC queries remain machine readable without a splash. The default console alerts continue to withhold credential values.

The run directory is private (mode 700 on Linux; an explicit current-user and SYSTEM ACL on Windows). Raw enumerator output can contain credentials. Each enumerator writes to `.capture` first. Only after the alerts are printed does the script move raw output to `linpeas-output.txt`, `lse-output.txt`, `winpeas-output.txt`, `privesccheck-output.txt`, and, when applicable, `sharphound.zip`. Inspect the run directory locally and handle it as sensitive evidence.

`tools.tsv` records release tag, source, and SHA-256. `findings.tsv`, `attempts.tsv`, `coverage.tsv`, `cve-candidates.tsv`, `cve-index.tsv`, and `cve-details.tsv` provide the decision record. A successful recipe is recorded by ID and evidence in `success.tsv` or `success.json`. Resume checks its prerequisites again and skips enumeration.

## Offline CVE and PoC catalog

`catalog/cve-ids/YYYY.tsv` contains 397,443 IDs and record states from the [official CVE List V5 daily baseline](https://github.com/CVEProject/cvelistV5/releases), split by year for fast lookups without loading the whole list. The compact files total about 9.4 MB. `catalog/cve-ids-source.json` records the baseline asset and its SHA-256, which was checked against the release-published digest. Rebuild it together with the detail sidecar using the command below; the builder rejects an index-only refresh when a detail sidecar exists, so their source dates cannot silently diverge. This index contains every ID in that dated baseline, including non-local CVEs; it provides no product, build, patch, or exploit applicability.

`catalog/local-eop.tsv` contains 118 compact **candidate** records selected from the [CISA KEV catalog](https://github.com/cisagov/kev-data). `catalog/source.json` records the source version, release date, record count, and SHA-256 of the source snapshot. `scripts/update_catalog.py --input verified-kev.json` rebuilds it at development time without fetching data. `catalog/curated-eop.tsv` adds nine review leads outside that KEV selection; [curated-advisories.md](catalog/curated-advisories.md) keeps their affected conditions and primary-source links available offline. An empty `kev_date` does not claim KEV status. The base catalog takes precedence if an ID appears in both files. The filter checks local privilege escalation terms and broad Windows/Linux product names. It can miss a relevant CVE or include one that does not apply to a host. A KEV listing confirms observed exploitation somewhere; it does not establish a vulnerable local build, missing patch, or safe exploit path. Edamame-NG never selects an escalation recipe from this text match alone.

`catalog/local-eop-details.tsv` adds 127 source-metadata rows for those review leads in about 472 KB. Each row contains the English CNA description, full CNA `affected` JSON, and CNA references from the same digest-verified CVE baseline as the all-CVE index. `catalog/local-eop-details-source.json` records the baseline and sidecar SHA-256 values. Query and scan paths check the sidecar digest, source alignment, and candidate membership before returning details. Rebuild both indexes with `scripts/build_cve_ids.py --input verified-baseline.zip.zip --expected-sha256 <published-digest> --with-local-details`. These are unreviewed source claims, not an automatic version matcher. Exact OS build, distro backports, patch state, configuration, and prerequisite checks remain necessary before any recipe can be selected. A source checkout keeps this small fallback; the optional complete pack adds source details for every baseline ID.

The optional all-CVE pack uses `catalog/all-cve-details/<generation>/YYYY/<suffix-prefix>.tsv.gz`. A shard contains at most 1,000 rows; routing removes the last three digits of the suffix as a string, including for 19-digit IDs. The seventh detail column, `source_json`, projects `dataType`, `dataVersion`, `cveMetadata`, and the complete CNA/ADP containers. It preserves conflicting source claims, versions, metrics, rejection reasons, and replacement IDs. Reserved IDs receive no invented product details. Complete-pack descriptions use JSON string escaping without surrounding quotes; parse `source_json` for the original Unicode and control characters. All source content remains unreviewed, with no automatic applicability or recipe selection.

Download the verified [2026-09-25 catalog release](https://github.com/Moriz82/Edamame-NG/releases/tag/catalog-2026-09-25) for the complete offline pack. It has a [tar.gz archive](https://github.com/Moriz82/Edamame-NG/releases/download/catalog-2026-09-25/edamame-ng-catalog-2026-09-25.tar.gz) for Linux and a [ZIP archive](https://github.com/Moriz82/Edamame-NG/releases/download/catalog-2026-09-25/edamame-ng-catalog-2026-09-25.zip) for Windows, each with an adjacent `.sha256` asset. Verify the downloaded archive against its checksum before extraction. From this release's source checkout, Linux can install the tar archive at the checkout root with `tar -xzf edamame-ng-catalog-2026-09-25.tar.gz`, then run `python3 scripts/build_cve_ids.py --verify-all-details`. On Windows PowerShell 3+, extract the ZIP into a **new empty directory** and pass its `catalog` subdirectory to `-CatalogDir`; this avoids overwriting the checkout's existing small catalog. For example:

```powershell
certutil -hashfile .\edamame-ng-catalog-2026-09-25.zip SHA256
# Compare with the downloaded .zip.sha256 before continuing.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$destination = Join-Path (Get-Location).Path 'full-cve-catalog-2026-09-25'
[IO.Compression.ZipFile]::ExtractToDirectory((Resolve-Path .\edamame-ng-catalog-2026-09-25.zip).Path, $destination)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Edamame-NG.ps1 -CatalogDir (Join-Path $destination 'catalog') -CveDetails CVE-2021-44228
```

The ZIP extraction step uses .NET's ZIP library. A networkless native PowerShell 3 guest extracted the release ZIP into an empty directory, verified all 595 shard hashes and the 397,443-record index, and passed direct queries and a fixture scan. A catalog downloaded from another source needs its own integrity and provenance review.

Build the pack from the **2026-09-25 baseline asset** that matches the bundled index. This is a development-time local operation; it makes no network requests. Allow space for the outer ZIP, temporary inner ZIP, staged gzip payload, and any previous generation. The builder refuses a different baseline against an existing catalog. An installed pack can be rebuilt in place only with identical source provenance, including the baseline filename. For a new baseline or changed provenance, build into a fresh catalog and review the complete replacement.

```sh
python3 scripts/build_cve_ids.py \
  --input 2026-09-25_all_CVEs_at_midnight.zip.zip \
  --expected-sha256 35f620251bc2efadd11fca5316085be0e729043af8b61e96b65347007ef7b97e \
  --with-local-details --with-all-details
python3 scripts/build_cve_ids.py --verify-all-details
```

The builder verifies the publisher digest, record identity/state, duplicates, shard limits, and exact complete detail/ID equality before activation. `all-cve-details-source.json` records provenance and the SHA-256 of the generation's small `shards.tsv` manifest. The ignored `all-cve-details/installed` marker binds that source manifest and is replaced last. Compressed payloads and the marker stay out of Git; small manifests and synthetic fixtures can be reviewed. A source clone without the marker uses the sparse fallback. Transfer a complete verified generation and its source manifest before copying the install marker last; verify the destination with `--verify-all-details`.

Bash and native PowerShell 3 read only requested shards, once per scan batch. They check both manifest hashes and each touched compressed shard's hash, size, row count, and layout. Gzip data is streamed with a 16 MiB row limit and 256 MiB expanded shard limit. No full detail corpus is loaded at startup. A missing or damaged declared shard in an installed pack yields `integrity-failed`; direct detail queries exit unsuccessfully, while scans retain other evidence and healthy detail rows. These local checks do not authenticate a pack obtained from an untrusted source. Use the verified baseline and publisher digest when building it.

`catalog/poc_refs.tsv` tracks eight PoC references and review state. The only packaged PoC is a small MIT-licensed adaptation of a pinned [sudo chroot research script](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot/tree/5c36150c6b4e64961ca133e618da1a48d1444d22), with its license and SHA-256. The [research advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) describes the flaw. The adaptation restricts commands to `--probe` and `--shell`, sends an empty password input for the probe, and cleans its staging directory on exit. A disposable Debian 13 VM proved UID 0 and an interactive root shell with a vulnerable upstream sudo 1.9.16p2 build; the same probe failed promptly with patched 1.9.17p1. The Linux runner accepts this as `cve-2025-32463-lab` only when the **exact tested sudo and PoC SHA-256 digests** match. Other distro builds and vendor backports remain unsupported until individually verified. The other seven PoC references remain links without bundled code. The [CVE-2024-1086 reference](https://github.com/Notselwyn/CVE-2024-1086) is explicitly marked as a kernel crash risk. This is an incomplete PoC corpus; the catalog manifest makes that state visible.

The CVE recipe is disabled on ordinary scans. Add `--enable-cve-2025-32463-lab` to a Linux Scan or Resume only on the isolated, exact-build fixture. This flag is required again for Resume. The fixture sudo binary and bundled PoC must be under root-owned paths with no group or other write permission; a normal user-owned checkout cannot serve as the lab PoC path. Install the bundle under a protected directory and pass `--catalog-dir` if needed. The runner checks those paths, fixed system utility paths, exact digests, and a bounded UID 0 probe before selecting the recipe.

## Current automatic recipes

| Platform | Recipe | Proof |
| --- | --- | --- |
| Linux | Already root | Current UID is 0 |
| Linux | Passwordless sudo for `/bin/bash` | Exact shell command runs with UID 0 |
| Linux | SUID `/bin/bash` | Preserved-privilege shell runs with UID 0 |
| Linux | SUID GNU `find` at `/usr/bin/find` or `/bin/find` | A bounded `bash -p` probe confirms effective UID 0 before opening the shell |
| Linux | `cap_setuid` on Python | Python can set UID 0 |
| Linux | Accessible Docker socket with a local image | Read-only host bind and chroot prove UID 0 |
| Linux | CVE-2025-32463 exact lab build | Exact vulnerable sudo and PoC digests, UID 0 probe, then shell |
| Windows | Already SYSTEM | Current token SID is `S-1-5-18` |
| Windows | Already elevated Administrator | Current token has Administrator role |
| Windows | Administrator membership with UAC | Elevated child verifies its token and writes a proof marker |
| Windows | Elevated Administrator to SYSTEM | Approved, reviewed PsExec opens a shell in the current interactive session; the shell process verifies SID `S-1-5-18` |
| Windows | Administrator membership with UAC to SYSTEM | UAC consent followed by the approved PsExec route; the SYSTEM shell process writes its identity proof |
| Windows | Standard user to SYSTEM on exact `EdamameWeakSvc` lab fixture | Effective service rights, protected fixture ID, a SYSTEM named-pipe client token, and restored service path before shell entry |

The Windows UAC paths prompt through the operating system and start with a user who is already an administrator. The weak-service recipe is the current standard-user route and applies only to its named lab fixture. The runner checks effective service rights, uses a private pipe, independently impersonates the connected client to verify SID `S-1-5-18`, and restores the original service path before showing a shell. A separate current-user watchdog restores that path if the operator process is killed during service startup. PsExec's local service creation requires approval on Scan and again on Resume. PsExec may install a service executable under Windows, create service registry state, and persist its EULA acceptance; interruption may leave service residue. The runner pins the reviewed PsExec64.exe v2.43 digest, so a changed release fails closed pending review and disposable-guest acceptance. The scripts report other unsupported paths instead of running unreviewed exploit binaries or changing tasks, drivers, or the kernel. CVE names from enumerators are suggestions with source links, not proof of vulnerability. The accepted sudo CVE recipe is limited to the exact lab build; it does not infer vulnerability from version text. Credential values in raw output are not replayed automatically. In `coverage.tsv`, `checked` for a broad enumeration area means the named external collectors completed and their output was saved; it does not certify every subcheck or an exploitable path. Unverified exploitation areas are `unsupported`, and incomplete collectors get separate partial tool rows.

On domain joined Windows hosts, the script runs SharpHound **Default** collection. This queries other domain joined computers and can take longer than local checks. Its ZIP is left for the operator. No off-host exploitation, relay, or poisoning is performed.

## Verification

Local synthetic checks:

```sh
bash -n edamame-ng.sh
shellcheck -S warning edamame-ng.sh
python3 tests/test_linux.py
python3 tests/test_catalog.py
pwsh -NoProfile -File tests/test_release.ps1
pwsh -NoProfile -File tests/test_windows_catalog.ps1
pwsh -NoProfile -File tests/test_capture_verbose.ps1
pwsh -NoProfile -File tests/test_windows_async.ps1
```

On a disposable Windows guest, `tests/test_psexec.ps1 -ArchivePath <verified-PSTools.zip>` checks official archive extraction, Authenticode, SHA-256, verified-cache fallback, and tamper rejection without contacting the network. It requires the current official ZIP as an external fixture.

`tests/test_windows_weak_service.ps1` checks native PowerShell 3.0 and 5.1 parsing, trusted system binaries, the service adapter, bounded pipe frames, and independent pipe-client SID observation. Run it as the standard fixture user with `-ExpectedNotSystem` as well as under the guest administrator account. The [weak-service acceptance record](docs/windows-weak-service-acceptance-2026-09-25.md) includes the standard-user shell, Resume, refusal and prerequisite failures, forced parent termination, restoration, and disposable VM cleanup.

The PowerShell release test parses `Edamame-NG.ps1` and checks local and release digest handling. Native Windows PowerShell 3.0 and 5.1 guests passed the focused capture, live verbose output, concurrent CVE screening, catalog, release, security, and weak-service adapter tests. These focused tests use fake assets and make no network requests. A separate [PowerShell 3 acceptance run](docs/windows-powershell-3-acceptance-2026-09-25.md) proved the fixed service fixture from a standard user, interactive SYSTEM Resume, and prerequisite refusal after fixture removal. The [offline and concurrent check record](docs/offline-concurrency-acceptance-2026-09-25.md) lists the cross-platform evidence and remaining enumerator limits.

`tests/integration_suid_find.sh` repeats the SUID `find` Scan/Resume checks with fake offline enumerators. Run it only as root inside an explicitly disposable **unprivileged LXC** guest with `EDAMAME_DISPOSABLE_LXC=1`; it refuses other environments with exit 77, restores `/usr/bin/find` ownership and mode, and deletes its temporary outputs.

Isolated Proxmox acceptance uses disposable, snapshot-restorable guests. Keep non-test guests and other test guests unchanged. Test fresh clones on isolated bridges, verify an elevated shell and Resume, then delete the clones. The public proof records anonymize the hypervisor name, internal domains, bridge names, and host segments of run IDs; test results and screenshots remain. See [acceptance-2026-09-25.md](docs/acceptance-2026-09-25.md), the first [test matrix](docs/matrix-2026-09-25.md), [extended acceptance](docs/extended-acceptance-2026-09-25.md), [workgroup acceptance](docs/workgroup-acceptance-2026-09-25.md), [CVE-2025-32463 acceptance](docs/cve-2025-32463-acceptance-2026-09-25.md), [Windows 5.1 catalog acceptance](docs/windows-5.1-catalog-acceptance-2026-09-25.md), the [additional distribution matrix](docs/additional-matrix-2026-09-25.md), [SUID find acceptance](docs/suid-find-acceptance-2026-09-25.md), [Windows UAC to SYSTEM acceptance](docs/windows-uac-system-acceptance-2026-09-25.md), [Windows weak-service acceptance](docs/windows-weak-service-acceptance-2026-09-25.md), and [Windows 11 client acceptance](docs/windows11-client-acceptance-2026-09-25.md) for observed results and gaps. General Windows weak-service exploitation remains unsupported outside the exact lab fixture.

The [Windows Server 2025 acceptance](docs/windows-server-2025-acceptance-2026-09-25.md) covers a standard-user workgroup scan, the fixed weak-service proof and Resume, a new isolated domain controller, SharpHound Default, complete executable WinPEAS and PrivescCheck runs, and an interactive domain Administrator to SYSTEM shell.
