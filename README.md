# Edamame-NG

Host-run Linux and Windows privilege escalation assessment scripts. The two supplied checklists are coverage inventories; their example commands are not executed verbatim.

## Run

Linux (Bash, `curl`, `timeout`, `sha256sum` or `shasum`):

```sh
bash edamame-ng.sh --scan --output-dir "$HOME/edamame-ng-runs"
bash edamame-ng.sh --resume --output-dir "$HOME/edamame-ng-runs"
```

Windows (Windows PowerShell 5.1 or later):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Edamame-NG.ps1 -Scan
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Edamame-NG.ps1 -Resume
```

Without `--scan`/`-Scan` or `--resume`/`-Resume`, a previous success offers Resume as the default. `--no-shell`/`-NoShell` proves a recipe without opening a shell. `--tool-dir`/`-ToolDir` accepts predownloaded assets only when each asset has an adjacent `.sha256` file containing its expected SHA-256. A new scan checks current official releases unless a tool directory is supplied. A failed update uses only a previously verified cache copy and prints a warning.

For a scan with no network access, supply the verified local assets and the bundled catalog:

```sh
bash edamame-ng.sh --scan --tool-dir ./offline-assets
bash edamame-ng.sh --cve CVE-2025-32463
bash edamame-ng.sh --poc CVE-2025-32463
```

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Edamame-NG.ps1 -Scan -ToolDir .\offline-assets
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Edamame-NG.ps1 -Cve CVE-2021-36934
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Edamame-NG.ps1 -Poc CVE-2025-32463
```

`--cve`/`-Cve` reads the local CVE index. `--poc`/`-Poc` reports an offline PoC file only after checking its SHA-256; it does not execute it. Both query modes work without a scan or network request. Use `--catalog-dir`/`-CatalogDir` to select another local catalog. A scan also saves `cve-index.tsv`, which joins enumerator suggestions to local catalog candidates and labels unindexed or wrong-platform IDs.

The older LSE release does not publish a SHA-256 in GitHub's release listing. For that asset, Edamame-NG prints a warning, hashes the official HTTPS download, and uses that hash to check later cached copies. This is a recorded digest, not independent upstream checksum validation. Windows has `-ToolTimeoutSeconds` (default 300) to retain partial output when an external enumerator stalls; Linux uses 600 seconds for each enumerator.

The run directory is private (mode 700 on Linux; an explicit current-user and SYSTEM ACL on Windows). Raw enumerator output can contain credentials. Each enumerator writes to `.capture` first. Console alerts contain counts and verified paths, never credential values. Only after the alerts are printed does the script move raw output to `linpeas-output.txt`, `lse-output.txt`, `winpeas-output.txt`, `privesccheck-output.txt`, and, when applicable, `sharphound.zip`. Inspect the run directory locally and handle it as sensitive evidence.

`tools.tsv` records release tag, source, and SHA-256. `findings.tsv`, `attempts.tsv`, `coverage.tsv`, `cve-candidates.tsv`, and `cve-index.tsv` provide the decision record. A successful recipe is recorded by ID and evidence in `success.tsv` or `success.json`. Resume checks its prerequisites again and skips enumeration.

## Offline CVE and PoC catalog

`catalog/local-eop.tsv` contains 118 compact **candidate** records selected from the [CISA KEV catalog](https://github.com/cisagov/kev-data). `catalog/source.json` records the source version, release date, record count, and SHA-256 of the source snapshot. `scripts/update_catalog.py --input verified-kev.json` rebuilds it at development time without fetching data. `catalog/curated-eop.tsv` adds the local glibc [CVE-2023-4911](https://www.qualys.com/2023/10/03/cve-2023-4911/looney-tunables-local-privilege-escalation-glibc-ld-so.txt) as a review lead outside that KEV selection; its empty `kev_date` does not claim KEV status. The base catalog takes precedence if an ID appears in both files. The filter checks local privilege escalation terms and broad Windows/Linux product names. It can miss a relevant CVE or include one that does not apply to a host. A KEV listing confirms observed exploitation somewhere; it does not establish a vulnerable local build, missing patch, or safe exploit path. Edamame-NG never selects an escalation recipe from this text match alone.

`catalog/poc_refs.tsv` tracks seven PoC references and review state. The only packaged PoC is a small MIT-licensed adaptation of a pinned [sudo chroot research script](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot/tree/5c36150c6b4e64961ca133e618da1a48d1444d22), with its license and SHA-256. The [research advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) describes the flaw. The adaptation restricts commands to `--probe` and `--shell`, sends an empty password input for the probe, and cleans its staging directory on exit. A disposable Debian 13 VM proved UID 0 and an interactive root shell with a vulnerable upstream sudo 1.9.16p2 build; the same probe failed promptly with patched 1.9.17p1. The Linux runner accepts this as `cve-2025-32463-lab` only when the **exact tested sudo and PoC SHA-256 digests** match. Other distro builds and vendor backports remain unsupported until individually verified. The other six PoC references remain links without bundled code. The [CVE-2024-1086 reference](https://github.com/Notselwyn/CVE-2024-1086) is explicitly marked as a kernel crash risk. This is an incomplete PoC corpus; the catalog manifest makes that state visible.

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

The Windows UAC path prompts through the operating system. It is elevation for a user who is already an administrator, not a standard-user to SYSTEM exploit. The scripts report unsupported paths instead of running unreviewed exploit binaries or changing services, tasks, privileged files, registry keys, drivers, or the kernel. CVE names from enumerators are suggestions with source links, not proof of vulnerability. The accepted sudo CVE recipe is limited to the exact lab build; it does not infer vulnerability from version text. Credential values in raw output are not replayed automatically. The `coverage.tsv` file says `checked`, `inapplicable`, or `unsupported` for each checklist area; incomplete enumerators leave their broad areas `unsupported` and get separate partial tool status rows.

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
```

The PowerShell release test parses `Edamame-NG.ps1` and checks local and release digest handling. It runs on PowerShell 7 for development. The Windows capture and ACL tests exercise subprocess completion, failure, timeouts, private directories, and same-host Resume selection on Windows PowerShell 5.1. These focused tests use fake assets, never exercise privilege escalation, and make no network requests.

`tests/integration_suid_find.sh` repeats the SUID `find` Scan/Resume checks with fake offline enumerators. Run it only as root inside an explicitly disposable **unprivileged LXC** guest with `EDAMAME_DISPOSABLE_LXC=1`; it refuses other environments with exit 77, restores `/usr/bin/find` ownership and mode, and deletes its temporary outputs.

isolated Proxmox acceptance uses disposable, snapshot-restorable guests. Keep non-test guests and other test guests unchanged. Test fresh clones on isolated bridges, verify an elevated shell and Resume, then delete the clones. See [acceptance-2026-09-25.md](docs/acceptance-2026-09-25.md), the first [test matrix](docs/matrix-2026-09-25.md), [extended acceptance](docs/extended-acceptance-2026-09-25.md), [workgroup acceptance](docs/workgroup-acceptance-2026-09-25.md), [CVE-2025-32463 acceptance](docs/cve-2025-32463-acceptance-2026-09-25.md), [Windows 5.1 catalog acceptance](docs/windows-5.1-catalog-acceptance-2026-09-25.md), the [additional distribution matrix](docs/additional-matrix-2026-09-25.md), and [SUID find acceptance](docs/suid-find-acceptance-2026-09-25.md) for observed results and gaps. A Windows standard-user to SYSTEM recipe must pass acceptance before being enabled.
