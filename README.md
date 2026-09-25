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

The older LSE release does not publish a SHA-256 in GitHub's release listing. For that asset, Edamame-NG prints a warning, hashes the official HTTPS download, and uses that hash to check later cached copies. This is a recorded digest, not independent upstream checksum validation. Windows has `-ToolTimeoutSeconds` (default 600) to retain partial output when an external enumerator stalls; Linux uses 600 seconds for each enumerator.

The run directory is private (mode 700 on Linux; current-user ACL on Windows). Raw enumerator output can contain credentials. Each enumerator writes to `.capture` first. Console alerts contain counts and verified paths, never credential values. Only after the alerts are printed does the script move raw output to `linpeas-output.txt`, `lse-output.txt`, `winpeas-output.txt`, `privesccheck-output.txt`, and, when applicable, `sharphound.zip`. Inspect the run directory locally and handle it as sensitive evidence.

`tools.tsv` records release tag, source, and SHA-256. `findings.tsv`, `attempts.tsv`, `coverage.tsv`, and `cve-candidates.tsv` provide the decision record. A successful recipe is recorded by ID and evidence in `success.tsv` or `success.json`. Resume checks its prerequisites again and skips enumeration.

## Current automatic recipes

| Platform | Recipe | Proof |
| --- | --- | --- |
| Linux | Already root | Current UID is 0 |
| Linux | Passwordless sudo for `/bin/bash` | Exact shell command runs with UID 0 |
| Linux | SUID `/bin/bash` | Preserved-privilege shell runs with UID 0 |
| Linux | `cap_setuid` on Python | Python can set UID 0 |
| Linux | Accessible Docker socket with a local image | Read-only host bind and chroot prove UID 0 |
| Windows | Already SYSTEM | Current token SID is `S-1-5-18` |
| Windows | Already elevated Administrator | Current token has Administrator role |
| Windows | Administrator membership with UAC | Elevated child verifies its token and writes a proof marker |

The Windows UAC path prompts through the operating system. It is elevation for a user who is already an administrator, not a standard-user to SYSTEM exploit. The scripts report unsupported paths instead of running unreviewed exploit binaries or changing services, tasks, privileged files, registry keys, drivers, or the kernel. CVE names from enumerators are suggestions with source links, not proof of vulnerability. No CVE exploit recipe has been accepted yet. Credential values in raw output are not replayed automatically. The `coverage.tsv` file says `checked`, `inapplicable`, or `unsupported` for each checklist area, with separate tool status rows for partial runs.

On domain joined Windows hosts, the script runs SharpHound **Default** collection. This queries other domain joined computers and can take longer than local checks. Its ZIP is left for the operator. No off-host exploitation, relay, or poisoning is performed.

## Verification

Local synthetic checks:

```sh
bash -n edamame-ng.sh
shellcheck -S warning edamame-ng.sh
python3 tests/test_linux.py
pwsh -NoProfile -File tests/test_release.ps1
```

The PowerShell release test parses `Edamame-NG.ps1` and checks local and release digest handling. It runs on PowerShell 7 for development. The Windows capture test exercises subprocess completion, failure, and timeouts on Windows PowerShell 5.1. These focused tests use fake assets, never exercise privilege escalation, and make no network requests.

isolated Proxmox acceptance uses disposable, snapshot-restorable guests. Keep non-test guests and other test guests unchanged. Test fresh clones on an isolated bridge, verify an elevated shell and Resume, then delete the clones. See [acceptance-2026-09-25.md](docs/acceptance-2026-09-25.md) for observed results and gaps. A Windows standard-user to SYSTEM recipe must pass acceptance before being enabled.
