# Additional isolated guest matrix — 2026-09-25

Three unprivileged Linux containers ran on the disposable `lab-net-05` bridge on `lab-hypervisor`. The bridge used an isolated private subnet and had no uplink or default route. The containers had only bridge-local addresses. No production VM, source VM, or current assessment target was used. Raw enumerator output and credentials are excluded from this record.

The [Proxmox template mirror](https://download.proxmox.com/images/system/) supplied the templates; Proxmox reported a verified checksum on download. Calculated SHA-256 values of the downloaded archives were:

| Template | Guest | SHA-256 |
| --- | --- | --- |
| Debian 12 | CT 1700, `edamame-debian12` | `ff5c55cba730fc1e93bc7de3e0ea4aecb05c692094009cfcf2999973a56f15e5` |
| Fedora 43 | CT 1701, `edamame-fedora43` | `3518e6a8a6d7514a880b9ca2decd10c323e3207c7a9b1200020f488a4272045c` |
| openSUSE Leap 15.6 | CT 1702, `edamame-suse156` | `b8d19220505029cd3429ef4372b396421afeddff400ae6f5a695b8e89efafa05` |

All three shared the Proxmox `7.0.14-4-pve` kernel, so these tests exercise distribution userlands and script behavior, not independent guest kernels. The local LinPEAS and LSE files were verified against adjacent SHA-256 files before execution. `tools.tsv` recorded SHA-256 `395b8a97ac5f2b4082f4cc316620cd6628c0a476eecba07afab176750059013e` for LinPEAS and `ccb6a164caa590bc60615e7a4d5ecff9162b86dc8c782a15b1cccedee02ca095` for LSE in every run.

| Guest | Clean baseline run | Disposable SUID Bash run | Result |
| --- | --- | --- | --- |
| Debian 12 | `20260925T103623Z-edamame-debian12-381` | `20260925T104200Z-edamame-debian12-56055` | Both tools completed in each run; `suid-bash` verified, then Resume opened an interactive shell whose `id -u` was 0. Removing SUID made Resume exit 1. |
| Fedora 43 | `20260925T103558Z-edamame-fedora43-262` | `20260925T104135Z-edamame-fedora43-58132` | Same proof and prerequisite rejection. |
| openSUSE Leap 15.6 | `20260925T103558Z-edamame-suse156-625` | `20260925T104135Z-edamame-suse156-61680` | Same proof and prerequisite rejection. `/bin/bash` is a symlink; its resolved target returned to mode 755. |

Each clean baseline reported no supported recipe. All six scans alerted candidate counts before the final raw output filenames appeared. Each run directory had mode 700, and raw files mode 600. Each `coverage.tsv` had 31 checked areas, one inapplicable area, and six unsupported areas. The 15 CVE strings in each scan were **suggestions**, with no build or patch proof; none triggered a recipe. Resume used the saved recipe and skipped enumerators. After fixture removal, `/bin/bash` resolved to mode 755 in every guest.

The amended Linux runner and `curated-eop.tsv` were also copied into the protected guest fixture after the scans. The offline `--cve CVE-2023-4911` query returned `indexed-review-only` for Linux/glibc on each guest. This validates lookup compatibility, not vulnerability of those guests.

## Native Windows PowerShell 5.1 catalog proof

VM 1703 was a full clone of stopped Windows Server 2022 source guest, attached only to `lab-net-05`. The clone's QEMU Guest Agent ran PowerShell as its existing SYSTEM token. It received the amended `Edamame-NG.ps1` and three text catalogs over a bridge-local HTTP server. The copied script's SHA-256 matched the local file: `5bf71f9b4f42c743fe34755b2c916d2e2ad8442c49745a9f26ea9b1d6ffb99e9`.

Windows PowerShell `5.1.20348.4294` parsed the amended script with zero errors. Direct `-Cve` queries returned Linux/glibc `CVE-2023-4911` from the supplement and Windows `CVE-2021-36934` from the base catalog. `-Poc CVE-2024-1086` returned `reference-only` with `unreviewed-crash-risk`; it did not download or run a PoC. A deliberately conflicting supplement row for `CVE-2025-32463` did not override the base Linux/Sudo row. A four-ID `cve-index.tsv` join classified a Windows match, two Linux platform mismatches, and an unknown ID. Temporarily removing the supplement made `CVE-2023-4911` `unindexed`. The clone ran no enumeration or escalation recipe during this catalog check.

The remaining coverage limits are the same as in the main README: unsupported checklist areas, independent kernel and Windows version breadth, reviewed build-specific CVE recipes, standard-user-to-SYSTEM, interactive UAC, and credential validation. This matrix alone does not establish full privilege escalation coverage.

## Cleanup readback

CTs 1700–1702 and VM 1703 were stopped and destroyed. Their configurations and ZFS volumes were absent on readback. The temporary bridge, bridge-local server, guest staging, local transfer archive, and three downloaded templates were removed. Source guest remained stopped. Non-test guests and other test guests remained running, and `labpool` was `ONLINE`.
