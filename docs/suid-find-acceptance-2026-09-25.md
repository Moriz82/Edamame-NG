# SUID `find` acceptance — 2026-09-25

Disposable Debian 13.1 unprivileged CT 1710 (`edamame-find`) ran on `lab-hypervisor` with an isolated, uplink-free `lab-net-06` bridge. It used the existing Proxmox Debian 13 template, whose calculated SHA-256 was `ca6dffb91c3239fedc30af2c11389198140de1f1fc3d58082f3d9f4239b92e1b`. The staged Linux runner SHA-256 was `76df5e25a12be76c975f34d9706d3474bb25cf0d5c2d9a23a08b96ef6355e6b3`. The local LinPEAS and LSE assets had adjacent SHA-256 files. No production VM or current assessment target was used.

| State | Run or action | Observed result |
| --- | --- | --- |
| Restricted `tester`, normal `/usr/bin/find` mode 755 | Scan `20260925T110451Z-edamame-find-357` | LinPEAS and LSE completed. Alerts preceded final raw files. No supported recipe verified. |
| Only `/usr/bin/find` changed to root-owned mode 4755 inside the CT | Scan `20260925T110710Z-edamame-find-59528` | The `suid-find` probe returned effective UID 0, selected the recipe, and alerted before saving final raw files. |
| Fixture still present | Interactive Resume | Resume skipped enumeration and opened a privileged Bash shell. `id -u` returned `0`; `whoami` returned `root`. The run count stayed at two. |
| Fixture removed; `/usr/bin/find` back to mode 755 | Resume | Recheck rejected the recipe with exit 1 and requested a new scan. |
| SUID fixture owned by `tester` rather than root | Resume | Recheck again rejected with exit 1. The disposable binary was returned to root ownership and mode 755. |

Both scans had 31 checked, one inapplicable, and six unsupported checklist areas. Each run directory was mode 700 and its raw LinPEAS/LSE files mode 600. Each scan extracted 15 CVE strings for review only; none was treated as a vulnerable-build proof. The shell was root **inside the unprivileged container**, not on the Proxmox host.

The runner now uses Bash's effective UID for root and SUID Bash checks, so a PATH-supplied fake `id` cannot satisfy those proofs. The `suid-find` probe calls fixed system paths and checks actual effective UID 0 before recipe selection. It does not change a file or service on the assessed host.

The repeatable `tests/integration_suid_find.sh` ran on a second isolated unprivileged Debian 13 CT 1720. Its LXC UID map began `0 100000`, and the explicit disposable marker was supplied. It passed baseline, SUID Scan, no-shell Resume without re-enumeration, and missing-SUID/non-root-owner rejection using fake offline enumerators. The fixture restored `/usr/bin/find` to root ownership and mode 755 and removed its temporary directory. Without the explicit marker, it exited 77 and left the binary unchanged.

CTs 1710 and 1720, their ZFS volumes, `lab-net-06` and `lab-net-07`, staging archives, and SSH control sessions were removed. Final readback found no matching disposable resources. The source template was pre-existing and left in place. non-test guests and other test guests remained running, and `labpool` was `ONLINE`.
