# Curated local escalation leads

These entries supplement the CISA KEV text selection. They are **review leads**, not proof that a host is vulnerable or that a PoC is safe to run. Package versions can carry vendor backports. Verify the installed build, patch status, configuration, and prerequisites against the linked advisory before considering a recipe. None of these entries is an automatic recipe.

| CVE | Affected condition from the primary advisory | Fixed release or status | Source |
| --- | --- | --- | --- |
| CVE-2023-2640 | Ubuntu kernels with the two named OverlayFS changes and unprivileged user namespace access | Consult the exact Ubuntu kernel package status; a kernel version alone is insufficient | [Ubuntu](https://ubuntu.com/security/CVE-2023-2640) |
| CVE-2023-32629 | Ubuntu OverlayFS metadata copy-up permission checks and unprivileged user namespace access | Consult the exact Ubuntu kernel package status | [Ubuntu](https://ubuntu.com/security/CVE-2023-32629) |
| CVE-2023-4911 | glibc loader `GLIBC_TUNABLES` flaw; applicability depends on the exact distribution build | Consult vendor package status | [Qualys research](https://www.qualys.com/2023/10/03/cve-2023-4911/looney-tunables-local-privilege-escalation-glibc-ld-so.txt) |
| CVE-2024-0132 | NVIDIA Container Toolkit 1.16.1 or earlier, default configuration, crafted container image; CDI deployments are excluded by the maintainer | 1.16.2 | [NVIDIA advisory](https://github.com/NVIDIA/libnvidia-container/security/advisories/GHSA-q2v4-jw5g-9xxj) |
| CVE-2024-21626 | runc 1.0.0-rc93 through 1.1.11; leaked file descriptors can expose host paths during container launch or `runc exec` | 1.1.12 | [runc advisory](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) |
| CVE-2025-31133 | runc masked-path mount race; severity and route depend on container privileges and controls | 1.2.8, 1.3.3, 1.4.0-rc.3 | [runc advisory](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2) |
| CVE-2025-52565 | runc `/dev/console` mount race with malicious container configuration | 1.2.8, 1.3.3, 1.4.0-rc.3 | [runc advisory](https://github.com/opencontainers/runc/security/advisories/GHSA-qw9x-cqr3-wc7r) |
| CVE-2025-52881 | runc procfs redirection and label bypass; impact depends on container configuration and other protections | 1.2.8, 1.3.3, 1.4.0-rc.3 | [runc advisory](https://github.com/opencontainers/runc/security/advisories/GHSA-cgrx-mc8f-2prm) |

The 2025 runc advisories describe several maintained release branches. Read the complete advisory for the affected range and any distribution backport; the fixed release column alone is not an applicability test. Container escape can affect the **host outside the disposable guest**. Do not use a shared production Proxmox kernel or runtime for exploit acceptance.
