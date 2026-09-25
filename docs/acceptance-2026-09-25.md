# Isolated Proxmox acceptance — 2026-09-25

Testing ran on `lab-hypervisor` with disposable clones attached to a temporary isolated bridge. No assessment target host was selected or tested. This record excludes credentials and raw enumerator output.

| Guest | Source | Disposable VMID | Snapshot | Observed result |
| --- | --- | --- | --- | --- |
| Linux Kali | Existing test guest | 1301 | `edamame-before-run` | Scan as UID 1000; LinPEAS timed out at 600 seconds with partial output; LSE completed; alerts preceded final output files. `sudo-shell` verified. Interactive Resume skipped enumeration and opened a root shell; `id -u` returned `0`. |
| Windows Server 2022 | Stopped lab source guest | 1302 | `edamame-before-run` | Windows PowerShell 5.1 parse and capture tests passed. Scan under the QEMU Guest Agent's SYSTEM token saved partial WinPEAS and PrivescCheck output after alerts. Resume skipped enumeration and reverified the SYSTEM token. This is identity proof, not standard-user escalation. |

Linux run ID: `20260925T055548Z-edamame-linux-test-1282`. Windows run ID: `20260925T051901Z-LAB-WKS01-1000` (guest local clock). Run output stayed inside the disposable guests and was removed with them.

The Windows clone was domain joined, but its domain controller was stopped and unreachable on the isolated bridge. SharpHound Default collection ran and recorded `partial-no-zip`; no ZIP was produced. A low-privilege Windows scheduled-task run could not be started on this clone, so no standard-user scan or standard-user-to-SYSTEM result is claimed. The current Windows recipes cover only an existing SYSTEM token, an existing elevated Administrator token, and UAC elevation for a member of Administrators. Credential validation and reviewed CVE exploit recipes remain unsupported on both platforms.

After testing, VMs 1301 and 1302 and their ZFS volumes were removed. The temporary `lab-net-01` bridge, transfer server, staged assets, mountpoint, and temporary SSH key were removed. Other test guests were running; the source guest was stopped. Non-test guests were not used.
