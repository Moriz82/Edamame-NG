# Extended isolated-lab acceptance — 2026-09-25

This run tested additional supported recipes and low-privilege domain contexts on disposable guests. The guests used temporary bridges on `lab-hypervisor`; no current assessment target was used. The existing AD lab host was unreachable from the testing Mac, so the Windows cases used isolated clones of the stopped CPTS AD lab. This note contains no credentials or raw enumerator output.

## Linux

| Guest | Configuration | Result |
| --- | --- | --- |
| VM 1400, [Metasploitable 2](https://www.vulnhub.com/entry/metasploitable-2,29/) | Original Ubuntu 8.04, i686, restricted `msfadmin` user; static isolated IP. The download's calculated SHA-256 was `a26ea2d80de1884080913c94eb12cd62c82ee0c8aea889a7841131cef55823ae`. VulnHub did not supply an independent digest. This old image lacks `timeout`, so a disposable Perl alarm wrapper supplied that documented prerequisite. | Run `20260925T075415Z-metasploitable-4635`: LinPEAS and LSE checked; 27 CVE suggestions, no supported recipe. Alerts preceded output files, directory mode 700, explicit Resume exited 2. The CVE list was not executed. |
| CT 1402, Debian 13.1 | Unprivileged container with nested Docker and a local Alpine 3.20 image (`sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc`). Package and image preparation used LAN DHCP before the container moved to an isolated bridge. Only then was the restricted test user added to the Docker group. | Run `20260925T081148Z-edamame-docker-540`: LinPEAS and LSE checked; `docker-host-root` verified, with a protected run directory and alerts before files. Resume opened an interactive UID 0 shell in the disposable container root filesystem. Default Resume skipped enumeration. Removing Docker group membership made Resume exit 1. |
| CT 1402, Debian 13.1 | Root inside the unprivileged container, not root on the Proxmox host. | Run `20260925T081552Z-edamame-docker-61538`: both enumerators checked; `already-root` selected before other recipes; Resume reverified UID 0. |

## Windows

Disposable VM 1410 (Windows Server 2022 DC) and VM 1411 (Windows Server 2022 domain member) resolved the same isolated `lab-a.invalid` domain. The test account was created only in the cloned domain. Its password and raw run files were never placed in Git or shared context. The verified domain lockout threshold was zero; authentication attempts were confined to these two guests. Clocks were resynchronized before Kerberos testing.

| Context | Result |
| --- | --- |
| Domain user on member, no local admin rights | First run `20260925T080719Z-LAB-WKS01-4872` exposed a domain detection bug: WMI denied access, so SharpHound was skipped. The script now falls back to `Domain.GetComputerDomain()`. Fixed run `20260925T081355Z-LAB-WKS01-2732` completed SharpHound Default and saved a 32,749-byte ZIP with seven JSON entries. WinPEAS and PrivescCheck timed out with labeled partial output; alerts preceded saved files; the protected run directory had one explicit user ACL. No local recipe was verified, and Resume without a success record exited 1. |
| Domain user temporarily granted local Administrator on member | Run `20260925T082009Z-LAB-WKS01-4992` verified `already-admin` and saved a readable SharpHound ZIP. Resume reverified the Administrator token and skipped enumeration. After removal from local Administrators, a fresh token was not elevated and Resume exited 1. |
| Domain user on controller | Run `20260925T082158Z-LAB-DC01-2812` completed SharpHound Default and saved a 32,726-byte ZIP with seven JSON entries. WinPEAS and PrivescCheck retained labeled partial output. Alerts preceded saved files; the protected run directory had one explicit user ACL. No local recipe was verified, and Resume without a success record exited 1. |

The member scan used a disposable CredSSP remoting session so the domain user could query the cloned DC. The controller scan used a Kerberos remoting session. The test account was never used to attempt access outside the isolated lab. SYSTEM scan and Resume results on two DCs and two members are in [the earlier matrix](matrix-2026-09-25.md).

| Current recipe | Live proof |
| --- | --- |
| Linux `already-root`, `sudo-shell`, `suid-bash`, `python-cap-setuid`, `docker-host-root` | All five passed on disposable guests across the two acceptance rounds. The Docker proof reached the disposable container root filesystem, not the Proxmox host. |
| Windows `already-system`, `already-admin` | Both passed and replayed. Removing Administrator membership invalidated its saved recipe. |
| Windows `uac-admin` | No interactive consent proof. These headless remoting sessions yielded a full admin or standard token, so this route remains unaccepted. |
| Standard-user to SYSTEM and CVE exploitation | No enabled recipe exists. |

## Cleanup and limits

VMs 1400, 1410, and 1411 and CT 1402 were stopped and destroyed. Final checks found no matching guest configurations or ZFS volumes, temporary bridges, HTTP listener, loop devices, or staging directory. Non-test guests and other test guests remained running; source guests remained stopped. `labpool` reported healthy. Local temporary test files, including the disposable domain credential, were removed. Only current reviewed recipes were attempted. CVE strings remain suggestions, and no new exploit recipe or credential validation was enabled.
