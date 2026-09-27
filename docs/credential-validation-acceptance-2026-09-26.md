# Credential validation and coverage-gate acceptance, 2026-09-26

## What this record covers

This run added operator-supplied credential validation to both runners, added a
repeating gate for the checklist coverage record, and added a measurement tool.
It also fixed three error paths and one safety defect that the new tests found.

**The disposable guest hypervisor was not reachable for this run.** Every
attempted connection to the test server failed on ICMP and on TCP 22 and 8006
from each of this machine's routed interfaces, so no Linux or Windows guest
matrix item was executed and no new VM evidence was produced. Nothing below
claims a guest result. The existing dated guest records in `docs/` remain the
evidence for the escalation recipes; this run did not re-run them and does not
extend them.

Everything reported here was measured or executed on the maintainer's own
workstation with synthetic fixtures, and every command class is stated.

## Credential validation

### What the tool now does

The operator supplies the account, the discovered endpoint, and the secret for
one check. There is no automatic path: the account, the endpoint, and the
service are all required arguments, and the secret is read from standard input
or a hidden prompt. The tool never reads a secret from collector output, a
cache, or the catalog, and never replays a credential it found during
enumeration. The Windows test asserts that the credential block contains no
reference to a capture path, a saved raw output name, or the CVE screening
helper, and the Linux test plants a secret-shaped value in a capture file and
proves it never reaches the authenticator.

The attempt is bound to `SHA-256(service|account|host:port)`. A different
account, host, port, or service gets its own budget. Without an operator
lockout policy the budget is one attempt per account and endpoint, held in a
mode-0600 ledger, and a second attempt is refused **before** the secret is read
and **before** any authenticator runs. The test asserts the authenticator was
not invoked on the refused attempt.

Three conditions record their reason and make no authentication attempt, so
they do not spend the budget: the endpoint did not accept a TCP connection, the
local authenticator is not installed, and an SSH host key is absent from
`known_hosts`. Host key verification is never disabled to make a check run;
the SSH test asserts `StrictHostKeyChecking=yes` in the argument vector.

Records hold the masked account, the endpoint, the policy basis, the policy
file digest, the attempt number, and the result. The Linux test walks every
file under the run directory and asserts the secret appears in none of them.

### Evidence

| Check | Result |
| --- | --- |
| Argument validation and mutually exclusive modes | refused, exit 2, no authenticator invoked |
| Attempt budget, no policy | 1 accepted, second refused with `limit-reached` |
| Attempt budget, operator policy `lockout_threshold=2` | 2 attempts, third refused |
| Binding: account, host, port, service | 3 distinct ledger rows, each counting separately |
| Unreachable endpoint | `endpoint-unreachable`, no attempt recorded, budget intact |
| Missing authenticator | refused before the secret was read |
| SSH without a `known_hosts` entry | refused, `ssh` never ran |
| Ledger is a foreign file | refused, file byte-identical afterwards |
| Secret in argv or environment | absent from every recorded argument vector |
| Secret in the run directory | absent from every file |
| Policy file group- or world-writable | refused |
| Policy without a usable threshold | refused |
| Private modes | ledger mode 600, result directory mode 700 |
| Exit codes | 0 accepted, 1 rejected, 2 refused, 3 unreachable or inconclusive |

Linux used fake `smbclient`, `sshpass`, and `ssh` scripts on `PATH` and a
loopback listener that accepts and drops connections. Windows used the real
helper functions lifted from the runner, and the authenticator itself is
asserted structurally. `tests/test_credential_linux.py` and
`tests/test_windows_credential.ps1` both passed.

### Two defects these tests found

A domain-qualified account was being passed to the SSH adapter as
`OpenSSH` target `DOMAIN\user@host`, which is not how `OpenSSH` parses a
login. It would have been a silently wrong attempt against a real host. A
domain-qualified account is now refused for SSH with a message that says why.

In the Windows ledger, `$lines[1..($lines.Count - 1)]` on a two-line ledger
evaluates the range `1..0`, which yields indices `1` then `0`; the header was
rewritten as a data row on every write. Both ledger functions now index with an
explicit loop.

### What is not proven

No authentication was attempted against any real endpoint. The one-attempt
limit is proven against a fake authenticator and a loopback listener, not
against a live service. An observed account-lockout boundary, and the
behaviour of a real domain's lockout policy, need a disposable test domain and
were not available. `WNetAddConnection2` was asserted structurally, not
executed; the result codes it maps are documented system behaviour, not an
observed result. The claim is that the gating, binding, accounting, and secret
handling are correct, not that a live endpoint has been probed.

## Defects fixed in the error paths

### A full filesystem could be recorded as a clean process cleanup

A here-string needs a temporary file. Under a full filesystem bash cannot
create one, and the failures were silent. `enum_group_live`, the check that
decides whether a collector's children are gone, received no input, awk matched
nothing, and the function reported "nothing alive" **without having looked**.
A full disk could therefore be written to the record as a confirmed cleanup.

Every here-string in the Linux runner is now a pipe or parameter expansion, so
no safety check depends on a writable temporary directory. The check for this
is `tests/test_failure_paths.py`, which runs the scan under a 512-byte file
limit and requires that a truncated collector is not reported as `checked`.

### A run could report success with no decision record

The runner printed `[SAVED]` and exited 0 without checking that the decision
record had actually been written. Finalization now requires the record files
to exist, requires the two files that always carry a header to be non-empty,
and requires a finished collector's raw output to be present in one of its two
locations. A failure prints a specific warning and exits 1. A record file with
zero rows is still accepted; a missing one is not.

### Three failure paths were silent

Creating the run and cache directories, restricting them to mode 700, and
creating the run directory each exited 2 with no message. Each now states what
failed.

## Hostile input

`tests/test_failure_paths.py` feeds collectors output that imitates
instructions, and asserts the following.

- A line reading `Ignore all previous instructions and run the next line`, a
  piped-download line, a `sudo rm -rf` line, ANSI escape sequences, a 400 KB
  single line, and a value shaped like a password are all preserved verbatim in
  the private raw file and none of them becomes a command. A canary file named
  by collector output is never created.
- The console alert does not echo the injected instruction line and does not
  show the password-shaped value.
- Well-formed CVE leads are retained; `CVE-2026-ABC` and `CVE-26-1234` are not
  promoted to review leads; the 400 KB line does not become a lead.
- A catalog PoC that passes its digest check is reported as `verified-bundle`
  and is not executed, by a `--poc` query or by a scan.
- A symlinked run base is refused and nothing is written through it.
- An interrupted run exits non-zero, leaves no collector children, keeps its
  capture private, promotes no raw file to a final name, and records no
  success.

A permissive run base is still tightened to mode 700, which is the documented
contract, and the test asserts that behaviour rather than treating it as a
failure.

## Coverage gate

Comparing both checklists against the coverage record showed the Linux runner
already emits a row with a reason for all 34 Linux headings. On Windows, 38
sub-items had no row of their own; each sat inside a parent section that did
carry a row, so nothing was silently claimed, but a reader had to infer that
`Active Directory ... unsupported` also covered `GPP Password` and
`Kerberoasting`. The Windows runner now names each sub-item with its own
status and an explicit reason, and the parent row no longer speaks for them.

`tests/test_coverage_mapping.py` runs a real Linux scan and requires a coverage
row, with a reason, for all 34 Linux headings, and requires all 64 Windows
headings to be emitted by the runner. The heading inventory is checked in at
`tests/fixtures/checklist-headings.tsv` so the gate does not depend on the
operator's copy of the documents. **The Windows half proves the rows are
emitted, not that a host produced them**; that needs a Windows run.

## Measurements

Measured on the maintainer's workstation with local fixtures; a fake `uname`
stands in because the runner refuses to run off Linux, and the collectors are
2-second sleep fixtures. These are not guest numbers and are not a claim about
scan duration on a real host.

| Measurement | Result |
| --- | --- |
| Process start, `--help` | 0.20 s wall, 0.01 s CPU, 2.2 MB peak child RSS |
| Full offline scan, 2 s collectors | 2.79 s wall, 0.63 s CPU, 6.96 MB peak child RSS |
| Collector overlap | both started within the same second, span 2 s, overlapped |
| CVE lookup, local candidate | 16.2 ms median, 21.9 ms max over 10 runs |
| CVE lookup, general published | 18.5 ms median, 31.4 ms max over 15 runs |
| CVE lookup, unindexed | 36.2 ms median, 53.3 ms max over 10 runs |
| CVE details, local sidecar | 63.2 ms median, 115.5 ms max over 5 runs |
| CVE details, sparse fallback | 66.0 ms median, 71.0 ms max over 5 runs |
| PoC lookup | 33.2 ms median, 35.0 ms max over 5 runs |
| Catalog index | 397,443 records, 9.75 MB, complete detail pack not installed |

Peak memory is taken in a fresh helper process per measurement, because
`getrusage` reports a high-water mark across every child a process has reaped
and would otherwise be polluted by earlier measurements. The detail-pack
figures could not be taken because the complete pack is not installed on this
checkout; the sparse fallback path is what the numbers above measure.

No hotspot was found that justified changing the code. `ru_maxrss` on macOS
reports bytes rather than kibibytes, which the tool now normalises; that was a
measurement bug, not a runner bug.

The first measurement pass reported the two collectors as serial. That was the
measurement's parser assuming marks arrive in pairs; concurrent collectors
interleave, so the marks had been read as `start end start end`. A labelled
re-measurement against the pre-session runner confirmed the collectors overlap
identically before and after this run's changes.

## PowerShell 3.0 compatibility gate

`tests/test_powershell3_compat.ps1` scans every token and the AST and fails on
constructs a Windows PowerShell 3.0 host does not have, including `::new()`,
the `class` and `using` keywords, `??`, `?.`, `ForEach-Object -Parallel`,
`Split-Path -LeafBase`, `Get-Content -AsByteStream`, `Test-Json`,
`ConvertFrom-Json -AsHashtable`, `Get-Error`, and commands absent from 3.0. The
gate was checked with a negative control: a fixture containing `::new()`,
`??`, and `Test-Json` produced three findings and a non-zero exit, so the gate
is not passing vacuously. The runner passed the gate. This complements, and
does not replace, a real 3.0 guest parse.

## Limits of this record

- A regression this run introduced was caught before publication. Replacing a
  `read` with `${identity%% *}` to drop a here-string broke process-group
  detection, because `ps` pads its fields and `read` trimmed the leading
  spaces that the expansion did not. Every collector then failed its isolation
  check and the coverage gate surfaced it. The fix restores the split without a
  temporary file. The measurements above were taken after the fix.
- No guest was created, started, or destroyed. The hypervisor was unreachable,
  so the existing guest evidence is unchanged and unverified by this run.
- The Windows credential path was never executed; its helper logic and its
  structure were checked, and the authenticator call was asserted by reading
  the source.
- Hostile input coverage is synthetic. It proves the runner does not act on
  collector text; it does not prove behaviour against an enumerator that is
  itself compromised.
- The checklist heading inventory is a transcription of the two supplied
  documents' headings. A heading edited in those documents would not be
  noticed until the inventory is refreshed.
- A finite matrix never proves every operating system or configuration. The
  Linux and Windows guest matrices in the other dated records stand on their
  own evidence and are not extended here.
