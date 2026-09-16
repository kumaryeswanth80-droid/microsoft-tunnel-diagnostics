# MTGDiag 7.4.7: use cases and testing guide

Copy `MTGDiag.sh` to the Linux Microsoft Tunnel server. Run it with Bash and
sudo, not with `sh`. No executable permission change is needed for the commands
below.

## Start here: no remediation

```bash
bash ./MTGDiag.sh --version
bash ./MTGDiag.sh --help
sudo bash ./MTGDiag.sh --mode self-test --non-interactive
sudo bash ./MTGDiag.sh --mode security-inventory --non-interactive
sudo bash ./MTGDiag.sh --mode security-updates --non-interactive
```

Expected outcomes:

| Command | Expected result |
| --- | --- |
| `--version` | `7.4.7`; no root required |
| `--help` | Available options; no root required |
| `--mode self-test` | Prerequisite checks only; this is not a vulnerability scan or a production certification |
| `--mode security-inventory` | Separate host and running Tunnel container scopes, complete Ubuntu package revisions, and PyJWT location/version |
| `--mode security-updates` | APT simulation for the selected installed host packages; no metadata refresh, package installation, restart, or reboot |

The security inventory does not scan every virtual environment, user-site
installation, stopped container, or unused image. An Azure Linux container
without `dpkg-query` or Python is reported as an inventory coverage gap, not as
vulnerability-free.

## Diagnostic use cases

| Use case | Command | What to expect |
| --- | --- | --- |
| Interactive menu | `sudo bash ./MTGDiag.sh` | Select a diagnostic or preview operation |
| Full baseline | `sudo bash ./MTGDiag.sh --mode full --non-interactive` | Host, proxy, container, endpoint, certificate, revocation, and release checks; internal test skipped without a URL |
| Host/container and certificate assessment | `sudo bash ./MTGDiag.sh --mode inventory --non-interactive` | Host inventory, health, certificates, revocation connectivity, and release assessment |
| Connectivity smoke test | `sudo bash ./MTGDiag.sh --mode connectivity --max-endpoints 5 --non-interactive` | Baseline inventory plus the first five discovered endpoints, not exhaustive coverage |
| All discovered endpoints | `sudo bash ./MTGDiag.sh --mode connectivity --all-endpoints --non-interactive` | Host and container endpoint probes where tools are available |
| Internal application | `sudo bash ./MTGDiag.sh --mode internal --internal-url https://app.example.internal/health --non-interactive` | Container access checks to your supplied URL; replace the example with an approved target |
| All existing scenario previews | `sudo bash ./MTGDiag.sh --mode preview-all --non-interactive` | Full diagnostics and six troubleshooting previews, reusing baseline health/release checks |
| Longer container startup allowance | `sudo bash ./MTGDiag.sh --mode inventory --health-wait-seconds 300 --non-interactive` | Wait for containers reporting `starting`, without repeating unchanged states |
| Dashboard-compatible log collection | `sudo bash ./MTGDiag.sh --mode log-collection --non-interactive` | Host/container inventory, bounded Tunnel journal, available container logs, and reports; no remediation or endpoint probes |

Diagnostic modes write evidence and may contact endpoints, but do not install
packages or run remediation without `--execute`. `preview-all` always disables
remediation and does not include the separate host package-update workflow.
It can generate local preview artifacts.

The separate browser dashboard can deploy the administrator-managed copy of this
script using a trusted publisher signature, then run `log-collection` or `full` with a
verified matching checksum. See [dashboard setup](dashboard/README.md). The
dashboard never passes `--execute` during either diagnostic workflow.

The dashboard also provides **Controlled remediation > Force upgrade (advanced)**.
It reuses the signed script's read-only upgrade preview, pins the published
version/digests, and requires separate custom-image consent plus
`APPROVE FORCE-UPGRADE`. The helper preserves a backup and submits one direct
monitor message, without packet capture or automatic rollback. This is an
advanced custom-image override, not the documented Intune site upgrade workflow.
It can interrupt VPN users. Success requires matching running image digests and
healthy containers; a timed-out submitted upgrade remains guarded against
resubmission. See the dashboard guide before using it.

For a modern full report, open **Evidence workspace > Full diagnostics** in the
dashboard and select **Run full diagnostics**. This runs full inventory,
host/container endpoint probes, certificate/revocation and release checks without
remediation. The tab provides live activity, highlighted failures and review
items, status counts, filtering and search. Internal application testing is
explicitly skipped without a configured URL. Host journal collection stays
separate. Runs have a 15-minute deadline; report limits and skipped/omitted
coverage are visible. A failed run does not overwrite the previous completed
report or imply that the host is healthy. Restart the updated dashboard and
approve the updated Linux helper installation before using the new operation.

Version 7.4.7 explains collection work before it runs: `[CHECK]` lines identify
the command/check, target and limits for host information, forwarding, proxy
inspection, container health/logs, `mst-cli` status, journal collection and report
packaging. Findings still appear only once as PASS/FAIL/REVIEW/etc.; activity
messages do not inflate finding counts or repeat cached diagnoses.

With the updated dashboard helper, **Live diagnostic activity** streams these
checks and their actual results while collection is running, followed by evidence
loading and rule analysis. It shows timestamps and elapsed time, not invented
percentages. Update the helper and deploy the signed 7.4.7 bundle before testing
the detailed stream. No shell tracing or credential-bearing command dumps are used.

For Microsoft Tunnel deployment prerequisites on Ubuntu 24.04 AMD64, use the
dashboard's **Check Tunnel prerequisites**, **Install prerequisite tools**, and
**Install / start Docker CE** controls. Installations require approved plans and
fresh sudo passwords, with stage-by-stage monitoring. Docker installation/start
requires a separate acknowledgement of runtime-managed networking effects.
Certificate, Intune configuration and network-reachability checks remain manual;
this does not enroll or install Microsoft Tunnel itself.

The separate **Dashboard connection prerequisites** panel installs diagnostic
dependencies, the remote helper and public-key trust for collecting logs.

## Troubleshooting use cases

These commands preview the selected workflow without executing remediation:

```bash
sudo bash ./MTGDiag.sh --scenario unhealthy
sudo bash ./MTGDiag.sh --scenario ip-starvation
sudo bash ./MTGDiag.sh --scenario bridge-conflict
sudo bash ./MTGDiag.sh --scenario container-down
sudo bash ./MTGDiag.sh --scenario upgrade
sudo bash ./MTGDiag.sh --scenario network-trace
```

| Scenario | Scope and caution |
| --- | --- |
| `unhealthy` | Reads the reported health state. The existing execute action resets a stored health value and restarts the agent; it does not resolve the underlying cause. Use only with an approved support procedure. |
| `ip-starvation` | Displays subnet capacity and allocation-error evidence; configuration changes remain administrative actions |
| `bridge-conflict` | Collects route/bridge overlap evidence; overlap alone is not proof of a fault because a bridge normally has its own route |
| `container-down` | Assesses containers; `--execute` requires `RESTART-TUNNEL` before restarting both |
| `upgrade` | Prepares a latest-release upgrade preview; `--execute` uses the existing forced-image upgrade workflow and requires `FORCE-UPGRADE-LATEST`. This is not Ubuntu host patching or guaranteed CVE remediation. |
| `network-trace` | `--execute` requires `NETWORK-TRACE`, starts tcpdump, and waits for Enter to stop. Capture only approved traffic; evidence may contain sensitive data. |

Use execute scenarios only interactively, with authorization and a maintenance
window where appropriate. Do not pipe approval tokens into the script.

## Ubuntu host package updates

This new mode is restricted to an Ubuntu 24.04 host and packages already
installed from these groups:

- glibc: `libc6`, `libc-bin`, `locales`.
- Python: `python3.12`, `python3.12-minimal`, `libpython3.12-minimal`,
  `libpython3.12-stdlib`, `libpython3.12t64`.
- Distribution-managed PyJWT: `python3-jwt`.

APT may also change dependencies. This is a targeted update to configured
repository candidates, not a security-only repository filter. It does not run
`dist-upgrade`, remove packages, override holds, use pip, patch containers, or
automatically reboot. APT maintainer scripts may restart services.

First preview:

```bash
sudo bash ./MTGDiag.sh --mode security-updates --non-interactive
```

This uses cached APT metadata, so a no-change preview does not prove the host is
up to date. For installation, obtain a recoverable backup and an approved
maintenance window, then run in an interactive SSH terminal:

```bash
sudo bash ./MTGDiag.sh --mode security-updates --execute
```

1. Type `REFRESH-HOST-SECURITY-PLAN` to authorize APT metadata refresh.
2. Review the fresh simulation, including dependency changes.
3. Type `APPLY-HOST-SECURITY-UPDATES` to authorize package installation.

Cancellation before the first approval changes no packages or repository
metadata. Cancellation before the second approval leaves refreshed metadata
but installs nothing. Held selected packages, inventory errors, metadata
refresh errors, and simulation failures block installation.

An installation failure can leave packages partially updated; examine the APT
log before retrying. There is no automatic rollback. Execution with
`--non-interactive` or without a terminal is rejected.

After applying updates, review the before/after inventory, APT restart guidance,
reboot-required notice, and fresh container health results. Schedule any required
restart/reboot, rerun inventory, and request a compliance rescan.

## Interpreting the reported CVEs

The supplied Ubuntu package versions were found on the host. Running Tunnel
containers identified themselves as Azure Linux 3.0; this does not prove they
have no unrelated vulnerabilities.

Vendor information consulted on September 16, 2026:

| Finding | Interpretation |
| --- | --- |
| glibc CVEs in the supplied report | Follow [USN-8737-2](https://ubuntu.com/security/notices/USN-8737-2); validate the complete Ubuntu revision against the vendor notice |
| CVE-2026-15308 | Ubuntu 24.04 Python 3.12 fix: `3.12.3-1ubuntu0.17` or later Ubuntu revision. See [Ubuntu status](https://ubuntu.com/security/CVE-2026-15308). |
| CVE-2026-32597 | The observed `python3-jwt` revision `2.7.0-1ubuntu0.1` already contains Ubuntu's backport. A runtime version of `2.7.0` alone cannot establish vulnerability. See [Ubuntu status](https://ubuntu.com/security/CVE-2026-32597). |
| CVE-2026-48522 and CVE-2026-48526 | Upstream fixes are in PyJWT 2.13.0, but Ubuntu 24.04 status was "Needs evaluation". Do not claim APT resolves these without vendor confirmation. See [48522](https://ubuntu.com/security/CVE-2026-48522) and [48526](https://ubuntu.com/security/CVE-2026-48526). |

The script deliberately does not label the host "CVE-free" after an APT
transaction. Do not overwrite Ubuntu's system PyJWT with `sudo pip`.

## Reports and test acceptance

Default output: `/tmp/mtgdiag-<UTC timestamp>/`.

| Artifact | Purpose |
| --- | --- |
| `report.txt`, `results.jsonl`, `report.html` | Findings; HTML renders each finding once |
| `security-host.txt`, `security-docker-<id>.txt`, `security-podman-<id>.txt` | Per-scope inventory when running security-inventory |
| `security-host-before-updates.txt`, `security-host-after-updates.txt` | Host package evidence around an update; after file is produced when installation is attempted |
| `security-apt-plan.log` | Proposed APT transaction |
| `security-apt-update.log`, `security-apt-install.log` | Refresh/install output when authorized |
| `security-held-packages.txt` | Package-hold evidence |
| `evidence.tar.gz` | Evidence bundle; review for sensitive content before sharing |

The HTML report is self-contained and works offline. Its dashboard highlights
failures in red, review items in amber, and proposed actions in purple. When
attention items exist, they are shown by default; use **All findings**, a status
filter, or a summary card to change the view. Search matches identifiers and
messages, and **Reset filters** restores every finding.

Counts represent recorded events, not distinct vulnerabilities or final service
state. Findings are ordered by status and retain their original order within
each status; timestamps help distinguish before/after remediation results.
Malformed records produce a prominent incomplete-evidence warning rather than
being silently discarded. With JavaScript disabled, all findings remain visible.
Printing includes all findings, even if the on-screen view is filtered.

Use a new or empty `--output-dir` for each run. Container collection uses
`--timeout` (default 8 seconds); increase it if package queries time out.

Acceptance criteria for a test server:

- Plain diagnostics and security inventory never install packages.
- Starting containers do not print a new diagnosis merely because uptime changes.
- Each baseline health/release check runs once in preview-all; post-remediation
  health checks are fresh.
- Host and container results retain separate identities and full package versions.
- Security-update preview only invokes APT simulation.
- Wrong approval text, a noninteractive execute attempt, or an unsupported host
  cannot start package installation.
- Successful APT execution reports a completed transaction, not universal CVE
  clearance.

`security-updates` returns nonzero on a blocked or failed operation and still
attempts to package evidence. Other legacy diagnostic modes primarily communicate
findings through PASS/FAIL/REVIEW records; exit code alone is not a health verdict.
