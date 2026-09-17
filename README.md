# Microsoft Tunnel Intelligent Readiness and Diagnostics

**MTGDiag 7.4.7** helps administrators collect readiness evidence before Microsoft
Tunnel Gateway deployment and troubleshoot host, container, connectivity, and
certificate problems afterward.

Start with the [use cases and testing guide](MTGDiag-Use-Cases.md) for detailed
commands, expected results, approval phrases, coverage limits, and acceptance
criteria.

## What this tool provides

| Area | Capabilities |
| --- | --- |
| Host and runtime | Linux and container-engine supportability, memory, disk, TUN device, forwarding state, and Tunnel configuration evidence |
| Proxy and connectivity | Host, service, engine, and container proxy inspection; discovered endpoint DNS, TCP, TLS, HTTP, timing, and certificate-issuer evidence |
| Certificates | Certificate metadata, key/signature and TLS-policy assessment, and revocation endpoint discovery/connectivity |
| Tunnel health | Agent/server container health, available logs, monitor evidence, and installed versus published release information |
| Less repetitive diagnosis | Reused baseline health/release checks in scenario previews; unchanged startup states do not generate repeated diagnoses; fresh health checks after remediation |
| Reports | Text, structured JSONL, self-contained offline HTML, and compressed evidence bundles |
| Security inventory | Separate host and running-container package scopes, full distribution revisions, and system-interpreter PyJWT metadata |
| Controlled changes | Preview-first troubleshooting and a separate, approval-gated Ubuntu host package-update workflow |

Diagnostic modes write evidence and may contact endpoints, but do not install
packages or run remediation without explicit execution approval. This is not a
deployment-readiness certification, an exhaustive vulnerability scanner, or an
automatic root-cause verdict.

## Requirements

Run the script with **Bash on the Linux host**, using root or `sudo` for diagnostic
modes. `--help` and `--version` do not require root.

The runtime precheck requires Bash, Python 3, curl, OpenSSL, tar, awk, sed, grep,
sort, find, sha256sum, and timeout. Individual checks also use Linux administration
tools and, for container checks, the supported Docker or Podman runtime and tools
available inside the containers.

The precheck reports missing dependencies; ordinary diagnostic runs do not install
them. The script does not automatically install or replace the container runtime.
Missing Tunnel components on a pre-deployment host are not evidence of readiness.

## Quick start

Obtain the repository on the Linux host:

```bash
git clone https://github.com/kumaryeswanth80-droid/microsoft-tunnel-diagnostics.git
cd microsoft-tunnel-diagnostics
sha256sum -c MTGDiag.sh.sha256

bash ./MTGDiag.sh --version
bash ./MTGDiag.sh --help
sudo bash ./MTGDiag.sh --mode self-test --non-interactive
```

The checksum checks consistency with the accompanying manifest; it is not a
publisher signature. Review the source and obtain it through a trusted channel.
No `chmod` is needed when invoking the script with `bash`. Do not run it with `sh`.
`self-test` checks runtime prerequisites only, not network readiness or CVE status.

### Before deployment: collect readiness evidence

```bash
sudo bash ./MTGDiag.sh --mode connectivity --all-endpoints --non-interactive
```

This collects baseline inventory and proxy settings, then probes all **discovered**
endpoints from the host and applicable containers. On a pre-deployment host, review
the host evidence separately from unavailable Tunnel/container checks.

DNS resolution, connection timings, TLS verification, and certificate issuers help
investigate connectivity and SSL inspection. Proxy configuration alone does not
prove the required traffic path works, and a successful TLS connection does not
prove inspection is absent. Validate SSL-inspection bypass requirements separately.

Public DNS/FQDN, inbound Tunnel TCP/UDP reachability, certificate provisioning,
Intune configuration, and capacity still require administrator validation. Use
Microsoft's approved readiness and deployment process alongside this evidence:
[Microsoft Tunnel prerequisites](https://learn.microsoft.com/en-us/intune/intune-service/protect/microsoft-tunnel-prerequisites).

### After deployment: run the full baseline

```bash
sudo bash ./MTGDiag.sh --mode full --non-interactive
```

Full mode includes host, proxy, container, endpoint, certificate, revocation, and
release checks. Internal application testing is skipped unless a URL is supplied.
Read PASS/FAIL/REVIEW/SKIP records and coverage notes; command completion or exit
code alone is not a health verdict.

## Common diagnostic commands

| Use case | Command |
| --- | --- |
| Interactive menu | `sudo bash ./MTGDiag.sh` |
| Inventory, certificates, and release assessment | `sudo bash ./MTGDiag.sh --mode inventory --non-interactive` |
| Five-endpoint smoke test, not exhaustive coverage | `sudo bash ./MTGDiag.sh --mode connectivity --max-endpoints 5 --non-interactive` |
| Internal application from Tunnel containers | `sudo bash ./MTGDiag.sh --mode internal --internal-url https://app.example.internal/health --non-interactive` |
| All scenario previews with reused baseline checks | `sudo bash ./MTGDiag.sh --mode preview-all --non-interactive` |
| Allow more time for starting containers | `sudo bash ./MTGDiag.sh --mode inventory --health-wait-seconds 300 --non-interactive` |
| Bounded log collection without endpoint probes | `sudo bash ./MTGDiag.sh --mode log-collection --non-interactive` |
| Read-only host/container security inventory | `sudo bash ./MTGDiag.sh --mode security-inventory --non-interactive` |

Replace the example internal URL with an approved target. `preview-all` disables
remediation and does not include the separate host package-update workflow.
`[CHECK]` activity identifies checks, targets, and limits without inflating finding
counts. See the [diagnostic use cases](MTGDiag-Use-Cases.md#diagnostic-use-cases) for
scope details.

## Troubleshooting: preview before execution

Available scenarios are `unhealthy`, `ip-starvation`, `bridge-conflict`,
`container-down`, `upgrade`, and `network-trace`.

```bash
sudo bash ./MTGDiag.sh --scenario container-down
sudo bash ./MTGDiag.sh --scenario upgrade
```

These commands preview only. Disruptive execution requires `--execute`, an
interactive terminal, authorization, and the exact approval phrase for that
workflow. Do not pipe approval tokens into the script.

Restarts can interrupt users and do not guarantee recovery. The `unhealthy`
execute workflow resets a stored health value and restarts the agent; it does
not fix the underlying cause. Network configuration remediation remains manual.
Packet capture requires separate approval and may collect sensitive traffic.

The `upgrade` scenario's execute path is an **advanced forced-image/custom-image
workflow**, not the documented
[Intune site upgrade workflow](https://learn.microsoft.com/en-us/intune/intune-service/protect/microsoft-tunnel-upgrade).
It is not Ubuntu host patching or guaranteed CVE remediation. Review the
[scenario-specific cautions](MTGDiag-Use-Cases.md#troubleshooting-use-cases) before
considering execution.

## Ubuntu host package updates and CVE interpretation

The separate `security-updates` mode targets selected **already-installed**
glibc, Python 3.12, and distribution-managed PyJWT packages on **Ubuntu 24.04**.
Preview the transaction first:

```bash
sudo bash ./MTGDiag.sh --mode security-updates --non-interactive
```

The preview uses cached APT metadata and does not refresh repositories, install
packages, restart services, or reboot. A no-change preview does not prove the
host is up to date.

For an authorized maintenance window with a recoverable backup:

```bash
sudo bash ./MTGDiag.sh --mode security-updates --execute
```

Execution requires two separate approvals: `REFRESH-HOST-SECURITY-PLAN` for
metadata refresh, then `APPLY-HOST-SECURITY-UPDATES` after reviewing the fresh
simulation. Dependencies may change and package scripts may restart services.
There is no automatic rollback, reboot, container patching, or system `pip`
replacement. Unsupported hosts, holds, and failed planning checks block installation.

Host and container findings are separate scopes. Use full distribution package
revisions and vendor advisories when evaluating backported fixes; an upstream
runtime version alone does not establish vulnerability. Missing inventory coverage
and successful package installation never mean "CVE-free." Follow the
[host-update procedure](MTGDiag-Use-Cases.md#ubuntu-host-package-updates) and
[dated CVE interpretation notes](MTGDiag-Use-Cases.md#interpreting-the-reported-cves),
then obtain a compliance rescan.

## Reports and evidence

Default output is `/tmp/mtgdiag-<UTC timestamp>/`. Use a new or empty
`--output-dir` for each run and retain needed evidence before temporary files are
removed.

| Artifact | Purpose |
| --- | --- |
| `report.txt` | Human-readable findings and activity |
| `results.jsonl` | Structured diagnostic records |
| `report.html` | Self-contained offline report with status counts, filters, search, and highlighted attention items |
| `evidence.tar.gz` | Collected evidence bundle |
| `security-host.txt`, `security-docker-<id>.txt`, `security-podman-<id>.txt` | Per-scope inventory when security inventory is run |
| `security-apt-plan.log`, `security-apt-update.log`, `security-apt-install.log` | Package-update evidence when the corresponding steps run |

HTML findings appear once, with failures, review items, and proposed actions
highlighted. Counts describe recorded events, not distinct vulnerabilities or a
final health verdict. Malformed records produce an incomplete-evidence warning.
See [reports and test acceptance](MTGDiag-Use-Cases.md#reports-and-test-acceptance)
for interpretation and acceptance criteria.

**Do not commit diagnostic output to this repository.** Logs, configuration
evidence, internal URLs, identifiers, and packet captures can be sensitive. Review
and protect evidence before sharing it; see [SECURITY.md](SECURITY.md).

## Separate browser dashboard

The use-case guide also describes a companion dashboard with verified SSH,
signed-script deployment, live diagnostic activity, a Full diagnostics tab, and
approval-gated actions.

**The dashboard application and its setup files are not included in this
repository.** Dashboard instructions in the guide apply only if you have obtained
that separate application. The script and offline HTML reports documented above
work without it; cloning this repository does not install a dashboard or enroll
a Microsoft Tunnel server.

## Maintainers

- Anushka Rai
- Yeswanth Kumar

This project is provided as-is. It does not replace Microsoft Support, official
deployment documentation, or your organization's authorization and change-control
processes.