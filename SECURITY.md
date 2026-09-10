# Security Policy

## Reporting a Security Issue

Please do not disclose security vulnerabilities through public GitHub issues.

When reporting a security concern, include:

- The affected MTGDiag version
- Linux distribution and version
- Docker or Podman version
- A clear description of the issue
- Safe reproduction steps
- Expected and actual behavior
- Any recommended mitigation

Do not include credentials, tokens, private keys, certificates, customer names, tenant identifiers, internal DNS names, IP addresses, packet captures, or diagnostic evidence in a public report.

## Sensitive Diagnostic Evidence

Microsoft Tunnel diagnostic output can contain sensitive operational information, including:

- Server names and internal IP addresses
- Internal DNS names and URLs
- Proxy configuration
- Certificate metadata
- Network connection metadata
- Microsoft Tunnel configuration identifiers
- Packet captures
- Container and service logs

Diagnostic evidence must not be committed to this repository. Protect, retain, and share generated evidence according to your organization's security, privacy, and data-handling requirements.

## Supported Versions

Security fixes are applied to the latest published version of MTGDiag.

Before reporting an issue, reproduce the behavior using the latest available release whenever possible.

## Operational Safety

MTGDiag operates in read-only or preview mode by default.

Operations enabled with `--execute` can:

- Restart Microsoft Tunnel components
- Modify approved local configuration values
- Initiate a Microsoft Tunnel container image upgrade
- Capture network traffic

Before using `--execute`:

1. Review the displayed execution plan.
2. Obtain the required operational or change approval.
3. Confirm that required backups are available.
4. Validate the workflow in a non-production environment.
5. Protect generated logs, packet captures, and evidence packages.

## Disclaimer

This project is provided as-is, without warranty.

The tool is not a replacement for Microsoft Support or official Microsoft Intune documentation. Administrators are responsible for testing, authorization, backup, change control, and protection of diagnostic evidence.