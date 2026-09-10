# Microsoft Tunnel Intelligent Readiness and Diagnostics

A Linux-based readiness, diagnostics, and guided troubleshooting tool for Microsoft Tunnel Gateway deployments.

## Maintainers

- Anushka Rai
- Yeswanth Kumar

## Overview

`MTGDiag.sh` helps administrators assess Microsoft Tunnel Gateway health, validate prerequisites, test network connectivity, inspect TLS certificate configuration, collect troubleshooting evidence, and run guarded remediation workflows.

The tool operates in read-only or preview mode by default. Environment-changing operations require the `--execute` switch and typed administrator approval.

## Key Features

- Linux operating system supportability validation
- Docker and Podman version validation
- Host resource and runtime prerequisite checks
- Host-level proxy discovery
- Docker or Podman engine-level proxy discovery
- Microsoft Tunnel container-level proxy discovery
- Microsoft Tunnel agent container status and health validation
- Microsoft Tunnel server container status and health validation
- Required Microsoft endpoint connectivity testing
- DNS, TCP, TLS, HTTP, proxy, certificate issuer, and response-time evidence
- Internal application connectivity testing
- TLS certificate subject, issuer, SAN, validity, and fingerprint inspection
- Certificate public-key algorithm, key-size, and signature-algorithm validation
- Effective `tls-priorities` compatibility assessment
- CRL, AIA, and OCSP endpoint discovery and connectivity testing
- Installed agent and server image digest reporting
- Microsoft Tunnel release version and release-date mapping
- Guided troubleshooting workflows
- Bounded packet-capture workflow
- Guarded Microsoft Tunnel force-upgrade workflow
- Text reports and compressed evidence-package generation

## Requirements

The tool is intended to run directly on a supported Microsoft Tunnel Gateway Linux server.

Required components include:

- A supported Linux distribution for Microsoft Tunnel
- Docker or Podman, depending on the Linux distribution
- Root or `sudo` access
- Bash
- Python 3
- curl
- OpenSSL
- tar
- Standard Linux text-processing utilities

The tool performs a runtime prerequisite check before diagnostics begin. If a required package is missing, the tool can show the required package and request administrator approval before installation.

The tool does not automatically install or replace Docker or Podman.

## Basic Usage

Make the script executable:

```bash
chmod +x MTGDiag.sh