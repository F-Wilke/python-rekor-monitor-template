# Security policy

## Supported versions

This is a research/educational project. The latest code on `main` is the only supported version. Older releases, branches and snapshots do not receive security fixes.

## Reporting vulnerabilities

**Do not open a public GitHub issue containing an unpatched vulnerability, credential, or exploit.** Use this repository's GitHub **Security → Advisories → Report a vulnerability** private reporting flow. Do not disclose sensitive details publicly.

Please include impact, affected versions, reproduction steps, expected vs actual behavior, and suggested remediation without including real secrets or user data. The maintainer will triage reports, investigate and coordinate disclosure, and provide status when a private contact channel is available.

## Updates

Security fixes are reviewed in pull requests, tested with CI, and released on `main` after validation. Critical leaks require immediate credential revocation/rotation and investigation of repository history; removing a file from the latest commit alone is insufficient. There is no guaranteed response or patch SLA.

This tool processes untrusted Rekor responses and cryptographic material. Operators remain responsible for validating identity, trust roots and authenticated checkpoints independently.
