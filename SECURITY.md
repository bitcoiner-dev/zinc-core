# Security Policy

## Supported Versions

Security fixes are provided for the current `0.10.x` release line. Earlier
pre-release lines are unsupported because the project intentionally removes
obsolete security-sensitive APIs rather than maintaining compatibility shims.

| Version | Supported |
|---|---|
| `0.10.x` | Yes |
| `<= 0.9.x` | No |

## Reporting a Vulnerability

Please report suspected vulnerabilities privately.

- Email: bitcoiner.dev@gmail.com
- Include: affected version, impact summary, reproduction steps, and a proposed fix (if known)

Reports involving signing scope, Ordinal Shield decisions, private descriptors,
secret lifetime, wallet lock behavior, vault encryption, or WASM exports are in
scope even when exploitation depends on a host application.

Do not open public issues for unpatched vulnerabilities.

## Response Expectations

- Initial acknowledgment: within 3 business days
- Triage update: within 7 business days
- Coordination for disclosure and release timeline after triage

Please allow time for downstream Zinc native and WASM consumers to update before
public disclosure when a fix changes a shared security contract.
