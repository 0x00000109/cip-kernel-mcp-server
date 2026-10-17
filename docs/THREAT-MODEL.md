# Threat Model & Safety Design

This document defines how **CIP Kernel MCP Server** keeps an administrator's
systems safe while giving LLM agents deep visibility into kernel dependencies
and security patches.

## 1. Assets

| Asset | Description |
| --- | --- |
| Production CIP hosts | Industrial systems running 5.10.x SLTS kernels. **Must never be modified by the server.** |
| Kernel & package inventory | System metadata collected by `scan_system`. May reveal topology and versions — treated as sensitive. |
| CVE & patch data | Cached vulnerability data; must not be tampered with (integrity matters for patch decisions). |
| Draft patches | Output of `patch_builder`; staged only, never applied automatically. |
| Audit log | Record of every tool invocation; tamper-evident append-only file. |

## 2. Adversaries & Risks

| Risk | Vector | Mitigation |
| --- | --- | --- |
| Indiscriminate auto-patching | LLM agent "helpfully" applies fixes | No tool can write to a running system; `patch_builder` emits to a staging dir; applying is a human, out-of-band step. |
| Prompt-injected patch advice | Malicious content in CVE feeds or repo metadata | Tool outputs are data-only; the server never executes fetched content; verdicts must include an evidence chain the admin can verify. |
| Poisoned CVE/patch cache | Compromised upstream or MITM | Signed/verifiable sources where available, pinned mirrors, hash checks on cache refresh. |
| Privilege escalation via scanner | `scan_system` abused to read secrets | Scanner reads only a whitelisted set of paths (`/proc`, `/sys`, package manifests); no arbitrary file read. |
| Air-gap exfiltration | Remote lookups from isolated networks | Remote sources are optional; offline mode serves fully from the local cache; egress is explicit in the audit log. |
| Supply-chain compromise of the server itself | Malicious dependency in the engine | Minimal dependency footprint, lockfiles, provenance-attested releases, reproducible Docker image. |

## 3. Trust Boundaries

1. **Running system ↔ server:** read-only, least privilege. The server is a
   passive observer of the host.
2. **LLM agent ↔ server:** agents may call tools, not shell out. Every
   mutating-adjacent operation (`patch_builder`, cache refresh) is surfaced as
   an explicit MCP approval request where supported.
3. **Server ↔ remote sources:** all external data is fetched, validated,
   cached, and versioned. Cache freshness is reported with every answer.

## 4. Guarantees

- **No side effects on production:** no tool writes to the scanned host, ever.
- **Verifiable answers:** every CVE applicability verdict ships the evidence
  (config lines, module presence, fixing commit IDs) so a human can audit it.
- **Least privilege:** the server runs unprivileged; no root requirement.
- **Auditability:** every invocation is logged: tool, arguments, data touched,
  and result digest.

## 5. Out of Scope

- Enforcement of patch application (belongs to the admin's config-management
  pipeline: Ansible, Salt, etc.).
- Authentication of MCP clients in stdio mode (assumed to be the local
  user's session); HTTP deployments should use the MCP authorization layer.
