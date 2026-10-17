# CIP Kernel MCP Server

**An open-source MCP (Model Context Protocol) server engine for Linux system administrators managing systems on CIP super-long-term-support (SLTS) kernels (5.10.x) — built to accelerate dependency discovery and security patch implementation.**

## 1. Motivation

The [Civil Infrastructure Platform (CIP)](https://www.cip-project.org/) maintains SLTS Linux kernels (currently 5.10.x, supported 10+ years) that power bridges, tunnels, railways, power plants, and other industrial systems. Administrators of these systems face a specific set of hard problems:

- **Dependency opacity.** A production CIP image combines a pinned kernel, distro packages, out-of-tree drivers, firmware blobs, and custom daemons. Answering *"what depends on this kernel symbol / library / driver version?"* currently requires slow, manual cross-referencing.
- **Slow CVE triage.** A CVE arrives in `kernel-5.10.x`. The admin must determine whether the affected subsystem is even enabled in the deployed kernel config, whether a fix is already in a CIP branch, and what backport a custom kernel requires.
- **Fragmented tooling.** `cve-tracker` data, NVD, kernel configs, `modinfo`, SBOM scanners, and patch sets live in disconnected silos.
- **10-year maintenance windows.** Long-lived deployments mean patches must be **backported**, not upgraded — which makes every change riskier and every dependency fact more valuable.

**CIP Kernel MCP Server** closes this gap by exposing these silos as structured, queryable MCP tools so that any MCP-capable LLM agent (Claude Code, IDE assistants, chat agents) can assist the admin with accurate, machine-verified facts.

## 2. Goals

1. Give LLM agents **fast, structured access to dependency information** for systems running CIP 5.10.x kernels.
2. Help administrators **triage CVEs and implement security patches** faster and more safely.
3. Remain **fully open source** (MIT), community-driven, and vendor-neutral.
4. Be **read-only by default** — analysis first; any mutating action is explicit, audited, and gated.

### Non-goals

- Replacing a package manager, build system, or patch pipeline.
- Auto-applying patches to production without human approval.
- Supporting non-LTS or non-CIP kernel branches (initially; other SLTS kernels may follow).

## 3. Core Capabilities (MCP Tools)

| Tool | Purpose | Phase |
| --- | --- | --- |
| `scan_system` | Collect a read-only machine inventory: kernel version, config (`/proc/config.gz`), loaded modules, distro. | P0 |
| `query_cve` | Look up a CVE across NVD, the kernel.org `cve-tracker`, and CIP security feeds; normalized record with affected files and fixing commits. | P0 |
| `cve_applicability` | Cross-reference a CVE against a concrete kernel config + module inventory → **applicable / not applicable / unknown**, always with an evidence chain. | P0 |
| `find_patches` | Locate existing fixing commits: mainline → stable 5.10.y → CIP branches. | P0 |
| `dependency_graph` | Build and query a dependency graph: kernel symbols ↔ modules ↔ drivers ↔ packages ↔ services. | P1 |
| `patch_builder` | Draft a kernel-rule-compliant backport into a staging directory; conflict report. | P1 |
| `release_tracker` | Per installed CIP release: fixed vs outstanding CVEs, update recommendation. | P1 |
| `config_audit` | Audit kernel config against hardening baselines (CIP hardening guide / IEC 62443). | P2 |
| `sbom_export` | Emit a CycloneDX/SPDX SBOM of the scanned system, including kernel and module inventory. | P2 |

## 4. Architecture

Modular engine in five layers, from the MCP runtime to the product surface.
Full module catalog, governing rules (R1–R8), and implementation priorities: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

```mermaid
flowchart LR
    A["MCP Client<br/>Claude Code / IDE / Chat"] -->|MCP stdio / HTTP| B["CIP Kernel MCP Server"]
    B --> C["Tool Layer<br/>scan · graph · CVE · patch"]
    C --> D[("Local Sysfs / Procfs<br/>Kernel Info & Config")]
    C --> E[("Local Cache + Integrity<br/>CVE DB, CIP git mirrors")]
    C --> F[("Remote Sources<br/>NVD, kernel.org cve-tracker,<br/>cip-kernel git")]
    H["Administrator<br/>approves mutating actions"] --> B
```

- **Transport:** stdio (local admin workstation); streamable HTTP team server in P3.
- **Safety model:** tools are read-only by default; no tool touches a running system.
- **Safety & security model:** [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## 5. Security Principles

1. **Read-only by default** — inventory and analysis require no privileges beyond reading.
2. **Least privilege** — no root requirement for scanning; agents run as a dedicated user.
3. **Explicit approval** — every state-changing operation requires a human confirmation step.
4. **Full audit trail** — every tool invocation is logged with hash-chained digests of inputs and outputs.
5. **Deterministic outputs** — verdicts never guess and always include their evidence chain.

## 6. Status

Phase **P0 (MCP Foundation)** — engine skeleton implemented:

- Engine core: MCP runtime (stdio), audit trail, offline-first cache, source-integrity hooks, tool registry.
- Providers: system inventory (read-only `/proc` + `/sys` paths), CVE feeds (NVD via cache), CIP git (branch catalogue + passthrough; live mirror queries are the next P0 step).
- Analysis: CVE applicability engine with evidence chains (Rule R3), patch locator (Rule R1).
- MCP tools: `scan_system`, `query_cve`, `find_patches`, `cve_applicability`.
- CI (Node 20/22: type-check, tests, build), vitest coverage for engine and analysis modules.

## 7. Tech Stack

- **Language:** TypeScript (Node.js ≥ 20) — chosen at kickoff; the official MCP SDK is TypeScript-first, giving a single-language engine + provider SDK. Python provider examples may follow in P3.
- **MCP SDK:** official [Model Context Protocol SDK](https://github.com/modelcontextprotocol/typescript-sdk) (server side, stdio transport).
- **Data:** offline-first JSON cache; NVD now, kernel.org `cve-tracker` + CIP git mirrors next.
- **CI:** GitHub Actions on Node 20/22 with vitest.

## 8. Development

```bash
npm install
npm run lint     # type-check (tsc --noEmit)
npm test         # vitest
npm run build    # compile to dist/
npm start        # run the MCP server over stdio
```

Point your MCP client's stdio command at `node dist/index.js`. Environment overrides: `CIP_MCP_CACHE_DIR`, `CIP_MCP_AUDIT_LOG`. Contribution rules: [CONTRIBUTING.md](CONTRIBUTING.md).

## 9. License & Contribution

MIT licensed. Contributions welcome: kernel triage expertise, MCP tool ideas, CVE data quality, and docs for industrial deployment scenarios are the most valuable first contributions.

## 10. Repository Layout

```
.
├── README.md
├── CONTRIBUTING.md
├── docs/
│   ├── ARCHITECTURE.md       # modular architecture, rules R1-R8, priorities P0-P3
│   └── THREAT-MODEL.md       # safety & security model
├── src/
│   ├── index.ts              # MCP server entry (stdio)
│   ├── engine/               # L0: types, runtime, audit, cache, integrity, registry
│   ├── providers/            # L1: system inventory, CVE feeds, CIP git
│   ├── analysis/             # L2: CVE applicability, patch locator
│   └── tools/                # L3: MCP tool wiring
├── tests/
└── .github/                  # CI workflow, issue templates
```
