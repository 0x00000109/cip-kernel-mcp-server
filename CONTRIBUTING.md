# Contributing to CIP Kernel MCP Server

Thanks for contributing! This project follows CIP's own working principles —
please read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) first: it defines the
module catalog (E/P/A/W/PR IDs), the governing rules (R1–R8), and the
implementation priorities.

## Ground rules

1. **Upstream First (R1).** The server never invents patches or CVE facts.
   Every piece of data must trace to a verifiable upstream source.
2. **Evidence chains (R3/R8).** Analysis modules never guess: verdicts are
   `applicable / not-applicable / unknown` and always include evidence.
3. **Read-only by default.** No tool may write to a scanned host. See
   [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
4. **Tests are required** for engine (`src/engine/`) and analysis
   (`src/analysis/`) modules. Run `npm test` before pushing.

## Development setup

```bash
npm install
npm run lint     # type-check (tsc --noEmit)
npm test         # vitest
npm run build    # compile to dist/
npm start        # run the MCP server over stdio
```

To try it with an MCP client, point the client's stdio command at
`node dist/index.js`. Set `CIP_MCP_CACHE_DIR` and `CIP_MCP_AUDIT_LOG` to
override cache and audit paths.

## Commit style

- `feat:` / `fix:` / `docs:` / `test:` / `chore:` prefixes.
- Reference module IDs and rules when relevant, e.g.
  `feat(a1): handle modules disabled in config (R3)`.
