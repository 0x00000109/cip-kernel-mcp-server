import { createHash } from 'node:crypto';
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export interface AuditEntry {
  timestamp: string;
  tool: string;
  argsDigest: string;
  resultDigest: string | null;
  prev?: string;
  error?: string;
}

/**
 * Append-only, tamper-evident audit trail (Rule R8, module E2).
 * Every MCP tool invocation is logged with digests of its inputs and outputs,
 * chained by hash so later tampering with entries is detectable.
 * Designed to be usable as IEC 62443-4-1 process evidence (see ARCHITECTURE.md R8).
 */
export class AuditLog {
  private chain: string | null = null;

  constructor(private readonly filePath: string) {
    mkdirSync(dirname(this.filePath), { recursive: true });
  }

  record(tool: string, args: unknown, result: unknown, error?: string): AuditEntry {
    const argsDigest = digest(args);
    const resultDigest = result === undefined ? null : digest(result);
    const prev = this.chain;
    this.chain = digest([prev, tool, argsDigest, resultDigest, error ?? null]);

    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      tool,
      argsDigest,
      resultDigest,
      ...(error ? { error } : {}),
      ...(prev ? { prev: prev.slice(0, 12) } : {}),
    };
    appendFileSync(this.filePath, JSON.stringify(entry) + '\n');
    return entry;
  }
}

function digest(value: unknown): string {
  const text = value === undefined ? 'undefined' : JSON.stringify(value) ?? 'null';
  return createHash('sha256').update(text).digest('hex');
}
