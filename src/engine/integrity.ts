import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

/**
 * Source integrity (Rule R5, module E3).
 * P0 scope: transport-level SHA-256 verification of downloaded artifacts.
 * TODO(P1): PGP verification of kernel.org CIP tarball signatures and signed
 * git tags (see ARCHITECTURE.md, module E3). The engine must refuse
 * unverifiable data sources (R5: releases are signed by CIP developers).
 */
export class SourceIntegrity {
  verifySha256(filePath: string, expectedSha256: string): boolean {
    const actual = createHash('sha256').update(readFileSync(filePath)).digest('hex');
    return actual === expectedSha256.toLowerCase();
  }
}
