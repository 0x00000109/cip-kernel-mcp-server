import { describe, expect, it } from 'vitest';
import { assessApplicability } from '../src/analysis/cve-applicability';
import type { CveRecord, KernelInventory } from '../src/engine/types';

const inventory = (): KernelInventory => ({
  kernelVersion: '5.10.209-cip50',
  arch: 'arm64',
  config: {
    CONFIG_EXT4_FS: 'n',
    CONFIG_BT: 'y',
    CONFIG_USB: 'm',
  },
  modules: [{ name: 'usb_storage', sizeKb: 100, usedBy: [] }],
  distro: { id: 'debian', name: 'Debian GNU/Linux', version: '11' },
  packages: [],
  collectedAt: new Date().toISOString(),
});

const cve = (file: string): CveRecord => ({
  id: 'CVE-2024-9999',
  description: 'fixture',
  source: 'kernel.org-cve',
  affected: [{ file }],
  fixingCommits: [
    { sha: 'a'.repeat(40), branches: ['linux-5.10.y-cip'] },
  ],
  fetchedAt: new Date().toISOString(),
});

describe('assessApplicability (Rule R3, module A1)', () => {
  it('returns not-applicable with high confidence when the subsystem is disabled', () => {
    const result = assessApplicability(cve('fs/ext4/inode.c'), inventory());
    expect(result.verdict).toBe('not-applicable');
    expect(result.confidence).toBe('high');
    expect(result.evidence.some((e) => e.claim.includes('CONFIG_EXT4_FS=n'))).toBe(true);
  });

  it('returns applicable when the affected subsystem is built-in', () => {
    const result = assessApplicability(cve('net/bluetooth/l2cap_core.c'), inventory());
    expect(result.verdict).toBe('applicable');
    expect(result.confidence).toBe('high');
    expect(result.evidence.some((e) => e.claim.includes('CONFIG_BT=y'))).toBe(true);
  });

  it('returns applicable when the modular subsystem is loaded', () => {
    const result = assessApplicability(cve('drivers/usb/storage/usb.c'), inventory());
    expect(result.verdict).toBe('applicable');
    expect(result.evidence.some((e) => e.claim.includes('module loaded'))).toBe(true);
  });

  it('returns unknown when the modular subsystem is not loaded', () => {
    const inv = inventory();
    inv.modules = [];
    const result = assessApplicability(cve('drivers/usb/storage/usb.c'), inv);
    expect(result.verdict).toBe('unknown');
  });

  it('returns unknown for files without a config mapping — never guesses', () => {
    const result = assessApplicability(cve('drivers/char/random.c'), inventory());
    expect(result.verdict).toBe('unknown');
    expect(result.confidence).toBe('low');
  });

  it('returns unknown when the CVE record has no affected-file data', () => {
    const rec = cve('fs/ext4/inode.c');
    rec.affected = [];
    const result = assessApplicability(rec, inventory());
    expect(result.verdict).toBe('unknown');
    expect(result.rationale).toContain('No affected-file data');
  });
});
