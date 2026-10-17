import { describe, expect, it } from 'vitest';
import { parseKernelCveRecord } from '../src/providers/kernel-cve';

/**
 * Fixture modeled on real kernel.org CVE records (vulns.git, CVE JSON 5.0):
 * programFiles for affected files, cpeApplicability per stable series, and
 * git.kernel.org/stable/c/<sha> fixing-commit references.
 */
const fixture = {
  dataType: 'CVE_RECORD',
  dataVersion: '5.1',
  cveMetadata: {
    cveId: 'CVE-2024-20988',
    state: 'PUBLISHED',
  },
  containers: {
    cna: {
      descriptions: [
        {
          lang: 'en',
          value:
            'In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: fix ...',
        },
      ],
      affected: [
        {
          vendor: 'Linux',
          product: 'Linux',
          programFiles: [
            'net/netfilter/nf_tables_api.c',
            'include/net/netfilter/nf_tables.h',
          ],
        },
      ],
      cpeApplicability: [
        {
          nodes: [
            {
              operator: 'OR',
              cpeMatch: [
                {
                  vulnerable: true,
                  criteria: 'cpe:2.3:o:linux:linux_kernel:5.10.*:*:*:*:*:*:*:*',
                  versionStartIncluding: '5.10.157',
                  versionEndExcluding: '5.10.163',
                },
                {
                  vulnerable: true,
                  criteria: 'cpe:2.3:o:linux:linux_kernel:6.1.*:*:*:*:*:*:*:*',
                  versionStartIncluding: '6.1.70',
                  versionEndExcluding: '6.1.78',
                },
              ],
            },
          ],
        },
      ],
      references: [
        'https://git.kernel.org/stable/c/aabbccddeeff00112233445566778899aabbccdd',
        'https://git.kernel.org/stable/c/112233445566778899aabbccddeeff0011223344',
        'https://nvd.nist.gov/vuln/detail/CVE-2024-20988',
      ],
    },
  },
};

describe('parseKernelCveRecord (module P3, Rule R3)', () => {
  it('extracts id, description and source', () => {
    const record = parseKernelCveRecord(fixture, '2026-10-17T00:00:00Z');
    expect(record).toBeDefined();
    expect(record?.id).toBe('CVE-2024-20988');
    expect(record?.source).toBe('kernel.org-cve');
    expect(record?.description).toContain('netfilter');
    expect(record?.fetchedAt).toBe('2026-10-17T00:00:00Z');
  });

  it('extracts affected files from programFiles', () => {
    const record = parseKernelCveRecord(fixture, '2026-10-17T00:00:00Z');
    expect(record?.affected.map((a) => a.file)).toEqual([
      'net/netfilter/nf_tables_api.c',
      'include/net/netfilter/nf_tables.h',
    ]);
  });

  it('extracts per-series version ranges from cpeApplicability', () => {
    const record = parseKernelCveRecord(fixture, '2026-10-17T00:00:00Z');
    expect(record?.affectedRanges).toEqual([
      {
        series: '5.10',
        branch: 'linux-5.10.y',
        startIncluding: '5.10.157',
        fixedIn: '5.10.163',
      },
      {
        series: '6.1',
        branch: 'linux-6.1.y',
        startIncluding: '6.1.70',
        fixedIn: '6.1.78',
      },
    ]);
  });

  it('extracts fixing commits from git.kernel.org stable references', () => {
    const record = parseKernelCveRecord(fixture, '2026-10-17T00:00:00Z');
    expect(record?.fixingCommits.map((f) => f.sha)).toEqual([
      'aabbccddeeff00112233445566778899aabbccdd',
      '112233445566778899aabbccddeeff0011223344',
    ]);
  });

  it('returns undefined for rejected records', () => {
    const rejected = {
      ...fixture,
      cveMetadata: { cveId: 'CVE-2024-20988', state: 'REJECTED' },
    };
    expect(parseKernelCveRecord(rejected, 'x')).toBeUndefined();
  });

  it('returns undefined when the record has no cve id', () => {
    expect(parseKernelCveRecord({}, 'x')).toBeUndefined();
  });

  it('tolerates records without cpeApplicability or references', () => {
    const minimal = {
      cveMetadata: { cveId: 'CVE-2024-0001', state: 'PUBLISHED' },
      containers: {
        cna: {
          descriptions: [{ lang: 'en', value: 'desc' }],
          affected: [{ vendor: 'Linux', product: 'Linux', programFiles: ['mm/gup.c'] }],
        },
      },
    };
    const record = parseKernelCveRecord(minimal, 'x');
    expect(record?.affectedRanges).toEqual([]);
    expect(record?.fixingCommits).toEqual([]);
    expect(record?.affected).toEqual([{ file: 'mm/gup.c' }]);
  });
});
