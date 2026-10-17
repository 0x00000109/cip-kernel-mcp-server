/**
 * Kernel version comparison and CVE version-range classification (module A1,
 * Rule R3). Versions may carry distro suffixes like '5.10.209-cip50' — only
 * the numeric base ('5.10.209') participates in comparisons.
 */

export interface KernelVersionParts {
  base: string;
  series: string;
}

export function parseKernelVersion(v: string): KernelVersionParts {
  const base = v.split('-')[0];
  const parts = base.split('.');
  return { base, series: `${parts[0] ?? '0'}.${parts[1] ?? '0'}` };
}

/** Numeric component-wise comparison, e.g. '5.10.9' < '5.10.10'. */
export function compareKernelVersions(a: string, b: string): number {
  const pa = a.split('-')[0].split('.').map((n) => Number(n) || 0);
  const pb = b.split('-')[0].split('.').map((n) => Number(n) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return Math.sign(d);
  }
  return 0;
}

export type RangeStatus = 'in-range' | 'fixed' | 'not-introduced';

/**
 * Classify a kernel version against an affected range.
 * A range without `fixedIn` is an open, unfixed range: any version at or after
 * `startIncluding` is in range.
 */
export function classifyAgainstRange(
  version: string,
  range: { startIncluding?: string; fixedIn?: string },
): RangeStatus {
  const { base } = parseKernelVersion(version);
  if (range.fixedIn && compareKernelVersions(base, range.fixedIn) >= 0) {
    return 'fixed';
  }
  if (range.startIncluding && compareKernelVersions(base, range.startIncluding) < 0) {
    return 'not-introduced';
  }
  return 'in-range';
}
