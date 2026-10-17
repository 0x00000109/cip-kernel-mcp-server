import { describe, expect, it } from 'vitest';
import {
  classifyAgainstRange,
  compareKernelVersions,
  parseKernelVersion,
} from '../src/analysis/version-range';

describe('parseKernelVersion', () => {
  it('strips distro suffixes like -cip50', () => {
    expect(parseKernelVersion('5.10.209-cip50')).toEqual({
      base: '5.10.209',
      series: '5.10',
    });
  });

  it('handles plain stable versions', () => {
    expect(parseKernelVersion('6.1.78')).toEqual({ base: '6.1.78', series: '6.1' });
  });
});

describe('compareKernelVersions', () => {
  it('compares numerically, not lexically', () => {
    expect(compareKernelVersions('5.10.9', '5.10.10')).toBeLessThan(0);
    expect(compareKernelVersions('5.10.163', '5.10.163')).toBe(0);
    expect(compareKernelVersions('5.10.209', '5.10.163')).toBeGreaterThan(0);
  });

  it('ignores distro suffixes', () => {
    expect(compareKernelVersions('5.10.163-cip25', '5.10.163')).toBe(0);
    expect(compareKernelVersions('5.10.163-cip25', '5.10.164')).toBeLessThan(0);
  });

  it('orders across series', () => {
    expect(compareKernelVersions('5.10.999', '6.1.1')).toBeLessThan(0);
  });
});

describe('classifyAgainstRange', () => {
  const range = { startIncluding: '5.10.157', fixedIn: '5.10.163' };

  it('marks versions at or after the fixing release as fixed', () => {
    expect(classifyAgainstRange('5.10.209-cip50', range)).toBe('fixed');
    expect(classifyAgainstRange('5.10.163', range)).toBe('fixed');
  });

  it('marks versions before the introducing release as not-introduced', () => {
    expect(classifyAgainstRange('5.10.100-cip12', range)).toBe('not-introduced');
  });

  it('marks versions between introduction and fix as in-range', () => {
    expect(classifyAgainstRange('5.10.160-cip25', range)).toBe('in-range');
  });

  it('treats open ranges (no fix released) as in-range', () => {
    const open = { startIncluding: '5.10.157' };
    expect(classifyAgainstRange('5.10.209-cip50', open)).toBe('in-range');
  });
});
