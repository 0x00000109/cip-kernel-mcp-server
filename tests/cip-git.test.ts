import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { CIP_MIRROR_URL, CipGitProvider, parseGitLog } from '../src/providers/cip-git';
import type { CveRecord } from '../src/engine/types';

const FIX_SHA_510 = 'aabbccddeeff00112233445566778899aabbccdd';
const FIX_SHA_61 = '112233445566778899aabbccddeeff0011223344';
const BACKPORT_SHA = '00112233445566778899aabbccddeeff00112233';

/**
 * Fixture mirroring a kernel.org CVE record for a netfilter fix with
 * per-series ranges (5.10 / 6.1) and two commit-keyed fixing commits.
 */
const record: CveRecord = {
  id: 'CVE-2024-20988',
  description: 'netfilter: nf_tables: fix ...',
  source: 'kernel.org-cve',
  affected: [{ file: 'net/netfilter/nf_tables_api.c' }],
  affectedRanges: [
    { series: '5.10', branch: 'linux-5.10.y', startIncluding: '5.10.157', fixedIn: '5.10.163' },
    { series: '6.1', branch: 'linux-6.1.y', startIncluding: '6.1.70', fixedIn: '6.1.78' },
  ],
  fixingCommits: [
    { sha: FIX_SHA_510, branches: [] },
    { sha: FIX_SHA_61, branches: [] },
  ],
  fetchedAt: '2026-10-17T00:00:00Z',
};

/** git log line with the provider's \x1f field separators and \x1e terminator. */
function logRecord(sha: string, subject: string, date: string, body: string): string {
  return [sha, subject, date, body].join('\x1f') + '\x1e';
}

const backportLog = logRecord(
  BACKPORT_SHA,
  'netfilter: nf_tables: fix a wrong data length',
  'Tue, 2 Jan 2024 10:00:00 +0100',
  `commit ${FIX_SHA_510} upstream.\n\nFixes: ${FIX_SHA_510} ("netfilter: ...")\n`,
);

interface GitMockOpts {
  fetchOk?: boolean;
  cloneOk?: boolean;
  describe?: string;
  describeFail?: boolean;
  log?: (ref: string) => string;
}

/** Injectable git runner: routes subcommands to canned outputs. */
function gitMock(opts: GitMockOpts) {
  const calls: Array<string[]> = [];
  const run = async (_cmd: string, args: string[]) => {
    calls.push(args);
    if (args.includes('clone')) {
      if (!opts.cloneOk) throw new Error('offline: clone failed');
      return '';
    }
    if (args.includes('fetch')) {
      if (!opts.fetchOk) throw new Error('offline: fetch failed');
      return '';
    }
    if (args.includes('describe')) {
      if (opts.describeFail) throw new Error('no tag contains commit');
      return `${opts.describe ?? ''}\n`;
    }
    if (args.includes('log')) {
      const ref = args[args.length - 1];
      return opts.log ? opts.log(ref) : '';
    }
    return '';
  };
  return { run, calls };
}

let tmp: string | undefined;
afterEach(() => {
  if (tmp) rmSync(tmp, { recursive: true, force: true });
  tmp = undefined;
});

function freshTmp(): string {
  tmp = mkdtempSync(join(tmpdir(), 'cip-git-test-'));
  return tmp;
}

/** A mirror dir that looks like an existing local clone. */
function seededMirror(root: string): string {
  const dir = join(root, 'linux-cip');
  mkdirSync(join(dir, '.git'), { recursive: true });
  return dir;
}

describe('CipGitProvider (module P2, Rules R1/R4)', () => {
  it('resolves CIP backports from the mirror with release and url', async () => {
    const mirrorDir = seededMirror(freshTmp());
    const { run } = gitMock({
      fetchOk: true,
      describe: 'v5.10.163-cip35~7',
      log: (ref) => (ref === 'origin/linux-5.10.y-cip' ? backportLog : ''),
    });
    const provider = new CipGitProvider(async () => record, { run, mirrorDir });
    const patches = await provider.findPatches('CVE-2024-20988');

    const cip = patches.find((p) => p.branch === 'linux-5.10.y-cip');
    expect(cip).toBeDefined();
    expect(cip?.source).toBe('cip-mirror');
    expect(cip?.patchSha).toBe(BACKPORT_SHA);
    expect(cip?.upstreamSha).toBe(FIX_SHA_510);
    expect(cip?.title).toBe('netfilter: nf_tables: fix a wrong data length');
    expect(cip?.fixedIn).toBe('5.10.163');
    expect(cip?.cipRelease).toBe('v5.10.163-cip35');
    expect(cip?.url).toBe(`${CIP_MIRROR_URL}/commit/?id=${BACKPORT_SHA}`);

    // Record-derived stable candidates are still included.
    expect(patches.some((p) => p.branch === 'linux-5.10.y' && p.source === 'cve-record')).toBe(true);
    expect(patches.some((p) => p.branch === 'linux-6.1.y' && p.source === 'cve-record')).toBe(true);
  });

  it('reports branches without a backport as an explicit negative signal', async () => {
    const mirrorDir = seededMirror(freshTmp());
    const { run } = gitMock({
      fetchOk: true,
      describe: 'v5.10.163-cip35~7',
      log: (ref) => (ref === 'origin/linux-5.10.y-cip' ? backportLog : ''),
    });
    const provider = new CipGitProvider(async () => record, { run, mirrorDir });
    const patches = await provider.findPatches('CVE-2024-20988');

    const rt = patches.find((p) => p.branch === 'linux-5.10.y-cip-rt');
    expect(rt?.source).toBe('cip-mirror');
    expect(rt?.patchSha).toBeUndefined();
    expect(rt?.title).toContain('No backport');
  });

  it('degrades to record candidates when the mirror is unavailable (R1/R2)', async () => {
    const root = freshTmp();
    const { run } = gitMock({ cloneOk: false });
    const provider = new CipGitProvider(async () => record, {
      run,
      mirrorDir: join(root, 'missing-mirror'),
    });
    const patches = await provider.findPatches('CVE-2024-20988');

    expect(patches).toHaveLength(2);
    expect(patches.every((p) => p.source === 'cve-record')).toBe(true);
    expect(patches[0].branch).toBe('linux-5.10.y');
    expect(patches[0].upstreamSha).toBe(FIX_SHA_510);
    expect(patches[0].fixedIn).toBe('5.10.163');
    expect(patches[1].upstreamSha).toBe(FIX_SHA_61);
    expect(patches[1].fixedIn).toBe('6.1.78');
  });

  it('keeps serving an existing local clone while offline', async () => {
    const mirrorDir = seededMirror(freshTmp());
    const { run } = gitMock({
      fetchOk: false,
      describe: 'v5.10.163-cip35~7',
      log: () => backportLog,
    });
    const provider = new CipGitProvider(async () => record, { run, mirrorDir });
    const patches = await provider.findPatches('CVE-2024-20988');

    expect(patches.some((p) => p.source === 'cip-mirror' && p.patchSha === BACKPORT_SHA)).toBe(true);
  });

  it('skips mirror queries for CVEs outside the SLTS series', async () => {
    const root = freshTmp();
    const outside: CveRecord = {
      ...record,
      affectedRanges: [record.affectedRanges![1]],
    };
    const { run, calls } = gitMock({});
    const provider = new CipGitProvider(async () => outside, {
      run,
      mirrorDir: join(root, 'mirror'),
    });
    const patches = await provider.findPatches('CVE-2024-20988');

    expect(calls).toHaveLength(0);
    expect(patches).toHaveLength(1);
    expect(patches[0].branch).toBe('linux-6.1.y');
    expect(patches[0].source).toBe('cve-record');
  });

  it('omits cipRelease when the backport is not yet in a tagged release', async () => {
    const mirrorDir = seededMirror(freshTmp());
    const { run } = gitMock({ fetchOk: true, describeFail: true, log: () => backportLog });
    const provider = new CipGitProvider(async () => record, { run, mirrorDir });
    const patches = await provider.findPatches('CVE-2024-20988');

    const cip = patches.find((p) => p.branch === 'linux-5.10.y-cip');
    expect(cip?.patchSha).toBe(BACKPORT_SHA);
    expect(cip?.cipRelease).toBeUndefined();
  });

  it('returns [] when the CVE record is unknown', async () => {
    const root = freshTmp();
    const { run } = gitMock({});
    const provider = new CipGitProvider(async () => undefined, {
      run,
      mirrorDir: join(root, 'mirror'),
    });
    expect(await provider.findPatches('CVE-2024-20988')).toEqual([]);
  });
});

describe('parseGitLog', () => {
  it('parses multiple records and ignores a trailing separator', () => {
    const out =
      logRecord('aaa', 'subj1', 'date1', 'body1') +
      logRecord('bbb', 'subj2', 'date2', 'body2') +
      '\x1e';
    const commits = parseGitLog(out);
    expect(commits).toHaveLength(2);
    expect(commits[0]).toEqual({ sha: 'aaa', subject: 'subj1', authoredAt: 'date1', message: 'body1' });
    expect(commits[1].sha).toBe('bbb');
  });

  it('skips malformed or empty records', () => {
    expect(parseGitLog('\x1f only-fields \x1e')).toHaveLength(0);
    expect(parseGitLog('')).toHaveLength(0);
  });
});
