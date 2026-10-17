import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import {
  collectInventory,
  extractIkconfig,
  parseConfigText,
  parseKernelVersion,
  type InventoryOptions,
} from '../src/providers/system-inventory';

const RELEASE = '5.10.209-cip50';
const PROC_VERSION = `Linux version ${RELEASE} (builder@cip) (gcc 10.2.1) #1 SMP PREEMPT`;
const CONFIG_TEXT = [
  '#',
  '# Automatically generated file; DO NOT EDIT.',
  '#',
  'CONFIG_EXT4_FS=y',
  'CONFIG_NF_TABLES=m',
  '# CONFIG_WLAN is not set',
  'CONFIG_LOCALVERSION="-cip"',
  '',
].join('\n');

/** Injectable whitelisted read surface backed by an in-memory file map. */
function fakeFs(files: Record<string, string | Buffer>): InventoryOptions {
  const readFileSync = (path: string): Buffer => {
    const value = files[path];
    if (value === undefined) throw new Error(`ENOENT: ${path}`);
    return typeof value === 'string' ? Buffer.from(value, 'utf8') : value;
  };
  const existsSync = (path: string): boolean => path in files;
  return { readFileSync, existsSync };
}

/** Kernel image with an embedded, gzip-compressed IKCONFIG blob. */
function imageWithIkconfig(configText: string): Buffer {
  return Buffer.concat([
    Buffer.from([0xde, 0xad, 0xbe, 0xef]),
    Buffer.from('IKCFG_ST', 'latin1'),
    gzipSync(Buffer.from(configText, 'utf8')),
    Buffer.from('IKCFG_ED', 'latin1'),
    Buffer.from([0xca, 0xfe]),
  ]);
}

describe('parseKernelVersion (module P1)', () => {
  it('extracts the release token from /proc/version', () => {
    expect(
      parseKernelVersion('Linux version 5.10.209-cip50 (builder@cip) (gcc 10.2.1) #1 SMP'),
    ).toBe('5.10.209-cip50');
  });
});

describe('parseConfigText', () => {
  it('parses =y/=m values and quoted string values', () => {
    const config = parseConfigText(CONFIG_TEXT);
    expect(config['CONFIG_EXT4_FS']).toBe('y');
    expect(config['CONFIG_NF_TABLES']).toBe('m');
    expect(config['CONFIG_LOCALVERSION']).toBe('"-cip"');
  });

  it("normalizes '# CONFIG_X is not set' to 'n' (real configs never emit =n)", () => {
    const config = parseConfigText(CONFIG_TEXT);
    expect(config['CONFIG_WLAN']).toBe('n');
  });
});

describe('extractIkconfig', () => {
  it('extracts and decompresses the embedded config blob', () => {
    const blob = extractIkconfig(imageWithIkconfig(CONFIG_TEXT));
    expect(blob?.toString('utf8')).toBe(CONFIG_TEXT);
    const config = parseConfigText(blob!.toString('utf8'));
    expect(config['CONFIG_EXT4_FS']).toBe('y');
    expect(config['CONFIG_WLAN']).toBe('n');
  });

  it('returns undefined when the image carries no IKCONFIG blob', () => {
    expect(extractIkconfig(Buffer.from('no magic in here'))).toBeUndefined();
  });

  it('returns undefined when the blob is truncated (no IKCFG_ED terminator)', () => {
    const image = Buffer.concat([
      Buffer.from('IKCFG_ST', 'latin1'),
      gzipSync(Buffer.from('CONFIG_X=y\n', 'utf8')),
    ]);
    expect(extractIkconfig(image)).toBeUndefined();
  });

  it('keeps scanning past a false IKCFG_ST marker without a gzip header', () => {
    const image = Buffer.concat([
      Buffer.from('IKCFG_ST', 'latin1'),
      Buffer.from('not gzip at all'),
      Buffer.from('IKCFG_ST', 'latin1'),
      gzipSync(Buffer.from('CONFIG_X=y\n', 'utf8')),
      Buffer.from('IKCFG_ED', 'latin1'),
    ]);
    expect(extractIkconfig(image)?.toString('utf8')).toBe('CONFIG_X=y\n');
  });
});

describe('config fallback chain (module P1, Rules R2/R3)', () => {
  it('reads /proc/config.gz when available and reports the source', () => {
    const inv = collectInventory(
      fakeFs({
        '/proc/version': PROC_VERSION,
        '/proc/config.gz': gzipSync(Buffer.from(CONFIG_TEXT, 'utf8')),
      }),
    );
    expect(inv.kernelVersion).toBe(RELEASE);
    expect(inv.configSource).toBe('proc-config-gz');
    expect(inv.config['CONFIG_EXT4_FS']).toBe('y');
    expect(inv.config['CONFIG_WLAN']).toBe('n');
  });

  it('falls back to the distro /boot config when procfs config is missing', () => {
    const inv = collectInventory(
      fakeFs({
        '/proc/version': PROC_VERSION,
        [`/boot/config-${RELEASE}`]: CONFIG_TEXT,
      }),
    );
    expect(inv.configSource).toBe('boot-config');
    expect(inv.config['CONFIG_NF_TABLES']).toBe('m');
  });

  it('extracts the config from the kernel image via IKCONFIG as a last resort', () => {
    const inv = collectInventory(
      fakeFs({
        '/proc/version': PROC_VERSION,
        [`/boot/vmlinux-${RELEASE}`]: imageWithIkconfig(CONFIG_TEXT),
      }),
    );
    expect(inv.configSource).toBe('ikconfig');
    expect(inv.config['CONFIG_EXT4_FS']).toBe('y');
  });

  it('tries /boot/vmlinux after the release-specific image', () => {
    const inv = collectInventory(
      fakeFs({
        '/proc/version': PROC_VERSION,
        '/boot/vmlinux': imageWithIkconfig(CONFIG_TEXT),
      }),
    );
    expect(inv.configSource).toBe('ikconfig');
  });

  it('continues down the chain when a source exists but is unreadable', () => {
    const configPaths = ['/proc/config.gz', `/boot/config-${RELEASE}`, `/boot/vmlinux-${RELEASE}`, '/boot/vmlinux'];
    const inv = collectInventory({
      existsSync: (p) => p === '/proc/version' || configPaths.includes(p),
      readFileSync: (p): Buffer => {
        if (p === '/proc/version') return Buffer.from(PROC_VERSION, 'utf8');
        throw new Error('unreadable source');
      },
    });
    expect(inv.configSource).toBe('none');
    expect(inv.config).toEqual({});
  });

  it('reports configSource none with an empty config when nothing is available', () => {
    const inv = collectInventory(fakeFs({ '/proc/version': PROC_VERSION }));
    expect(inv.configSource).toBe('none');
    expect(inv.config).toEqual({});
  });

  it('collects loaded modules and distro info from the whitelisted paths', () => {
    const inv = collectInventory(
      fakeFs({
        '/proc/version': PROC_VERSION,
        '/proc/modules':
          'nf_tables 245760 3 - Live 0x0000000000000000\next4 614400 1 - Live 0x0000000000000000\n',
        '/etc/os-release': 'ID=debian\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\n',
      }),
    );
    expect(inv.configSource).toBe('none');
    expect(inv.modules).toHaveLength(2);
    expect(inv.modules[0].name).toBe('nf_tables');
    expect(inv.modules[0].sizeKb).toBe(245760);
    expect(inv.modules[1].sizeKb).toBe(614400);
    expect(inv.distro.id).toBe('debian');
    expect(inv.distro.name).toBe('Debian GNU/Linux');
    expect(inv.distro.version).toBe('12');
  });
});
