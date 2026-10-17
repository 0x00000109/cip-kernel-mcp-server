import { existsSync, readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import type {
  ConfigSource,
  InventoryProvider,
  KernelInventory,
  ModuleInfo,
} from '../engine/types.js';

/**
 * System Inventory provider (Rules R2/R3, module P1).
 * Read-only and least privilege: only a whitelisted set of paths is touched
 * (/proc/version, /proc/config.gz, /proc/modules, /etc/os-release,
 * /boot/config-<release>, /boot/vmlinux-<release>). No arbitrary file
 * reads — see docs/THREAT-MODEL.md.
 *
 * The kernel config is resolved along a fallback chain, because embedded and
 * hardened builds often ship without CONFIG_IKCONFIG_PROC:
 *   1. /proc/config.gz          — when CONFIG_IKCONFIG_PROC=y
 *   2. /boot/config-<release>   — distro-shipped config for the running kernel
 *   3. IKCONFIG blob extracted from /boot/vmlinux-<release> (then /boot/vmlinux)
 *      — when CONFIG_IKCONFIG=y; the embedded, gzip-compressed config image
 * The resolved source is reported as `configSource` on the inventory so
 * verdicts can cite where the config evidence came from (Rule R8).
 */

/** Whitelisted kernel-image candidates for IKCONFIG extraction, in order. */
const kernelImageCandidates = (release: string): string[] => [
  `/boot/vmlinux-${release}`,
  '/boot/vmlinux',
];

/**
 * Embedded ikconfig framing: gzip data between these markers inside the
 * kernel image (same layout the kernel's scripts/extract-ikconfig scans for).
 */
const IKCFG_ST = Buffer.from('IKCFG_ST', 'latin1');
const IKCFG_ED = Buffer.from('IKCFG_ED', 'latin1');
const GZIP_MAGIC = Buffer.from([0x1f, 0x8b]);

/**
 * Injectable read surface: tests stub the whitelisted paths, the engine
 * gets the real node:fs. `readFileSync` must throw when unavailable.
 */
export interface InventoryOptions {
  readFileSync?: (path: string) => Buffer;
  existsSync?: (path: string) => boolean;
}

export class SystemInventoryProvider implements InventoryProvider {
  readonly id = 'system-inventory';

  private readonly read: (path: string) => Buffer;
  private readonly exists: (path: string) => boolean;

  constructor(opts: InventoryOptions = {}) {
    this.read = opts.readFileSync ?? readFileSync;
    this.exists = opts.existsSync ?? existsSync;
  }

  async init(): Promise<void> {
    if (!this.exists('/proc/version')) {
      throw new Error(
        'Not a Linux system: /proc/version not found. scan_system supports Linux hosts only.',
      );
    }
  }

  async collect(): Promise<KernelInventory> {
    return collectInventory({ readFileSync: this.read, existsSync: this.exists });
  }
}

export function collectInventory(opts: InventoryOptions = {}): KernelInventory {
  const read = opts.readFileSync ?? readFileSync;
  const exists = opts.existsSync ?? existsSync;

  const kernelVersion = parseKernelVersion(read('/proc/version').toString('utf8'));
  const { config, source } = readKernelConfig(kernelVersion, { read, exists });
  return {
    kernelVersion,
    arch: process.arch,
    config,
    configSource: source,
    modules: readLoadedModules({ read, exists }),
    distro: readDistro({ read, exists }),
    packages: [], // TODO(P1): package enumeration via dpkg/apk (module P5)
    collectedAt: new Date().toISOString(),
  };
}

/** Format: "Linux version 5.10.209-cip50 (gcc ...) ..." — first token is the release. */
export function parseKernelVersion(procVersion: string): string {
  const match = /Linux version (\S+)/.exec(procVersion);
  return match ? match[1] : 'unknown';
}

/**
 * Parse kernel config text into a CONFIG symbol map. Values are kept as
 * written (`y`, `m`, quoted strings). Disabled options are rendered as
 * comments in real config files (`# CONFIG_X is not set`), never as `=n`;
 * they are normalized to 'n' so the applicability config gate can rule
 * subsystems out (Rule R3).
 */
export function parseConfigText(text: string): Record<string, string> {
  const config: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const set = /^(CONFIG_\w+)=(.+)$/.exec(line);
    if (set) {
      config[set[1]] = set[2];
      continue;
    }
    const notSet = /^#\s+(CONFIG_\w+) is not set$/.exec(line);
    if (notSet) {
      config[notSet[1]] = 'n';
    }
  }
  return config;
}

interface ReadSurface {
  read: (path: string) => Buffer;
  exists: (path: string) => boolean;
}

function readKernelConfig(
  release: string,
  surface: ReadSurface,
): { config: Record<string, string>; source: ConfigSource } {
  if (surface.exists('/proc/config.gz')) {
    try {
      return {
        config: parseConfigText(gunzipSync(surface.read('/proc/config.gz')).toString('utf8')),
        source: 'proc-config-gz',
      };
    } catch {
      /* corrupt or unreadable — try the next source */
    }
  }

  const bootConfig = `/boot/config-${release}`;
  if (surface.exists(bootConfig)) {
    try {
      return {
        config: parseConfigText(surface.read(bootConfig).toString('utf8')),
        source: 'boot-config',
      };
    } catch {
      /* unreadable — fall through */
    }
  }

  // CONFIG_IKCONFIG embeds the config as a gzip blob framed by IKCFG_ST/
  // IKCFG_ED markers inside the kernel image. Uncompressed vmlinux images
  // carry the framing verbatim; in a compressed bzImage the blob sits
  // behind the wrapper compression, which we do not attempt (documented
  // limitation — such hosts should ship /boot/config-* or enable IKCONFIG_PROC).
  for (const image of kernelImageCandidates(release)) {
    if (!surface.exists(image)) continue;
    try {
      const blob = extractIkconfig(surface.read(image));
      if (blob) {
        return { config: parseConfigText(blob.toString('utf8')), source: 'ikconfig' };
      }
    } catch {
      /* unreadable image — try the next candidate */
    }
  }

  return { config: {}, source: 'none' };
}

/**
 * Extract the gzip-compressed IKCONFIG blob from a kernel image buffer.
 * Scans for the IKCFG_ST marker followed by a gzip header and bounded by
 * the next IKCFG_ED marker. Returns undefined when no intact framing is
 * found.
 */
export function extractIkconfig(image: Uint8Array): Buffer | undefined {
  const buf = Buffer.isBuffer(image) ? image : Buffer.from(image);
  let start = buf.indexOf(IKCFG_ST);
  while (start !== -1) {
    const gzStart = start + IKCFG_ST.length;
    if (buf.subarray(gzStart, gzStart + GZIP_MAGIC.length).equals(GZIP_MAGIC)) {
      const end = buf.indexOf(IKCFG_ED, gzStart);
      if (end !== -1) {
        try {
          return gunzipSync(buf.subarray(gzStart, end));
        } catch {
          /* corrupt blob — keep scanning for another framing */
        }
      }
    }
    start = buf.indexOf(IKCFG_ST, start + 1);
  }
  return undefined;
}

function readLoadedModules(surface: ReadSurface): ModuleInfo[] {
  const modules: ModuleInfo[] = [];
  if (!surface.exists('/proc/modules')) return modules;
  for (const line of surface.read('/proc/modules').toString('utf8').split('\n')) {
    if (!line.trim()) continue;
    // Format: name size used use_count state [core_deps]
    const parts = line.split(' ');
    if (parts.length < 6) continue;
    modules.push({
      name: parts[0],
      sizeKb: Number(parts[1]) || 0,
      usedBy: parts[3] && parts[3] !== '0' ? parts[3].split(',') : [],
    });
  }
  return modules;
}

function readDistro(surface: ReadSurface): { id?: string; name?: string; version?: string } {
  if (!surface.exists('/etc/os-release')) return {};
  const info: Record<string, string> = {};
  for (const line of surface.read('/etc/os-release').toString('utf8').split('\n')) {
    const match = /^([A-Z_]+)="?(.*?)"?$/.exec(line.trim());
    if (match) {
      info[match[1]] = match[2];
    }
  }
  return { id: info.ID, name: info.NAME, version: info.VERSION_ID };
}
