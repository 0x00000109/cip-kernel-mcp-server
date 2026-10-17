import { existsSync, readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import type { InventoryProvider, KernelInventory, ModuleInfo } from '../engine/types.js';

/**
 * System Inventory provider (Rules R2/R3, module P1).
 * Read-only and least privilege: only a whitelisted set of paths is touched
 * (/proc/version, /proc/config.gz, /proc/modules, /etc/os-release).
 * No arbitrary file reads — see docs/THREAT-MODEL.md.
 */
export class SystemInventoryProvider implements InventoryProvider {
  readonly id = 'system-inventory';

  async init(): Promise<void> {
    if (!existsSync('/proc/version')) {
      throw new Error(
        'Not a Linux system: /proc/version not found. scan_system supports Linux hosts only.',
      );
    }
  }

  async collect(): Promise<KernelInventory> {
    return collectInventory();
  }
}

export function collectInventory(): KernelInventory {
  const kernelVersion = parseKernelVersion(readFileSync('/proc/version', 'utf8'));
  return {
    kernelVersion,
    arch: process.arch,
    config: readKernelConfig(),
    modules: readLoadedModules(),
    distro: readDistro(),
    packages: [], // TODO(P1): package enumeration via dpkg/apk (module P5)
    collectedAt: new Date().toISOString(),
  };
}

function parseKernelVersion(procVersion: string): string {
  // Format: "Linux version 5.10.209-cip50 (...) ..."
  const match = /Linux version (\S+)/.exec(procVersion);
  return match ? match[1] : 'unknown';
}

function readKernelConfig(): Record<string, string> {
  const config: Record<string, string> = {};
  if (existsSync('/proc/config.gz')) {
    const text = gunzipSync(readFileSync('/proc/config.gz')).toString('utf8');
    for (const line of text.split('\n')) {
      const match = /^(CONFIG_\w+)=(.+)$/.exec(line);
      if (match) {
        config[match[1]] = match[2];
      }
    }
  }
  // TODO(P0+): fall back to IKCONFIG extraction from the kernel image, and to
  // /sys/module inventory when CONFIG_IKCONFIG_PROC is off.
  return config;
}

function readLoadedModules(): ModuleInfo[] {
  const modules: ModuleInfo[] = [];
  if (existsSync('/proc/modules')) {
    for (const line of readFileSync('/proc/modules', 'utf8').split('\n')) {
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
  }
  return modules;
}

function readDistro(): { id?: string; name?: string; version?: string } {
  if (!existsSync('/etc/os-release')) return {};
  const info: Record<string, string> = {};
  for (const line of readFileSync('/etc/os-release', 'utf8').split('\n')) {
    const match = /^([A-Z_]+)="?(.*?)"?$/.exec(line.trim());
    if (match) {
      info[match[1]] = match[2];
    }
  }
  return { id: info.ID, name: info.NAME, version: info.VERSION_ID };
}
