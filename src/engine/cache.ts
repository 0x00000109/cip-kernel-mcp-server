import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export interface CacheEntry<T> {
  value: T;
  fetchedAt: string;
  fresh: boolean;
}

/**
 * Offline-first cache manager (Rule R2, module E4).
 * All remote data is cached locally for air-gapped use, and stale data is
 * served with `fresh: false` when a refresh fails — callers surface the
 * freshness stamp with every answer (see THREAT-MODEL.md).
 */
export class CacheManager {
  constructor(
    private readonly cacheDir: string,
    private readonly ttlMs: number = 24 * 60 * 60 * 1000,
  ) {
    mkdirSync(this.cacheDir, { recursive: true });
  }

  async wrap<T>(namespace: string, key: string, fetcher: () => Promise<T> | T): Promise<CacheEntry<T>> {
    const path = this.pathFor(namespace, key);

    if (existsSync(path)) {
      const raw = JSON.parse(readFileSync(path, 'utf8')) as { value: T; fetchedAt: string };
      const age = Date.now() - Date.parse(raw.fetchedAt);
      if (age <= this.ttlMs) {
        return { value: raw.value, fetchedAt: raw.fetchedAt, fresh: true };
      }
      // Stale: try to refresh, fall back to the stale copy for offline use.
      try {
        const value = await fetcher();
        this.write(path, value);
        return { value, fetchedAt: new Date().toISOString(), fresh: true };
      } catch {
        return { value: raw.value, fetchedAt: raw.fetchedAt, fresh: false };
      }
    }

    const value = await fetcher();
    this.write(path, value);
    return { value, fetchedAt: new Date().toISOString(), fresh: true };
  }

  private write(path: string, value: unknown): void {
    writeFileSync(path, JSON.stringify({ value, fetchedAt: new Date().toISOString() }));
  }

  private pathFor(namespace: string, key: string): string {
    return join(this.cacheDir, `${namespace}-${encodeURIComponent(key)}.json`);
  }
}
