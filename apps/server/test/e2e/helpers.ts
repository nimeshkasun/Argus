import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { GenericContainer, type StartedTestContainer, Wait } from 'testcontainers';
import { type INestApplication } from '@nestjs/common';
import request from 'supertest';

/** Minimal cookie-aware client that echoes the CSRF cookie like the SPA does. */
export class Client {
  cookies = new Map<string, string>();

  constructor(private readonly app: INestApplication) {}

  async call(method: 'get' | 'post' | 'patch' | 'put' | 'delete', path: string, body?: object, opts: { csrf?: boolean; headers?: Record<string, string> } = {}) {
    let r = request(this.app.getHttpServer())[method](path).set('Cookie', [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; '));
    const csrf = this.cookies.get('argus_csrf');
    if (csrf && opts.csrf !== false) r = r.set('x-csrf-token', csrf);
    for (const [k, v] of Object.entries(opts.headers ?? {})) r = r.set(k, v);
    const res = await (body ? r.send(body) : r);
    for (const c of ([] as string[]).concat(res.headers['set-cookie'] ?? [])) {
      const [pair] = c.split(';');
      const idx = pair.indexOf('=');
      const name = pair.slice(0, idx);
      const value = decodeURIComponent(pair.slice(idx + 1));
      if (value === '' || /Expires=Thu, 01 Jan 1970/i.test(c)) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return res;
  }

  login(username: string, password: string) {
    return this.call('post', '/api/v1/auth/login', { username, password });
  }
}

export interface DbHarness {
  name: 'postgres' | 'mongodb';
  env(): Promise<Record<string, string>>;
  stop(): Promise<void>;
}

/** One harness per supported database, each backed by a throwaway container. */
export function dbHarnesses(): DbHarness[] {
  let pg: StartedPostgreSqlContainer | undefined;
  let mongo: StartedTestContainer | undefined;
  return [
    {
      name: 'postgres',
      async env() {
        pg = await new PostgreSqlContainer('postgres:17-alpine').start();
        return { ARGUS_DB_TYPE: 'postgres', ARGUS_DB_URL: pg.getConnectionUri() };
      },
      stop: async () => void (await pg?.stop()),
    },
    {
      name: 'mongodb',
      async env() {
        // Same container setup as packages/data/test/mongo-container.ts (kept in sync).
        const started = await startMongo();
        mongo = started.container;
        return { ARGUS_DB_TYPE: 'mongodb', ARGUS_DB_URL: started.url, ARGUS_DB_NAME: 'argus_e2e' };
      },
      stop: async () => void (await mongo?.stop()),
    },
  ];
}

const MONGO_IMAGE = process.env.ARGUS_TEST_MONGO_IMAGE ?? 'mongo:8.0';

/** Single-node MongoDB; on failure the error includes mongod's own output so CI logs show the cause. */
async function startMongo(): Promise<{ container: StartedTestContainer; url: string }> {
  const output: string[] = [];
  try {
    const container = await new GenericContainer(MONGO_IMAGE)
      .withCommand(['mongod', '--bind_ip_all', '--wiredTigerCacheSizeGB', '0.25'])
      // MongoDB 8 refuses to start on Linux 6.19+ kernels (SERVER-121912), which GitHub's runners now use, while
      // TCMalloc per-CPU caches are active. glibc owning rseq turns those caches off and lets mongod start.
      .withEnvironment({ GLIBC_TUNABLES: 'glibc.pthread.rseq=1' })
      .withExposedPorts(27017)
      .withLogConsumer((stream) => stream.on('data', (line: Buffer | string) => output.push(String(line).trimEnd())))
      .withWaitStrategy(Wait.forLogMessage(/Waiting for connections/))
      .withStartupTimeout(120_000)
      .start();
    return { container, url: `mongodb://${container.getHost()}:${container.getMappedPort(27017)}/?directConnection=true` };
  } catch (err) {
    const tail = output.slice(-40).join('\n');
    throw new Error(`${err instanceof Error ? err.message : String(err)}\n--- ${MONGO_IMAGE} output ---\n${tail || '(no output)'}`);
  }
}

export const BASE_TEST_ENV = {
  ARGUS_MASTER_KEY: 'e2e-master-key-0123456789-abcdefghijklmnop',
  ARGUS_WEB_DIR: '/nonexistent',
  LOG_LEVEL: 'silent',
  NODE_ENV: 'test',
  ARGUS_AUTH_RATE_LIMIT: '1000',
  // External scanning tools are never used in tests, even if installed: their scanners report "skipped".
  ARGUS_OPENGREP_PATH: 'argus-test-no-opengrep',
  ARGUS_TRIVY_PATH: 'argus-test-no-trivy',
};

export async function waitFor<T>(fn: () => Promise<T | null | undefined | false>, opts: { timeoutMs?: number; intervalMs?: number; what?: string } = {}): Promise<T> {
  const deadline = Date.now() + (opts.timeoutMs ?? 60_000);
  let last: unknown;
  while (Date.now() < deadline) {
    try {
      const v = await fn();
      if (v) return v;
    } catch (err) {
      last = err;
    }
    await new Promise((r) => setTimeout(r, opts.intervalMs ?? 250));
  }
  throw new Error(`Timed out waiting for ${opts.what ?? 'condition'}${last ? `: ${String(last)}` : ''}`);
}
