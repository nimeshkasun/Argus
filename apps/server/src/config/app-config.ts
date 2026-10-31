import { existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { z } from 'zod';

export type ArgusRole = 'all' | 'api' | 'worker';

const envSchema = z.object({
  ARGUS_DB_TYPE: z.enum(['postgres', 'mongodb'], { error: 'must be "postgres" or "mongodb"' }),
  ARGUS_DB_URL: z.string().min(1, 'is required'),
  ARGUS_DB_NAME: z.string().min(1).optional(),
  ARGUS_MASTER_KEY: z.string().min(32, 'must be at least 32 characters (generate one with: openssl rand -base64 48)'),
  ARGUS_ROLE: z.enum(['all', 'api', 'worker']).default('all'),
  ARGUS_ADMIN_PASSWORD: z.string().min(1).optional(),
  ARGUS_PUBLIC_URL: z.url().optional(),
  ARGUS_COOKIE_SECURE: z.enum(['auto', 'true', 'false']).default('auto'),
  ARGUS_TRUST_PROXY: z.string().default('1'),
  ARGUS_WEB_DIR: z.string().optional(),
  ARGUS_WORKER_CONCURRENCY: z.coerce.number().int().min(1).max(64).default(2),
  ARGUS_AUTH_RATE_LIMIT: z.coerce.number().int().min(1).max(10_000).default(10),
  ARGUS_SCAN_WORKDIR: z.string().optional(),
  ARGUS_SCAN_TIMEOUT_MINUTES: z.coerce.number().int().min(1).max(720).default(30),
  ARGUS_SCHEDULER_INTERVAL_SECONDS: z.coerce.number().int().min(1).max(3600).default(30),
  ARGUS_OFFLINE: z.enum(['true', 'false']).default('false'),
  SCAN: z.enum(['true', 'false']).default('true'),
  ARGUS_GITLEAKS_PATH: z.string().min(1).default('gitleaks'),
  ARGUS_OPENGREP_PATH: z.string().min(1).default('opengrep'),
  ARGUS_OPENGREP_RULES: z.string().min(1).optional(),
  ARGUS_TRIVY_PATH: z.string().min(1).default('trivy'),
  ARGUS_OSV_URL: z.url().default('https://api.osv.dev'),
  ARGUS_KEV_URL: z.url().default('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
  ARGUS_EPSS_URL: z.url().default('https://api.first.org/data/v1/epss'),
  ARGUS_EOL_URL: z.url().default('https://endoflife.date'),
  ARGUS_NPM_REGISTRY_URL: z.url().default('https://registry.npmjs.org'),
  ARGUS_NUGET_URL: z.url().default('https://api.nuget.org/v3-flatcontainer'),
  ARGUS_DEPSDEV_URL: z.url().default('https://api.deps.dev'),
  ARGUS_NVD_URL: z.url().default('https://services.nvd.nist.gov/rest/json/cves/2.0'),
  ARGUS_NVD_API_KEY: z.string().min(1).optional(),
  ARGUS_METRICS_TOKEN: z.string().min(16, 'must be at least 16 characters').optional(),
  ARGUS_GRAPH_URL: z.url().default('https://graph.microsoft.com'),
  ARGUS_ENTRA_LOGIN_URL: z.url().default('https://login.microsoftonline.com'),
  WEBSITES_PORT: z.coerce.number().int().positive().optional(),
  PORT: z.coerce.number().int().positive().default(8080),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  NODE_ENV: z.string().default('production'),
});

export class ConfigError extends Error {
  override name = 'ConfigError';
}

/** Validated runtime configuration. Built once at startup; invalid configuration fails fast. */
export class AppConfig {
  readonly dbType!: 'postgres' | 'mongodb';
  readonly dbUrl!: string;
  readonly dbName?: string;
  readonly masterKey!: string;
  readonly role!: ArgusRole;
  readonly adminPassword?: string;
  readonly publicUrl?: string;
  readonly cookieSecure!: boolean;
  readonly trustProxy!: boolean | number | string;
  readonly webDir!: string | null;
  readonly workerConcurrency!: number;
  /** Per-IP requests per minute for each credential endpoint (login, MFA verify, password change). */
  readonly authRateLimit!: number;
  /** Parent directory for ephemeral scan workspaces. */
  readonly scanWorkdir!: string;
  readonly scanTimeoutMs!: number;
  readonly schedulerIntervalMs!: number;
  /** No outbound threat-intelligence lookups; scanners that need them report partial results. */
  readonly offline!: boolean;
  /** False: this instance never runs repository scans; queued scans wait for a worker that does (e.g. local development). */
  readonly scanEnabled!: boolean;
  readonly gitleaksPath!: string;
  readonly opengrepPath!: string;
  /** Rules directory for code analysis; without one the code scanner is skipped. */
  readonly opengrepRules!: string | null;
  readonly trivyPath!: string;
  /** Base URLs of public data sources; point them at internal mirrors if required. */
  readonly intel!: { osv: string; kev: string; epss: string; eol: string; npmRegistry: string; nuget: string; depsDev: string; nvd: string; nvdApiKey: string | null };
  /** Microsoft cloud endpoints (override for sovereign clouds such as GCC High). */
  readonly microsoft!: { graph: string; login: string };
  /** Bearer token Prometheus must send to /metrics; null turns the endpoint off. */
  readonly metricsToken!: string | null;
  readonly port!: number;
  readonly logLevel!: string;
  readonly isProduction!: boolean;
  readonly version!: string;

  constructor(values: Omit<AppConfig, never>) {
    Object.assign(this, values);
  }

  static fromEnv(env: NodeJS.ProcessEnv): AppConfig {
    // Orchestrators (docker compose, App Service) often pass optional settings as empty strings: treat those as unset.
    const parsed = envSchema.safeParse(Object.fromEntries(Object.entries(env).filter(([, v]) => v !== undefined && v.trim() !== '')));
    if (!parsed.success) {
      const lines = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`);
      throw new ConfigError(`Invalid Argus configuration:\n${lines.join('\n')}\nSee docs/configuration.md.`);
    }
    const e = parsed.data;
    const isProduction = e.NODE_ENV === 'production';
    const cookieSecure =
      e.ARGUS_COOKIE_SECURE === 'auto' ? (e.ARGUS_PUBLIC_URL ? e.ARGUS_PUBLIC_URL.startsWith('https://') : isProduction) : e.ARGUS_COOKIE_SECURE === 'true';

    return new AppConfig({
      dbType: e.ARGUS_DB_TYPE,
      dbUrl: e.ARGUS_DB_URL,
      dbName: e.ARGUS_DB_NAME,
      masterKey: e.ARGUS_MASTER_KEY,
      role: e.ARGUS_ROLE,
      adminPassword: e.ARGUS_ADMIN_PASSWORD,
      publicUrl: e.ARGUS_PUBLIC_URL?.replace(/\/+$/, ''),
      cookieSecure,
      trustProxy: parseTrustProxy(e.ARGUS_TRUST_PROXY),
      webDir: resolveWebDir(e.ARGUS_WEB_DIR),
      workerConcurrency: e.ARGUS_WORKER_CONCURRENCY,
      authRateLimit: e.ARGUS_AUTH_RATE_LIMIT,
      scanWorkdir: resolve(e.ARGUS_SCAN_WORKDIR ?? join(tmpdir(), 'argus-scans')),
      scanTimeoutMs: e.ARGUS_SCAN_TIMEOUT_MINUTES * 60_000,
      schedulerIntervalMs: e.ARGUS_SCHEDULER_INTERVAL_SECONDS * 1000,
      offline: e.ARGUS_OFFLINE === 'true',
      scanEnabled: e.SCAN === 'true',
      gitleaksPath: e.ARGUS_GITLEAKS_PATH,
      opengrepPath: e.ARGUS_OPENGREP_PATH,
      opengrepRules: e.ARGUS_OPENGREP_RULES ? resolve(e.ARGUS_OPENGREP_RULES) : null,
      trivyPath: e.ARGUS_TRIVY_PATH,
      intel: {
        osv: trimSlash(e.ARGUS_OSV_URL),
        kev: e.ARGUS_KEV_URL,
        epss: trimSlash(e.ARGUS_EPSS_URL),
        eol: trimSlash(e.ARGUS_EOL_URL),
        npmRegistry: trimSlash(e.ARGUS_NPM_REGISTRY_URL),
        nuget: trimSlash(e.ARGUS_NUGET_URL),
        depsDev: trimSlash(e.ARGUS_DEPSDEV_URL),
        nvd: trimSlash(e.ARGUS_NVD_URL),
        nvdApiKey: e.ARGUS_NVD_API_KEY ?? null,
      },
      microsoft: { graph: trimSlash(e.ARGUS_GRAPH_URL), login: trimSlash(e.ARGUS_ENTRA_LOGIN_URL) },
      metricsToken: e.ARGUS_METRICS_TOKEN ?? null,
      // Azure App Service passes the container port in WEBSITES_PORT.
      port: e.WEBSITES_PORT ?? e.PORT,
      logLevel: e.LOG_LEVEL,
      isProduction,
      version: readVersion(),
    });
  }
}

function trimSlash(url: string): string {
  return url.replace(/\/+$/, '');
}

function parseTrustProxy(value: string): boolean | number | string {
  if (value === 'true') return true;
  if (value === 'false') return false;
  return /^\d+$/.test(value) ? Number(value) : value;
}

function resolveWebDir(configured: string | undefined): string | null {
  const dir = configured ? resolve(configured) : resolve(__dirname, '../../../web/dist');
  return existsSync(join(dir, 'index.html')) ? dir : null;
}

function readVersion(): string {
  try {
    return (JSON.parse(readFileSync(resolve(__dirname, '../../package.json'), 'utf8')) as { version: string }).version;
  } catch {
    return '0.0.0';
  }
}
