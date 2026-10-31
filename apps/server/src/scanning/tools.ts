import { execFile } from 'node:child_process';
import { readFile, rm } from 'node:fs/promises';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const probes = new Map<string, Promise<string | null>>();

/** Version printed by `binary <args>`, or null if the tool is not installed. Probed once per process. */
export function toolVersion(binary: string, args: string[], parse: (stdout: string) => string | null = (s) => s.trim() || 'unknown'): Promise<string | null> {
  const key = `${binary}\u0000${args.join(' ')}`;
  let probe = probes.get(key);
  if (!probe) {
    probe = execFileAsync(binary, args, { timeout: 15_000, windowsHide: true })
      .then(({ stdout }) => parse(stdout))
      .catch(() => null);
    probes.set(key, probe);
  }
  return probe;
}

export const opengrepVersion = (binary: string) => toolVersion(binary, ['--version'], (s) => s.trim().split(/\s+/).pop() || 'unknown');
export const trivyVersion = (binary: string) => toolVersion(binary, ['--version'], (s) => /Version:\s*(\S+)/.exec(s)?.[1] ?? null);

export class ToolError extends Error {
  override name = 'ToolError';
}

/**
 * Runs a scanning tool that writes a JSON report, and returns the parsed report. The tool runs without a shell, in
 * the checkout, with a timeout; a non-zero exit is only an error if no report was written. The report is deleted.
 */
export async function runJsonTool<T>(binary: string, args: string[], opts: { cwd: string; report: string; timeoutMs: number; env?: NodeJS.ProcessEnv }): Promise<T> {
  let failure: string | null = null;
  try {
    await execFileAsync(binary, args, { cwd: opts.cwd, timeout: opts.timeoutMs, windowsHide: true, maxBuffer: 32 * 1024 * 1024, env: { ...process.env, ...opts.env } });
  } catch (err) {
    const e = err as { killed?: boolean; signal?: string; stderr?: string; message: string };
    failure = e.killed || e.signal === 'SIGTERM' ? `timed out after ${Math.round(opts.timeoutMs / 1000)} s` : (e.stderr?.trim().split('\n').slice(-3).join(' ') || e.message).slice(0, 500);
  }
  try {
    return JSON.parse(await readFile(opts.report, 'utf8')) as T;
  } catch {
    throw new ToolError(failure ?? 'no report was written');
  } finally {
    await rm(opts.report, { force: true });
  }
}
