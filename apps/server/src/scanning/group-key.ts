import { canonicalPackageName, type FindingPackage, type FindingSecret, type ScannerName } from '@argus/shared';

export interface GroupableFinding {
  scanner: ScannerName;
  ruleId: string;
  path: string | null;
  package: FindingPackage | null;
  secret: FindingSecret | null;
  details: Record<string, unknown> | null;
}

/**
 * Identity of the issue a ticket tracks within a repository. Findings that describe the same issue share it:
 * one advisory for one package across several manifests, one secret value in several files, one framework
 * release cycle used by several projects.
 */
export function groupKeyFor(f: GroupableFinding): string {
  const pkg = f.package ? `${f.package.ecosystem}:${canonicalPackageName(f.package.ecosystem, f.package.name)}` : '';
  switch (f.scanner) {
    case 'dependencies':
    case 'licenses':
      return `${f.scanner}|${f.ruleId}|${pkg}`;
    case 'secrets':
      return `secrets|${f.secret?.hash ?? `${f.ruleId}|${f.path}`}`;
    case 'frameworks':
      return `frameworks|${String(f.details?.product ?? f.ruleId)}|${String(f.details?.cycle ?? f.path)}`;
    case 'certificates':
      return `certificates|${f.ruleId}|${String(f.details?.fingerprintSha256 ?? f.secret?.hash ?? f.path)}`;
  }
}
