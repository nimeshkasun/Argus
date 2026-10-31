import { type Dependency, type Finding, type Repository } from '@argus/data';
import { canonicalPackageName, type Ecosystem } from '@argus/shared';

const segments = (path: string) => path.split('/').map(encodeURIComponent).join('/');

/** Package URL (https://github.com/package-url/purl-spec) of a package version. */
export function purl(ecosystem: Ecosystem, name: string, version: string): string {
  const v = encodeURIComponent(version);
  switch (ecosystem) {
    case 'npm':
      return `pkg:npm/${name.startsWith('@') ? `%40${segments(name.slice(1))}` : encodeURIComponent(name)}@${v}`;
    case 'nuget':
      return `pkg:nuget/${encodeURIComponent(name)}@${v}`;
    case 'pypi':
      return `pkg:pypi/${encodeURIComponent(canonicalPackageName('pypi', name))}@${v}`;
    case 'maven': {
      const [group, artifact] = name.split(':');
      return `pkg:maven/${encodeURIComponent(group)}/${encodeURIComponent(artifact ?? '')}@${v}`;
    }
    case 'go':
      return `pkg:golang/${segments(name)}@${v}`;
    case 'cargo':
      return `pkg:cargo/${encodeURIComponent(name)}@${v}`;
  }
}

function licenseEntry(license: string | null) {
  if (!license) return undefined;
  return /\s(OR|AND|WITH)\s|[()]/i.test(license) ? [{ expression: license }] : [{ license: { id: license } }];
}

function cvssMethod(vector: string | null): string {
  if (vector?.startsWith('CVSS:3.1')) return 'CVSSv31';
  if (vector?.startsWith('CVSS:3.0')) return 'CVSSv3';
  if (vector?.startsWith('CVSS:4')) return 'CVSSv4';
  return 'other';
}

/** CycloneDX 1.5 JSON document for a repository's latest dependency inventory and open vulnerabilities. */
export function buildCycloneDx(repo: Repository, deps: Dependency[], vulnFindings: Finding[], tool: { version: string }, serial: string) {
  const components = new Map<string, { purl: string; dep: Dependency; manifests: Set<string> }>();
  for (const d of deps) {
    const ref = purl(d.ecosystem, d.name, d.version);
    const existing = components.get(ref);
    if (existing) {
      existing.manifests.add(d.manifestPath);
      existing.dep = { ...existing.dep, direct: existing.dep.direct || d.direct, dev: existing.dep.dev && d.dev };
    } else components.set(ref, { purl: ref, dep: d, manifests: new Set([d.manifestPath]) });
  }

  const vulnerabilities = new Map<string, { id: string; source?: { url: string }; ratings: unknown[]; description?: string; affects: { ref: string }[] }>();
  for (const f of vulnFindings) {
    if (!f.advisory || !f.package) continue;
    const ref = purl(f.package.ecosystem, f.package.name, f.package.version);
    if (!components.has(ref)) continue;
    const v = vulnerabilities.get(f.advisory.id) ?? {
      id: f.advisory.id,
      ...(f.advisory.url ? { source: { url: f.advisory.url } } : {}),
      ratings: f.advisory.cvssScore !== null ? [{ score: f.advisory.cvssScore, method: cvssMethod(f.advisory.cvssVector), ...(f.advisory.cvssVector ? { vector: f.advisory.cvssVector } : {}) }] : [],
      ...(f.advisory.summary ? { description: f.advisory.summary } : {}),
      affects: [],
    };
    if (!v.affects.some((a) => a.ref === ref)) v.affects.push({ ref });
    vulnerabilities.set(f.advisory.id, v);
  }

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${serial}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: { components: [{ type: 'application', name: 'Argus', version: tool.version }] },
      component: { type: 'application', 'bom-ref': repo.id, name: repo.fullName, ...(repo.htmlUrl ? { externalReferences: [{ type: 'vcs', url: repo.htmlUrl }] } : {}) },
    },
    components: [...components.values()].map(({ purl: ref, dep, manifests }) => ({
      type: 'library',
      'bom-ref': ref,
      name: dep.name,
      version: dep.version,
      purl: ref,
      scope: dep.dev ? 'excluded' : 'required',
      ...(licenseEntry(dep.license) ? { licenses: licenseEntry(dep.license) } : {}),
      properties: [
        { name: 'argus:direct', value: String(dep.direct) },
        ...[...manifests].map((m) => ({ name: 'argus:manifest', value: m })),
      ],
    })),
    vulnerabilities: [...vulnerabilities.values()],
  };
}
