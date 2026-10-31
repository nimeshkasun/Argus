import { type DependencyDto, ECOSYSTEM_LABELS, type Paged } from '@argus/shared';
import { useQuery } from '@tanstack/react-query';
import { Download, Package, Search } from 'lucide-react';
import { useState } from 'react';
import { api } from '../lib/api';
import { Badge, Button, CenteredSpinner, Checkbox, EmptyState, ErrorAlert, Input, Pagination, Table } from './ui';

const PAGE_SIZE = 50;

/** The repository's dependency inventory from its latest successful scan, with SBOM download. */
export function DependenciesTable({ repoId }: { repoId: string }) {
  const [search, setSearch] = useState('');
  const [vulnerableOnly, setVulnerableOnly] = useState(false);
  const [page, setPage] = useState(1);
  const query = useQuery({
    queryKey: ['repo', repoId, 'dependencies', { search, vulnerableOnly, page }],
    queryFn: () => api<Paged<DependencyDto>>(`/repos/${repoId}/dependencies`, { query: { search, vulnerableOnly: vulnerableOnly ? 'true' : undefined, page, pageSize: PAGE_SIZE } }),
    placeholderData: (prev) => prev,
  });

  return (
    <>
      <div className="flex flex-wrap items-center gap-3 border-b border-slate-200 p-4 dark:border-slate-800">
        <div className="relative min-w-56 flex-1">
          <Search className="pointer-events-none absolute top-2.5 left-3 size-4 text-slate-400" />
          <Input
            placeholder="Search packages"
            className="pl-9"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
          />
        </div>
        <Checkbox label="Vulnerable only" checked={vulnerableOnly} onChange={(e) => (setVulnerableOnly(e.target.checked), setPage(1))} />
        <a href={`/api/v1/repos/${repoId}/sbom`} download>
          <Button variant="secondary" size="sm" icon={<Download className="size-4" />}>
            SBOM (CycloneDX)
          </Button>
        </a>
      </div>
      <ErrorAlert error={query.error} />
      {query.isLoading ? (
        <CenteredSpinner />
      ) : !query.data?.items.length ? (
        <EmptyState icon={<Package className="size-5" />} title="No dependencies" description="No npm or NuGet packages were found in the latest scan, or nothing matches the filter." />
      ) : (
        <>
          <Table head={['Package', 'Version', 'Latest', 'License', 'Manifest', '']}>
            {query.data.items.map((d) => (
              <tr key={`${d.manifestPath}-${d.ecosystem}-${d.name}-${d.version}`}>
                <td className="px-4 py-2.5">
                  <div className="font-medium">{d.name}</div>
                  <div className="text-xs text-slate-500">
                    {ECOSYSTEM_LABELS[d.ecosystem]} · {d.direct ? 'direct' : 'transitive'}
                    {d.dev && ' · dev'}
                  </div>
                </td>
                <td className="px-4 py-2.5 font-mono text-xs">{d.version}</td>
                <td className="px-4 py-2.5 font-mono text-xs text-slate-500">{d.latestVersion ?? '—'}</td>
                <td className="px-4 py-2.5 text-xs">{d.license ?? <span className="text-slate-400">unknown</span>}</td>
                <td className="px-4 py-2.5 font-mono text-xs text-slate-500">{d.manifestPath}</td>
                <td className="px-4 py-2.5">
                  <div className="flex flex-wrap gap-1">
                    {d.vulnerabilities > 0 && <Badge tone="red">{d.vulnerabilities} vulnerabilit{d.vulnerabilities === 1 ? 'y' : 'ies'}</Badge>}
                    {d.deprecated && <Badge tone="amber">Deprecated</Badge>}
                  </div>
                </td>
              </tr>
            ))}
          </Table>
          <Pagination page={page} pageSize={PAGE_SIZE} total={query.data.total} onPage={setPage} />
        </>
      )}
    </>
  );
}
