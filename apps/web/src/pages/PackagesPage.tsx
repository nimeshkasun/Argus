import { ECOSYSTEM_LABELS, ECOSYSTEMS, type Ecosystem, type PackageUsageDto, type Paged } from '@argus/shared';
import { useQuery } from '@tanstack/react-query';
import { PackageSearch } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { Link } from 'react-router';
import { Badge, Button, Card, CenteredSpinner, EmptyState, ErrorAlert, Field, Input, PageHeader, Pagination, Select, Table } from '../components/ui';
import { api } from '../lib/api';

const PAGE_SIZE = 50;

export function PackagesPage() {
  const [form, setForm] = useState({ name: '', ecosystem: '' as Ecosystem | '', version: '' });
  const [submitted, setSubmitted] = useState<typeof form | null>(null);
  const [page, setPage] = useState(1);
  const query = useQuery({
    queryKey: ['packages', submitted, page],
    queryFn: () => api<Paged<PackageUsageDto>>('/packages/search', { query: { ...submitted, page, pageSize: PAGE_SIZE } }),
    enabled: !!submitted?.name,
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setPage(1);
    setSubmitted({ ...form });
  };

  return (
    <>
      <PageHeader title="Package search" description="Find every repository that uses a package — for example to answer “are we affected?” when a new vulnerability is announced." />
      <Card className="mb-6 p-5">
        <form onSubmit={submit} className="grid items-end gap-4 sm:grid-cols-[2fr_1fr_1fr_auto]">
          <Field label="Package name">{(id) => <Input id={id} placeholder="e.g. lodash, requests or org.apache.logging.log4j:log4j-core" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />}</Field>
          <Field label="Ecosystem">
            {(id) => (
              <Select id={id} value={form.ecosystem} onChange={(e) => setForm({ ...form, ecosystem: e.target.value as Ecosystem | '' })}>
                <option value="">Any</option>
                {ECOSYSTEMS.map((e) => (
                  <option key={e} value={e}>
                    {ECOSYSTEM_LABELS[e]}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Version range (optional)">{(id) => <Input id={id} placeholder="e.g. <4.17.21" value={form.version} onChange={(e) => setForm({ ...form, version: e.target.value })} />}</Field>
          <Button type="submit">Search</Button>
        </form>
      </Card>
      {submitted && (
        <Card>
          <ErrorAlert error={query.error} />
          {query.isLoading ? (
            <CenteredSpinner />
          ) : !query.data?.items.length ? (
            <EmptyState icon={<PackageSearch className="size-5" />} title="Not found" description="No repository you can see uses this package (in the last successful scan)." />
          ) : (
            <>
              <Table head={['Repository', 'Version', 'Manifest', 'Usage']}>
                {query.data.items.map((u) => (
                  <tr key={`${u.repoId}-${u.manifestPath}-${u.version}`}>
                    <td className="px-4 py-2.5">
                      <Link to={`/repositories/${u.repoId}`} className="font-medium hover:text-indigo-600 dark:hover:text-indigo-400">
                        {u.repoFullName}
                      </Link>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs">
                      {u.name}@{u.version}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-slate-500">{u.manifestPath}</td>
                    <td className="px-4 py-2.5">
                      <div className="flex gap-1">
                        <Badge tone={u.direct ? 'indigo' : 'slate'}>{u.direct ? 'Direct' : 'Transitive'}</Badge>
                        {u.dev && <Badge>Dev</Badge>}
                      </div>
                    </td>
                  </tr>
                ))}
              </Table>
              <Pagination page={page} pageSize={PAGE_SIZE} total={query.data.total} onPage={setPage} />
            </>
          )}
        </Card>
      )}
    </>
  );
}
