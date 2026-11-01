import { API_TOKEN_LIFETIMES_DAYS, type ApiTokenCreatedDto, type ApiTokenDto, CI_PR_SCAN_SCOPES, type Permission, READ_ONLY_SCOPES } from '@argus/shared';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRound, Plus } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { toast } from 'sonner';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { formatDate, formatDateTime, formatRelative } from '../lib/utils';
import { SecretReveal } from './SecretReveal';
import { Badge, Button, Card, CardHeader, Checkbox, ErrorAlert, Field, Input, Modal, Select, Table } from './ui';

function status(t: ApiTokenDto) {
  if (t.revokedAt) return <Badge>Revoked</Badge>;
  if (new Date(t.expiresAt) <= new Date()) return <Badge tone="amber">Expired</Badge>;
  return <Badge tone="green">Active</Badge>;
}

function CreateTokenModal({ onClose }: { onClose(): void }) {
  const qc = useQueryClient();
  const { me } = useAuth();
  const held = (me?.permissions ?? []) as Permission[];
  const [name, setName] = useState('');
  const [days, setDays] = useState(90);
  const [scopes, setScopes] = useState<Permission[]>(READ_ONLY_SCOPES.filter((s) => held.includes(s)));
  const [created, setCreated] = useState<ApiTokenCreatedDto | null>(null);
  const create = useMutation({
    mutationFn: () => api<ApiTokenCreatedDto>('/me/tokens', { method: 'POST', body: { name, scopes, expiresInDays: days } }),
    onSuccess: (t) => {
      setCreated(t);
      void qc.invalidateQueries({ queryKey: ['me', 'tokens'] });
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate();
  };

  if (created) {
    return (
      <Modal open onClose={onClose} title="Token created" description="Copy it now. It is shown only once and cannot be recovered." footer={<Button onClick={onClose}>Done</Button>}>
        <div className="space-y-3 text-sm">
          <SecretReveal value={created.token} />
          <p className="text-slate-500">
            Send it as <code className="rounded bg-slate-100 px-1 dark:bg-slate-800">Authorization: Bearer &lt;token&gt;</code>. It expires {formatDateTime(created.expiresAt)}.
          </p>
        </div>
      </Modal>
    );
  }
  return (
    <Modal
      open
      wide
      onClose={onClose}
      title="New API token"
      description="For CI pipelines and scripts. A token can only use the permissions you choose here, and never more than your role allows."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="token-form" loading={create.isPending} disabled={!scopes.length}>
            Create token
          </Button>
        </>
      }
    >
      <form id="token-form" onSubmit={submit} className="space-y-4">
        <ErrorAlert error={create.error} />
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name">{(id) => <Input id={id} value={name} onChange={(e) => setName(e.target.value)} required minLength={2} placeholder="e.g. GitHub Actions" />}</Field>
          <Field label="Expires after">
            {(id) => (
              <Select id={id} value={days} onChange={(e) => setDays(Number(e.target.value))}>
                {API_TOKEN_LIFETIMES_DAYS.map((d) => (
                  <option key={d} value={d}>
                    {d} days
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        <div>
          <div className="mb-2 flex items-center justify-between">
            <span className="text-sm font-medium">Scopes</span>
            <div className="flex gap-1">
              <Button type="button" size="sm" variant="ghost" onClick={() => setScopes(READ_ONLY_SCOPES.filter((s) => held.includes(s)))}>
                Read-only preset
              </Button>
              {CI_PR_SCAN_SCOPES.every((s) => held.includes(s)) && (
                <Button type="button" size="sm" variant="ghost" title="Just enough to request pull request scans from a CI pipeline" onClick={() => setScopes([...CI_PR_SCAN_SCOPES])}>
                  CI pull request scans
                </Button>
              )}
            </div>
          </div>
          <div className="grid gap-2 sm:grid-cols-3">
            {held.map((p) => (
              <Checkbox key={p} label={p} checked={scopes.includes(p)} onChange={(e) => setScopes(e.target.checked ? [...scopes, p] : scopes.filter((s) => s !== p))} />
            ))}
          </div>
        </div>
      </form>
    </Modal>
  );
}

/** The signed-in user's tokens (Profile), or every token (administrators). */
export function ApiTokensCard({ all = false }: { all?: boolean }) {
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const key = all ? ['api-tokens'] : ['me', 'tokens'];
  const list = useQuery({ queryKey: key, queryFn: () => api<ApiTokenDto[]>(all ? '/api-tokens' : '/me/tokens') });
  const revoke = useMutation({
    mutationFn: (t: ApiTokenDto) => api(all ? `/api-tokens/${t.id}` : `/me/tokens/${t.id}`, { method: 'DELETE' }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: key });
      toast.success('Token revoked.');
    },
  });
  return (
    <Card className="lg:col-span-2">
      <CardHeader
        title={all ? 'API tokens (all users)' : 'API tokens'}
        description={all ? 'Personal tokens across the installation. Revoke any token that is no longer needed or may have leaked.' : 'Personal tokens for CI and automation. Use Authorization: Bearer <token>.'}
        actions={
          !all && (
            <Button size="sm" icon={<Plus className="size-4" />} onClick={() => setCreating(true)}>
              New token
            </Button>
          )
        }
      />
      <ErrorAlert error={list.error ?? revoke.error} />
      {list.data?.length === 0 ? (
        <div className="flex items-center gap-2 p-5 text-sm text-slate-500">
          <KeyRound className="size-4" /> No tokens.
        </div>
      ) : (
        <Table head={[...(all ? ['Owner'] : []), 'Name', 'Scopes', 'Last used', 'Expires', 'Status', '']}>
          {list.data?.map((t) => (
            <tr key={t.id}>
              {all && <td className="px-4 py-2 text-sm">{t.userName}</td>}
              <td className="px-4 py-2">
                <div className="font-medium">{t.name}</div>
                <div className="font-mono text-xs text-slate-500">{t.prefix}…</div>
              </td>
              <td className="max-w-xs px-4 py-2 text-xs text-slate-600 dark:text-slate-400">{t.scopes.join(', ')}</td>
              <td className="px-4 py-2 text-sm" title={t.lastUsedIp ?? undefined}>
                {t.lastUsedAt ? formatRelative(t.lastUsedAt) : 'Never'}
              </td>
              <td className="px-4 py-2 text-sm whitespace-nowrap" title={formatDateTime(t.expiresAt)}>{formatDate(t.expiresAt)}</td>
              <td className="px-4 py-2">{status(t)}</td>
              <td className="px-4 py-2 text-right">
                {!t.revokedAt && (
                  <Button size="sm" variant="ghost" loading={revoke.isPending && revoke.variables?.id === t.id} onClick={() => confirm(`Revoke "${t.name}"? Anything using it stops working.`) && revoke.mutate(t)}>
                    Revoke
                  </Button>
                )}
              </td>
            </tr>
          ))}
        </Table>
      )}
      {creating && <CreateTokenModal onClose={() => setCreating(false)} />}
    </Card>
  );
}
