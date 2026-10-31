import { ECOSYSTEM_LABELS, ECOSYSTEMS, type Ecosystem, type FindingDto, type LicenseException, type ScanningSettings } from '@argus/shared';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Trash2 } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { toast } from 'sonner';
import { api } from '../lib/api';
import { Button, ErrorAlert, Field, Input, Modal, Select, Table } from './ui';

const EMPTY: LicenseException = { package: '', ecosystem: null, license: null, reason: '' };

function ExceptionFields({ value, onChange }: { value: LicenseException; onChange(v: LicenseException): void }) {
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <Field label="Package" hint='Exact name, or a prefix ending in "*" (e.g. lightningcss*).'>
        {(id) => <Input id={id} value={value.package} onChange={(e) => onChange({ ...value, package: e.target.value })} required maxLength={214} />}
      </Field>
      <Field label="Ecosystem">
        {(id) => (
          <Select id={id} value={value.ecosystem ?? ''} onChange={(e) => onChange({ ...value, ecosystem: (e.target.value || null) as Ecosystem | null })}>
            <option value="">Any</option>
            {ECOSYSTEMS.map((e) => (
              <option key={e} value={e}>
                {ECOSYSTEM_LABELS[e]}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <Field label="Only under license (optional)" hint="SPDX id, e.g. MPL-2.0. Empty approves the package under any license.">
        {(id) => <Input id={id} value={value.license ?? ''} onChange={(e) => onChange({ ...value, license: e.target.value.trim() || null })} maxLength={100} />}
      </Field>
      <Field label="Reason" hint="Recorded in the audit log with the change.">
        {(id) => <Input id={id} value={value.reason} onChange={(e) => onChange({ ...value, reason: e.target.value })} required minLength={5} maxLength={500} />}
      </Field>
    </div>
  );
}

/** Table of license exceptions with add and remove, for the scanning settings form. */
export function LicenseExceptionsEditor({ value, onChange, disabled }: { value: LicenseException[]; onChange(v: LicenseException[]): void; disabled?: boolean }) {
  const [draft, setDraft] = useState<LicenseException | null>(null);
  return (
    <div className="space-y-3">
      {value.length > 0 && (
        <Table head={['Package', 'Ecosystem', 'License', 'Reason', '']}>
          {value.map((e, i) => (
            <tr key={`${e.package}-${e.ecosystem}-${e.license}-${i}`}>
              <td className="px-4 py-2 font-mono text-xs">{e.package}</td>
              <td className="px-4 py-2 text-sm">{e.ecosystem ? ECOSYSTEM_LABELS[e.ecosystem] : 'Any'}</td>
              <td className="px-4 py-2 text-sm">{e.license ?? 'Any'}</td>
              <td className="px-4 py-2 text-sm text-slate-600 dark:text-slate-300">{e.reason}</td>
              <td className="px-4 py-2 text-right">
                {!disabled && <Button type="button" variant="ghost" size="sm" aria-label={`Remove exception for ${e.package}`} icon={<Trash2 className="size-4" />} onClick={() => onChange(value.filter((_, j) => j !== i))} />}
              </td>
            </tr>
          ))}
        </Table>
      )}
      {draft ? (
        <div className="space-y-3 rounded-md p-4 ring-1 ring-slate-200 dark:ring-slate-700">
          <ExceptionFields value={draft} onChange={setDraft} />
          <div className="flex gap-2">
            <Button
              type="button"
              size="sm"
              disabled={!draft.package.trim() || draft.reason.trim().length < 5}
              onClick={() => {
                onChange([...value, { ...draft, package: draft.package.trim(), reason: draft.reason.trim() }]);
                setDraft(null);
              }}
            >
              Add exception
            </Button>
            <Button type="button" size="sm" variant="secondary" onClick={() => setDraft(null)}>
              Cancel
            </Button>
          </div>
        </div>
      ) : (
        !disabled && (
          <Button type="button" size="sm" variant="secondary" icon={<Plus className="size-4" />} onClick={() => setDraft(EMPTY)}>
            Add exception
          </Button>
        )
      )}
    </div>
  );
}

/** Approves a license finding's package from the finding itself, by adding an exception to the scanning settings. */
export function ApproveLicenseModal({ finding, onClose }: { finding: FindingDto; onClose(): void }) {
  const qc = useQueryClient();
  const offending = Array.isArray(finding.details?.offending) ? (finding.details.offending as string[]) : [];
  const [value, setValue] = useState<LicenseException>({ package: finding.package?.name ?? '', ecosystem: finding.package?.ecosystem ?? null, license: offending[0] ?? null, reason: '' });
  const save = useMutation({
    mutationFn: async () => {
      // Read the current settings just before writing, so a concurrent change is not lost.
      const current = await api<ScanningSettings>('/settings/scanning');
      return api<ScanningSettings>('/settings/scanning', { method: 'PUT', body: { ...current, licenseExceptions: [...current.licenseExceptions, value] } });
    },
    onSuccess: (data) => {
      qc.setQueryData(['settings', 'scanning'], data);
      toast.success(`${value.package} approved. Its license findings close at the next scan.`);
      onClose();
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate();
  };
  return (
    <Modal
      open
      onClose={onClose}
      title="Approve license"
      description="Adds an exception to the license policy for every repository. The package is no longer flagged from the next scan, and its tickets resolve then."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="approve-license-form" loading={save.isPending}>
            Approve
          </Button>
        </>
      }
    >
      <form id="approve-license-form" onSubmit={submit} className="space-y-4">
        <ErrorAlert error={save.error} />
        <ExceptionFields value={value} onChange={setValue} />
      </form>
    </Modal>
  );
}
