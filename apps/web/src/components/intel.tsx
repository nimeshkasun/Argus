import { type AdvisoryInput, ECOSYSTEM_LABELS, ECOSYSTEMS, type Ecosystem, type Severity, SEVERITIES } from '@argus/shared';
import { Field, Input, Select } from './ui';

export type AdvisoryForm = Omit<AdvisoryInput, 'cveIds' | 'references' | 'cvssScore' | 'fixedVersion'> & { cveIds: string; references: string; cvssScore: string; fixedVersion: string };

export const emptyAdvisory: AdvisoryForm = { ecosystem: 'npm', packageName: '', affectedRange: '', fixedVersion: '', severity: 'high', cvssScore: '', cveIds: '', title: '', summary: '', references: '' };

export function toAdvisoryForm(a: AdvisoryInput): AdvisoryForm {
  return { ...a, fixedVersion: a.fixedVersion ?? '', cvssScore: a.cvssScore?.toString() ?? '', cveIds: a.cveIds.join(', '), references: a.references.join('\n') };
}

const list = (s: string, sep: RegExp) =>
  s
    .split(sep)
    .map((x) => x.trim())
    .filter(Boolean);

export function fromAdvisoryForm(f: AdvisoryForm): AdvisoryInput {
  return {
    ...f,
    packageName: f.packageName.trim(),
    affectedRange: f.affectedRange.trim(),
    fixedVersion: f.fixedVersion.trim() || null,
    cvssScore: f.cvssScore.trim() === '' ? null : Number(f.cvssScore),
    cveIds: list(f.cveIds, /[,\s]+/).map((c) => c.toUpperCase()),
    references: list(f.references, /\s+/),
  };
}

/** Fields of an advisory, shared by manual entry and the review of AI-extracted proposals. */
export function AdvisoryFields({ value, onChange, idPrefix }: { value: AdvisoryForm; onChange(v: AdvisoryForm): void; idPrefix: string }) {
  const set = (patch: Partial<AdvisoryForm>) => onChange({ ...value, ...patch });
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <Field label="Title">{(id) => <Input id={`${idPrefix}-${id}`} value={value.title} onChange={(e) => set({ title: e.target.value })} required minLength={3} />}</Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Ecosystem">
          {(id) => (
            <Select id={`${idPrefix}-${id}`} value={value.ecosystem} onChange={(e) => set({ ecosystem: e.target.value as Ecosystem })}>
              {ECOSYSTEMS.map((e) => (
                <option key={e} value={e}>
                  {ECOSYSTEM_LABELS[e]}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Severity">
          {(id) => (
            <Select id={`${idPrefix}-${id}`} value={value.severity} onChange={(e) => set({ severity: e.target.value as Severity })}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </Select>
          )}
        </Field>
      </div>
      <Field label="Package">{(id) => <Input id={`${idPrefix}-${id}`} value={value.packageName} onChange={(e) => set({ packageName: e.target.value })} required placeholder="e.g. lodash or Newtonsoft.Json" />}</Field>
      <Field label="Affected versions" hint='npm-style range, e.g. "<4.17.21" or ">=2.0.0 <2.3.1".'>
        {(id) => <Input id={`${idPrefix}-${id}`} value={value.affectedRange} onChange={(e) => set({ affectedRange: e.target.value })} required className="font-mono" />}
      </Field>
      <Field label="Fixed in (optional)">{(id) => <Input id={`${idPrefix}-${id}`} value={value.fixedVersion} onChange={(e) => set({ fixedVersion: e.target.value })} className="font-mono" />}</Field>
      <Field label="CVSS score (optional)">{(id) => <Input id={`${idPrefix}-${id}`} type="number" min={0} max={10} step="0.1" value={value.cvssScore} onChange={(e) => set({ cvssScore: e.target.value })} />}</Field>
      <Field label="CVE ids (optional)">{(id) => <Input id={`${idPrefix}-${id}`} value={value.cveIds} onChange={(e) => set({ cveIds: e.target.value })} placeholder="CVE-2026-12345" />}</Field>
      <Field label="Reference URLs (optional)">{(id) => <Input id={`${idPrefix}-${id}`} value={value.references} onChange={(e) => set({ references: e.target.value })} placeholder="https://…" />}</Field>
      <div className="sm:col-span-2">
        <Field label="Summary">
          {(id) => (
            <textarea
              id={`${idPrefix}-${id}`}
              rows={3}
              maxLength={4000}
              value={value.summary}
              onChange={(e) => set({ summary: e.target.value })}
              className="block w-full rounded-md border-0 bg-white px-3 py-2 text-sm shadow-xs ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-900 dark:ring-slate-700"
            />
          )}
        </Field>
      </div>
    </div>
  );
}
