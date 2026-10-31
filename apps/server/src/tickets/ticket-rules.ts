import { type Finding } from '@argus/data';
import { ACTIVE_TICKET_STATUSES, type Severity, SEVERITIES, type TicketingSettings, type TicketStatus } from '@argus/shared';

const DAY = 86_400_000;

/** critical = 4 ... info = 0. */
export function severityRank(s: Severity): number {
  return SEVERITIES.length - 1 - SEVERITIES.indexOf(s);
}

export function isActive(status: TicketStatus): boolean {
  return ACTIVE_TICKET_STATUSES.includes(status);
}

export function slaDueAt(from: Date, severity: Severity, settings: TicketingSettings): Date {
  return new Date(from.getTime() + settings.slaDays[severity] * DAY);
}

export type SyncChange = 'auto_resolved' | 'auto_accepted' | 'reopened' | null;

/**
 * What a ticket's status becomes given the state of its findings.
 *
 * - Every finding fixed -> resolved (verified by scan); every remaining finding suppressed -> risk accepted.
 * - Open findings on a risk-accepted / false-positive ticket mean its suppression expired or was removed -> reopened.
 * - Open findings on a resolved / closed ticket reopen it only after a scan: a manual "resolved" waits for
 *   the next scan to verify the fix instead of bouncing back immediately.
 */
export function decideStatus(current: TicketStatus, counts: { open: number; suppressed: number; total: number }, afterScan: boolean): { status: TicketStatus; change: SyncChange } {
  if (counts.open > 0) {
    if (current === 'risk_accepted' || current === 'false_positive') return { status: 'reopened', change: 'reopened' };
    if ((current === 'resolved' || current === 'closed') && afterScan) return { status: 'reopened', change: 'reopened' };
    return { status: current, change: null };
  }
  if (isActive(current) && counts.total > 0) {
    return counts.suppressed > 0 ? { status: 'risk_accepted', change: 'auto_accepted' } : { status: 'resolved', change: 'auto_resolved' };
  }
  return { status: current, change: null };
}

/** The finding that represents a group: highest risk among open ones, else the most recently seen. */
export function leadFinding(findings: Finding[]): Finding {
  const open = findings.filter((f) => f.status === 'open');
  const pool = open.length ? open : findings;
  return [...pool].sort((a, b) => b.riskScore - a.riskScore || b.lastSeenAt.getTime() - a.lastSeenAt.getTime())[0];
}

export function ticketTitle(findings: Finding[]): string {
  const lead = leadFinding(findings);
  if (lead.scanner === 'containers' && typeof lead.details?.image === 'string') {
    const open = findings.filter((f) => f.status === 'open' && f.advisory).length;
    return open ? `Container image ${lead.details.image}: ${open} vulnerabilit${open === 1 ? 'y' : 'ies'}` : `Container image ${lead.details.image}: ${lead.title}`;
  }
  const locations = new Set(findings.map((f) => f.path).filter(Boolean)).size;
  return locations > 1 ? `${lead.title} (+${locations - 1} more location${locations > 2 ? 's' : ''})` : lead.title;
}
