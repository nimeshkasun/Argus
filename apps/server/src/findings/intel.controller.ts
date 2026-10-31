import { Controller, Get } from '@nestjs/common';
import { type IntelStatusDto } from '@argus/shared';
import { RequirePermissions } from '../auth/decorators';
import { AppConfig } from '../config/app-config';
import { IntelService } from '../scanning/intel.service';
import { gitleaksVersion } from '../scanning/scanners/secrets';
import { opengrepVersion, trivyVersion } from '../scanning/tools';

const FEEDS: [string, string][] = [
  ['osv', 'OSV.dev vulnerability database (includes GitHub Security Advisories)'],
  ['kev', 'CISA Known Exploited Vulnerabilities'],
  ['epss', 'FIRST EPSS exploit prediction'],
  ['eol', 'endoflife.date release cycles'],
  ['nvd', 'NVD CVE API (CVSS when OSV has none)'],
];

@Controller('intel')
export class IntelController {
  constructor(
    private readonly intel: IntelService,
    private readonly config: AppConfig,
  ) {}

  @Get('status')
  @RequirePermissions('settings:read')
  async status(): Promise<IntelStatusDto> {
    const status = await this.intel.feedStatus(FEEDS.map(([k]) => k));
    const [version, opengrep, trivy] = await Promise.all([gitleaksVersion(this.config.gitleaksPath), opengrepVersion(this.config.opengrepPath), trivyVersion(this.config.trivyPath)]);
    return {
      feeds: FEEDS.map(([key, label]) => {
        const s = status.get(key);
        return { key, label, fetchedAt: s?.fetchedAt ?? null, entries: s?.entries ?? null, error: s?.error ?? null };
      }),
      gitleaks: { available: version !== null, version },
      opengrep: { available: opengrep !== null, version: opengrep, rules: this.config.opengrepRules !== null },
      trivy: { available: trivy !== null, version: trivy },
    };
  }
}
