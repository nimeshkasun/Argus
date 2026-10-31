import { describe, expect, it } from 'vitest';
import { groupKeyFor } from '../../src/scanning/group-key';
import { composeImages, dockerfileImages, manifestImages } from '../../src/scanning/image-refs';
import { codeFindings, type OpengrepResult, rulePrefixOf, ruleTitle } from '../../src/scanning/scanners/code';
import { imageFindings, type TrivyImageReport } from '../../src/scanning/scanners/containers';
import { iacFindings, type TrivyConfigReport } from '../../src/scanning/scanners/iac';

const opengrep = (over: Partial<OpengrepResult> & { meta?: NonNullable<OpengrepResult['extra']['metadata']>; lines?: string }): OpengrepResult => ({
  check_id: 'opt.argus.rules.opengrep.python.lang.security.deserialization.avoid-pickle',
  path: 'app/main.py',
  start: { line: 4 },
  end: { line: 4 },
  extra: {
    message: 'Avoid using `pickle`, which is known to lead to code execution vulnerabilities.',
    severity: 'WARNING',
    lines: over.lines ?? '    return pickle.loads(data)',
    metadata: over.meta ?? { category: 'security', cwe: ['CWE-502: Deserialization of Untrusted Data'], owasp: ['A08:2021 - Software and Data Integrity Failures'], confidence: 'LOW', likelihood: 'LOW', impact: 'MEDIUM', references: ['https://docs.python.org/3/library/pickle.html'] },
  },
  ...over,
});

describe('code analysis (Opengrep)', () => {
  const allowed = new Set(['app/main.py', 'test/test_main.py']);
  const prefix = 'opt.argus.rules.opengrep.';

  it('turns security results into findings without storing the matched code', () => {
    const [f] = codeFindings([opengrep({})], { rulePrefix: prefix, allowed });
    expect(f).toMatchObject({
      ruleId: 'python.lang.security.deserialization.avoid-pickle',
      title: 'Avoid pickle in app/main.py',
      path: 'app/main.py',
      line: 4,
      details: { cwe: 'CWE-502: Deserialization of Untrusted Data', impact: 'MEDIUM', confidence: 'LOW', tool: 'opengrep' },
      risk: { base: 35, baseLabel: 'Code weakness: medium impact, low confidence', testPath: false },
    });
    expect(JSON.stringify(f)).not.toContain('pickle.loads(data)');
  });

  it('keeps only security rules from allowed files, and tells repeated identical matches apart', () => {
    const results = [
      opengrep({}),
      opengrep({ path: './app/main.py', start: { line: 9 }, end: { line: 9 } }),
      opengrep({ check_id: `${prefix}python.lang.correctness.unchecked-subprocess-call`, meta: { category: 'correctness' } }),
      opengrep({ path: 'vendor/lib.py' }),
      opengrep({ path: 'test/test_main.py', check_id: 'my-org.no-eval', meta: {}, lines: 'eval(x)' }),
    ];
    const out = codeFindings(results, { rulePrefix: prefix, allowed });
    expect(out.map((f) => `${f.ruleId}@${f.path}:${f.line}`)).toEqual(['python.lang.security.deserialization.avoid-pickle@app/main.py:4', 'python.lang.security.deserialization.avoid-pickle@app/main.py:9', 'my-org.no-eval@test/test_main.py:4']);
    expect(out[0].identity).not.toEqual(out[1].identity);
    // Identity never uses line numbers, which shift as code changes around the finding.
    const moved = codeFindings([opengrep({ start: { line: 40 }, end: { line: 40 } })], { rulePrefix: prefix, allowed });
    expect(moved[0].identity).toEqual(out[0].identity);
    expect(out[2].risk).toMatchObject({ base: 50, testPath: true });
  });

  it('derives rule prefixes and readable titles', () => {
    expect(rulePrefixOf('/opt/argus/rules/opengrep')).toBe(prefix);
    expect(ruleTitle('javascript.express.security.audit.xss.direct-response-write')).toBe('Direct response write');
  });
});

describe('infrastructure as code (Trivy config)', () => {
  const report: TrivyConfigReport = {
    Results: [
      {
        Target: 'Dockerfile',
        Type: 'dockerfile',
        Misconfigurations: [
          { ID: 'DS-0002', Title: "Image user should not be 'root'", Message: 'Specify at least 1 USER command', Resolution: "Add 'USER <non root user name>'", Severity: 'HIGH', PrimaryURL: 'https://avd.aquasec.com/misconfig/ds-0002', Status: 'FAIL', CauseMetadata: { Provider: 'Dockerfile', Service: 'general' } },
          { ID: 'DS-0005', Title: 'ADD instead of COPY', Severity: 'LOW', Status: 'FAIL', CauseMetadata: { StartLine: 2 } },
          { ID: 'DS-0001', Title: 'Passed check', Severity: 'MEDIUM', Status: 'PASS' },
        ],
      },
      {
        Target: 'infra/main.tf',
        Type: 'terraform',
        Misconfigurations: [
          { ID: 'AWS-0107', Title: 'An ingress security group rule allows traffic from /0.', Severity: 'CRITICAL', Resolution: 'Set a more restrictive cidr range', Status: 'FAIL', CauseMetadata: { Resource: 'aws_security_group.sg', Provider: 'AWS', Service: 'ec2', StartLine: 10 } },
          { ID: 'AWS-0107', Title: 'An ingress security group rule allows traffic from /0.', Severity: 'CRITICAL', Status: 'FAIL', CauseMetadata: { Resource: 'aws_security_group.sg', StartLine: 10 } },
        ],
      },
      { Target: 'ignored/main.tf', Type: 'terraform', Misconfigurations: [{ ID: 'AWS-0001', Severity: 'HIGH', Status: 'FAIL' }] },
    ],
  };

  it('reports failed checks once per file and resource', () => {
    const out = iacFindings(report, new Set(['Dockerfile', 'infra/main.tf']));
    expect(out.map((f) => `${f.ruleId}@${f.path}:${f.line ?? '-'}`)).toEqual(['DS-0002@Dockerfile:-', 'DS-0005@Dockerfile:2', 'AWS-0107@infra/main.tf:10']);
    expect(out[2]).toMatchObject({ title: 'An ingress security group rule allows traffic from /0 in infra/main.tf', remediation: 'Set a more restrictive cidr range', details: { kind: 'Terraform', resource: 'aws_security_group.sg', provider: 'AWS' }, risk: { base: 90 } });
    expect(out[0].risk).toMatchObject({ base: 70, baseLabel: 'Misconfiguration: high severity' });
    expect(out[1].risk.base).toBe(10);
  });
});

describe('container images', () => {
  it('finds base images in Dockerfiles, resolving global ARG defaults and skipping build stages', () => {
    const dockerfile = [
      'ARG NODE_IMAGE=node:24-bookworm-slim',
      'ARG GO="golang:1.27"',
      'FROM ${NODE_IMAGE} AS build',
      'RUN npm ci',
      'FROM --platform=linux/amd64 $GO AS tools',
      'FROM build AS test',
      'FROM scratch',
      'FROM ${UNSET} AS x',
      'FROM node AS node',
      'FROM gcr.io/distroless/nodejs24-debian12@sha256:' + 'a'.repeat(64),
    ].join('\n');
    expect(dockerfileImages(dockerfile, 'Dockerfile').map((r) => `${r.image}:${r.line}`)).toEqual(['node:24-bookworm-slim:3', 'golang:1.27:5', 'node:9', `gcr.io/distroless/nodejs24-debian12@sha256:${'a'.repeat(64)}:10`]);
  });

  it('finds Compose service images and Kubernetes container images', () => {
    const compose = 'services:\n  db:\n    image: postgres:16\n  app:\n    build: .\n  cache:\n    image: ${REDIS_IMAGE:-redis:7-alpine}\n  other:\n    image: ${UNSET}\n';
    expect(composeImages(compose, 'docker-compose.yml').map((r) => r.image)).toEqual(['postgres:16', 'redis:7-alpine']);
    const k8s = 'apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      initContainers:\n        - name: init\n          image: busybox:1.36\n      containers:\n        - name: web\n          image: nginx:1.19\n---\napiVersion: v1\nkind: ConfigMap\ndata:\n  image: not-a-container\n';
    expect(manifestImages(k8s, 'k8s/deploy.yaml').map((r) => `${r.image}:${r.line}`)).toEqual(['busybox:1.36:8', 'nginx:1.19:11']);
    expect(manifestImages('image: {{ .Values.image }}\nkind: Pod\napiVersion: v1\n', 'chart/templates/pod.yaml')).toEqual([]);
  });

  const report: TrivyImageReport = {
    Metadata: { OS: { Family: 'alpine', Name: '3.18.0', EOSL: true }, RepoDigests: ['alpine@sha256:02bb'] },
    Results: [
      {
        Target: 'alpine:3.18.0 (alpine 3.18.0)',
        Class: 'os-pkgs',
        Type: 'alpine',
        Vulnerabilities: [
          { VulnerabilityID: 'CVE-2022-48174', PkgName: 'busybox', InstalledVersion: '1.36.0-r9', FixedVersion: '1.36.1-r1', Title: 'busybox: stack overflow in ash.c', Severity: 'CRITICAL', PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2022-48174', CVSS: { nvd: { V3Score: 9.8, V3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } } },
          { VulnerabilityID: 'CVE-2023-0001', PkgName: 'libcrypto3', InstalledVersion: '3.1.0-r4', Severity: 'HIGH' },
        ],
      },
    ],
  };

  it('turns Trivy image results into findings with KEV and EPSS, plus end-of-life OS', () => {
    const out = imageFindings(report, { image: 'alpine:3.18.0', path: 'Dockerfile', line: 1 }, { kev: new Set(['CVE-2022-48174']), epss: new Map([['CVE-2022-48174', 0.2]]) });
    expect(out.map((f) => f.ruleId)).toEqual(['CVE-2022-48174', 'CVE-2023-0001', 'image-os-end-of-life']);
    expect(out[0]).toMatchObject({
      title: 'busybox@1.36.0-r9 in alpine:3.18.0: busybox: stack overflow in ash.c',
      path: 'Dockerfile',
      advisory: { id: 'CVE-2022-48174', cvssScore: 9.8, kev: true, epss: 0.2 },
      details: { image: 'alpine:3.18.0', os: 'alpine 3.18.0', package: 'busybox', fixedVersion: '1.36.1-r1', digest: 'sha256:02bb' },
      risk: { base: 98, kev: true, epss: 0.2 },
    });
    expect(out[1].risk).toMatchObject({ base: 70, baseLabel: 'high (Trivy)' });
    expect(out[1].remediation).toMatch(/No fixed version/);
    // Every vulnerability of an image is one ticket: they are fixed together by moving to a patched image.
    const keys = new Set(out.map((f) => groupKeyFor({ scanner: 'containers', ruleId: f.ruleId, path: f.path, package: f.package, secret: f.secret, details: f.details })));
    expect([...keys]).toEqual(['containers|alpine:3.18.0']);
  });
});
