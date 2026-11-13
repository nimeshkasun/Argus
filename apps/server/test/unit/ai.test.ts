import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { REMEDIATION_OUTPUT } from '../../src/ai/output-schemas';
import { AiOutputError, createAiClient } from '../../src/ai/providers';
import { capText, describeSecret, redactForPrompt } from '../../src/ai/redaction';
import { IntegrationError } from '../../src/integrations/outbound';
import { startMockAi } from '../e2e/mock-ai';

// Assembled at runtime so the fake credential never appears as a literal that secret scanners flag.
const AWS = ['AKIA', 'Z7Q2XVBN4KDF3HJW'].join('');
const GH = `ghp_${'aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6'}`;

describe('prompt redaction', () => {
  it('removes known values, detector matches, credential assignments, URL credentials and private keys', () => {
    const input = [
      `const aws = "${AWS}";`,
      `token: ${GH}`,
      'DB_PASSWORD=Sup3rS3cretValue!',
      'conn = "Server=db;User Id=sa;Password=Pa55word99;"',
      'remote = https://deploy:hunter2hunter2@git.example.com/repo.git',
      'Authorization: Bearer abc.def.ghi',
      '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx\n-----END RSA PRIVATE KEY-----',
      'custom = my-very-own-secret-value',
    ].join('\n');
    const { text, redactions } = redactForPrompt(input, ['my-very-own-secret-value']);
    for (const secret of [AWS, GH, 'Sup3rS3cretValue!', 'Pa55word99', 'hunter2hunter2', 'abc.def.ghi', 'MIIEowIBAAKCAQEAx', 'my-very-own-secret-value']) expect(text).not.toContain(secret);
    expect(text).toContain('[REDACTED:aws-access-token]');
    expect(text).toContain('[REDACTED:private-key]');
    expect(redactions).toBeGreaterThanOrEqual(8);
  });

  it('removes long random tokens but keeps ordinary code, versions, placeholders and commit SHAs', () => {
    const random = ['q8Zr2LmX9vT4kP7w', 'B1nY6cF3hJ0sD5gA8eR2uI4o'].join('');
    const input = `import _ from 'lodash';\n_.template(userInput); // lodash@4.17.20\npassword = "changeme"\ncommit 3f2a9c1b7d4e6f8a0b2c4d6e8f0a1b3c5d7e9f1a\nkey = ${random}`;
    const { text } = redactForPrompt(input);
    expect(text).not.toContain(random);
    expect(text).toContain("import _ from 'lodash';");
    expect(text).toContain('lodash@4.17.20');
    expect(text).toContain('password = "changeme"');
    expect(text).toContain('3f2a9c1b7d4e6f8a0b2c4d6e8f0a1b3c5d7e9f1a');
  });

  it('describes a secret without revealing it and caps long text', () => {
    const d = describeSecret('AKIAIOSFODNN7EXAMPLE');
    expect(JSON.stringify(d)).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(d).toMatchObject({ length: 20, looksLikePlaceholder: false, containsWords: ['example'] });
    expect(describeSecret('changeme')).toMatchObject({ looksLikePlaceholder: true });
    const capped = capText('x'.repeat(5000), 1000);
    expect(capped.length).toBeLessThanOrEqual(1000);
    expect(capped).toContain('truncated');
  });
});

describe('AI provider clients', () => {
  let mock: Awaited<ReturnType<typeof startMockAi>>;
  beforeAll(async () => {
    mock = await startMockAi({ answer: (kind, call) => (call.body.model === 'bad-json' ? 'not json' : undefined) });
  });
  afterAll(() => mock.close());

  const req = { system: 'sys', prompt: 'fix lodash', schema: REMEDIATION_OUTPUT.schema, schemaName: 'remediation', effort: 'medium' as const };

  it.each([
    ['anthropic', 'claude-opus-5-5', '/ai/anthropic'],
    ['openai', 'gpt-6.1-sol', '/ai/openai'],
    ['gemini', 'gemini-3.8-flash', '/ai/gemini'],
  ] as const)('%s sends a schema-constrained request and reports tokens', async (provider, model, path) => {
    const client = createAiClient(provider, { model, apiKey: 'sk-test-key-123456', baseUrl: `${mock.url}${path}` });
    const res = await client.generate(req);
    expect(REMEDIATION_OUTPUT.validate.parse(JSON.parse(res.text)).fixVersion).toBe('4.17.21');
    expect(res).toMatchObject({ model, inputTokens: 1000, outputTokens: 200 });
    const call = mock.calls.at(-1)!;
    expect(call.provider).toBe(provider);
    expect(call.text).toContain('fix lodash');
    if (provider === 'anthropic') {
      // SDK 1.x sends the key as a bearer token; an explicit key also stops it reading ANTHROPIC_* variables.
      expect(call.headers.authorization).toBe('Bearer sk-test-key-123456');
      expect(call.body).toMatchObject({ output_config: { effort: 'medium', format: { type: 'json_schema' } } });
      // Fallbacks are only requested from the Claude API itself, never through a custom gateway.
      expect(call.body.fallbacks).toBeUndefined();
    }
    if (provider === 'openai') {
      expect(call.headers.authorization).toBe('Bearer sk-test-key-123456');
      expect(call.body).toMatchObject({ response_format: { type: 'json_schema', json_schema: { strict: true } } });
    }
    if (provider === 'gemini') {
      expect(call.headers['x-goog-api-key']).toBe('sk-test-key-123456');
      expect(call.body).toMatchObject({ generationConfig: { responseMimeType: 'application/json' } });
    }
  });

  it('never puts the API key in error messages', async () => {
    const failing = await startMockAi({ status: 401 });
    try {
      for (const [provider, path] of [['anthropic', '/ai/anthropic'], ['openai', '/ai/openai'], ['gemini', '/ai/gemini']] as const) {
        const client = createAiClient(provider, { model: 'm', apiKey: 'sk-live-should-not-leak', baseUrl: `${failing.url}${path}` });
        const err = await client.generate(req).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(IntegrationError);
        expect((err as Error).message).not.toContain('sk-live-should-not-leak');
        expect((err as IntegrationError).status).toBe(401);
      }
    } finally {
      await failing.close();
    }
  });

  it('relay adds /v1, reports the served model and tags the request', async () => {
    const client = createAiClient('relay', { model: 'smart', apiKey: 'rly_test_key_123456', baseUrl: `${mock.url}/ai/relay/` });
    const res = await client.generate(req);
    expect(res).toMatchObject({ model: 'openai/gpt-6.1-sol', inputTokens: 1000, outputTokens: 200 });
    const call = mock.calls.at(-1)!;
    expect(call.provider).toBe('relay');
    expect(call.headers.authorization).toBe('Bearer rly_test_key_123456');
    expect(call.body).toMatchObject({ model: 'smart', relay: { cache: false, tags: ['app:argus'] }, response_format: { type: 'json_schema' } });
  });

  it('relay needs a base URL, and its errors never leak the key', async () => {
    await expect(createAiClient('relay', { model: 'smart', apiKey: 'rly_test_key_123456', baseUrl: null }).generate(req)).rejects.toThrow(/base URL/);
    const failing = await startMockAi({ status: 401 });
    try {
      const err = await createAiClient('relay', { model: 'smart', apiKey: 'rly_live_should_not_leak', baseUrl: `${failing.url}/ai/relay` }).generate(req).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(IntegrationError);
      expect((err as Error).message).not.toContain('rly_live_should_not_leak');
      expect((err as IntegrationError).status).toBe(401);
    } finally {
      await failing.close();
    }
  });

  it('returns raw text so the caller can reject output that is not valid JSON', async () => {
    const client = createAiClient('openai', { model: 'bad-json', apiKey: 'k-12345678', baseUrl: `${mock.url}/ai/openai` });
    const res = await client.generate(req);
    expect(() => JSON.parse(res.text)).toThrow();
    expect(new AiOutputError('x')).toBeInstanceOf(Error);
  });
});
