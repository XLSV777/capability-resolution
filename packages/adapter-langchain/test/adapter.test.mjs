import { usedStubs } from './hooks.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockResolver, RESOLVER } from './mock-resolver.mjs';

const { CapabilityResolverTool } = await import('../src/index.js');
const { Tool } = await import('@langchain/core/tools');
const { USER_AGENT } = await import('capability-resolver-client');

test('CapabilityResolverTool is a LangChain Tool with a name and description', () => {
  const t = new CapabilityResolverTool({ resolvers: [RESOLVER], fetch: mockResolver().fetch });
  assert.ok(t instanceof Tool);
  assert.equal(t.name, 'capability_resolve');
  assert.match(t.description, /does not connect to any server/);
  assert.equal(CapabilityResolverTool.lc_name(), 'CapabilityResolverTool');
  if (usedStubs.size) console.log('# ran against the documented stub of: ' + [...usedStubs].join(', '));
});

test('invoke(string): JSON with verified candidates, constraints applied, only the resolver contacted', async () => {
  const m = mockResolver();
  const t = new CapabilityResolverTool({ resolvers: [RESOLVER], fetch: m.fetch, constraints: { no_sign_in: true } });
  const out = JSON.parse(await t.invoke('send a transactional email'));
  assert.equal(out.resolver, RESOLVER);
  assert.deepEqual(out.candidates.map((c) => c.url), ['https://mail.example.com/mcp']);
  assert.match(out.spec, /^Capability Resolution 0\.2, open draft by 7IT Solutions/);
  assert.ok(m.calls.every((c) => c.url.startsWith(RESOLVER + '/') && c.ua === USER_AGENT));
  const both = JSON.parse(await new CapabilityResolverTool({ resolvers: [RESOLVER], fetch: m.fetch }).invoke({ input: 'send a transactional email' }));
  assert.equal(both.candidates.length, 2);
});

test('fails open: a tampered answer gives an empty list; resolver options do not leak into Tool fields', async () => {
  const t = new CapabilityResolverTool({ resolvers: [RESOLVER], fetch: mockResolver({ tamper: true }).fetch, verbose: false });
  assert.deepEqual(JSON.parse(await t.invoke('send a transactional email')).candidates, []);
  if (t.fields) assert.deepEqual(Object.keys(t.fields), ['verbose']);
});
