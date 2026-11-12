import { usedStubs } from './hooks.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockResolver, RESOLVER } from './mock-resolver.mjs';

const { CapabilityResolverTool, candidateTools, checkCandidateTools, CapabilityDriftError } = await import('../src/index.js');
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
  assert.match(out.spec, /^Capability Resolution 0\.3, open specification by 7IT Solutions/);
  assert.ok(m.calls.every((c) => c.url.startsWith(RESOLVER + '/') && c.ua === USER_AGENT));
  const both = JSON.parse(await new CapabilityResolverTool({ resolvers: [RESOLVER], fetch: m.fetch }).invoke({ input: 'send a transactional email' }));
  assert.equal(both.candidates.length, 2);
});

test('fails open: a tampered answer gives an empty list; resolver options do not leak into Tool fields', async () => {
  const t = new CapabilityResolverTool({ resolvers: [RESOLVER], fetch: mockResolver({ tamper: true }).fetch, verbose: false });
  assert.deepEqual(JSON.parse(await t.invoke('send a transactional email')).candidates, []);
  if (t.fields) assert.deepEqual(Object.keys(t.fields), ['verbose']);
});

test('0.3 fingerprint: candidates carry tfp; candidateTools checks tools/list before handing out tools', async () => {
  const { fingerprintTools } = await import('capability-resolver-client');
  const tools = [{ name: 'send_email', description: 'Send.', inputSchema: { type: 'object', properties: { to: { type: 'string' } } } }, { name: 'status', inputSchema: { type: 'object' }, annotations: { readOnlyHint: true } }];
  const tfp = fingerprintTools({ tools });
  const pages = { undefined: { tools: [tools[1]], nextCursor: 'p2' }, p2: { tools: [{ ...tools[0], description: 'New words.' }] } };
  let handedOut = 0;
  const client = (list) => ({ listTools: async (p) => list[p?.cursor], tools: async () => { handedOut++; return { ok: true }; } });
  const load = async () => { handedOut++; return ['tool']; };
  const call = (c, cl, o) => candidateTools(c, cl, load, o);
  // same tools, paged and reworded: match, tools handed out
  assert.equal((await checkCandidateTools({ tfp }, client(pages))).status, 'match');
  await call({ tfp }, client(pages));
  assert.equal(handedOut, 1);
  // a schema changed: drift, nothing handed out
  const changed = { undefined: { tools: [tools[1], { ...tools[0], inputSchema: { type: 'object' } }] } };
  await assert.rejects(call({ tfp }, client(changed)), (e) => e instanceof CapabilityDriftError && e.result.status === 'drift');
  assert.equal(handedOut, 1);
  // no fingerprint signed: fail open, tools/list is not even needed
  await call({ tfp: null }, { listTools: async () => { throw new Error('not called'); }, tools: async () => { handedOut++; return {}; } });
  assert.equal(handedOut, 2);
  // a client whose listTools has another shape
  const other = { listTools: async ({ params } = {}) => pages[params?.cursor] };
  assert.equal((await checkCandidateTools({ tfp }, other, { listTools: (p) => other.listTools({ params: p }) })).status, 'match');
});
