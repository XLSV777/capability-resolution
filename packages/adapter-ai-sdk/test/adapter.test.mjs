import { usedStubs } from './hooks.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockResolver, RESOLVER } from './mock-resolver.mjs';

const { resolveTool, candidateTools, checkCandidateTools, CapabilityDriftError } = await import('../src/index.js');
const { USER_AGENT } = await import('capability-resolver-client');
const opts = { toolCallId: 'call-1', messages: [] }; // ToolExecutionOptions, as the AI SDK passes them

test('resolveTool(): an AI SDK tool with description, a JSON Schema input and execute', () => {
  const t = resolveTool({ resolvers: [RESOLVER], fetch: mockResolver().fetch });
  assert.match(t.description, /does not connect to any server/);
  const schema = t.inputSchema.jsonSchema;
  assert.deepEqual(schema.required, ['need']);
  assert.deepEqual(Object.keys(schema.properties), ['need', 'no_sign_in', 'read_only']);
  assert.equal(typeof t.execute, 'function');
  if (usedStubs.size) console.log('# ran against the documented stub of: ' + [...usedStubs].join(', '));
});

test('execute: verified candidates, the spec named, only the resolver contacted, the library User-Agent sent', async () => {
  const m = mockResolver();
  const out = await resolveTool({ resolvers: [RESOLVER], fetch: m.fetch }).execute({ need: 'send a transactional email', no_sign_in: true }, opts);
  assert.equal(out.resolver, RESOLVER);
  assert.deepEqual(out.candidates.map((c) => [c.url, c.status]), [['https://mail.example.com/mcp', 'ok']]);
  assert.match(out.spec, /^Capability Resolution 0\.3, open specification by 7IT Solutions, CC BY 4\.0/);
  assert.ok(m.calls.every((c) => c.url.startsWith(RESOLVER + '/') && c.ua === USER_AGENT));
});

test('execute fails open: a tampered answer or no resolvers gives an empty list, never an error', async () => {
  const bad = await resolveTool({ resolvers: [RESOLVER], fetch: mockResolver({ tamper: true }).fetch }).execute({ need: 'send a transactional email' }, opts);
  assert.deepEqual([bad.resolver, bad.candidates], [null, []]);
  const none = await resolveTool({ resolvers: [] }).execute({ need: 'send a transactional email' }, opts);
  assert.deepEqual(none.candidates, []);
});

test('0.3.1: with no resolvers given the tool asks the client default (7Maps); resolvers: [] asks nobody', async () => {
  const urls = [];
  const fetch = async (u) => { urls.push(String(u)); throw new Error('offline'); };
  const out = await resolveTool({ fetch }).execute({ need: 'send a transactional email' }, opts);
  assert.deepEqual(out.candidates, []);
  assert.deepEqual(urls, ['https://7it.co.il/.well-known/capability-resolver']);
  urls.length = 0;
  await resolveTool({ resolvers: [], fetch }).execute({ need: 'send a transactional email' }, opts);
  assert.equal(urls.length, 0);
});

test('0.3 fingerprint: candidates carry tfp; candidateTools checks tools/list before handing out tools', async () => {
  const { fingerprintTools } = await import('capability-resolver-client');
  const tools = [{ name: 'send_email', description: 'Send.', inputSchema: { type: 'object', properties: { to: { type: 'string' } } } }, { name: 'status', inputSchema: { type: 'object' }, annotations: { readOnlyHint: true } }];
  const tfp = fingerprintTools({ tools });
  const pages = { undefined: { tools: [tools[1]], nextCursor: 'p2' }, p2: { tools: [{ ...tools[0], description: 'New words.' }] } };
  let handedOut = 0;
  // the AI SDK client shape: listTools({ params: { cursor } })
  const client = (list) => ({ listTools: async ({ params } = {}) => list[params?.cursor], tools: async () => { handedOut++; return { ok: true }; } });
  const load = null;
  const call = (c, cl, o) => candidateTools(c, cl, o);
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
  // a client whose listTools has another shape (the protocol SDK client: listTools({ cursor }))
  const other = { listTools: async (p) => pages[p?.cursor] };
  assert.equal((await checkCandidateTools({ tfp }, other, { listTools: (p) => other.listTools(p) })).status, 'match');
  // without opts, a client of that other shape is read the AI SDK way: page 2 is never reached, so it is not a match
  assert.notEqual((await checkCandidateTools({ tfp }, other)).status, 'match');
});
