import { usedStubs } from './hooks.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockResolver, RESOLVER } from './mock-resolver.mjs';

const { resolveTool } = await import('../src/index.js');
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
  assert.match(out.spec, /^Capability Resolution 0\.2, open draft by 7IT Solutions, CC BY 4\.0/);
  assert.ok(m.calls.every((c) => c.url.startsWith(RESOLVER + '/') && c.ua === USER_AGENT));
});

test('execute fails open: a tampered answer or no resolvers gives an empty list, never an error', async () => {
  const bad = await resolveTool({ resolvers: [RESOLVER], fetch: mockResolver({ tamper: true }).fetch }).execute({ need: 'send a transactional email' }, opts);
  assert.deepEqual([bad.resolver, bad.candidates], [null, []]);
  const none = await resolveTool().execute({ need: 'send a transactional email' }, opts);
  assert.deepEqual(none.candidates, []);
});
