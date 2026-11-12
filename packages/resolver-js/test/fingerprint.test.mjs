// Tool fingerprint (spec 0.3): JCS, canonical tool list, fingerprint, drift checks and the tfp vectors.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalize, canonicalToolList, fingerprintTools, checkDrift, listAllTools, checkClientDrift, TFP_RE, MAX_TOOL_PAGES, verifyToken } from '../src/index.js';

const file = JSON.parse(readFileSync(new URL('../../test-vectors/tfp-vectors.json', import.meta.url), 'utf8'));
const byName = Object.fromEntries(file.fingerprints.map((f) => [f.name, f]));

test('JCS: numbers follow RFC 8785 (ECMAScript serialization)', () => {
  const cases = [[0, '0'], [-0, '0'], [1e30, '1e+30'], [1e21, '1e+21'], [1e20, '100000000000000000000'], [4.5, '4.5'], [0.002, '0.002'], [0.000001, '0.000001'], [1e-7, '1e-7'], [5e-324, '5e-324'], [1.7976931348623157e308, '1.7976931348623157e+308'], [9007199254740992, '9007199254740992'], [295147905179352825856, '295147905179352830000'], [333333333.3333333, '333333333.3333333'], [-1.5e-10, '-1.5e-10']];
  for (const [n, s] of cases) assert.equal(canonicalize(n), s, String(n));
  for (const bad of [NaN, Infinity, -Infinity, 1n, () => 1, Symbol('x')]) assert.throws(() => canonicalize(bad));
});

test('JCS: members sorted by UTF-16 code units (RFC 8785 section 3.2.3 example), no whitespace, escapes', () => {
  const o = { '€': 'Euro Sign', '\r': 'Carriage Return', 'דּ': 'Hebrew Letter Dalet With Dagesh', 1: 'One', '😀': 'Emoji: Grinning Face', '\u0080': 'Control', 'ö': 'Latin Small Letter O With Diaeresis' };
  assert.equal(canonicalize(o), '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}');
  assert.equal(canonicalize([56, { d: true, 10: null, 1: [] }]), '[56,{"1":[],"10":null,"d":true}]');
  assert.equal(canonicalize('a\u000fb"\\/\b\f\n\r\t '), '"a\\u000fb\\"\\\\/\\b\\f\\n\\r\\t "');
  assert.equal(canonicalize({ a: undefined, b: [undefined] }), '{"b":[null]}');
  const cyc = {}; cyc.self = cyc;
  assert.throws(() => canonicalize(cyc), /cyclic/);
});

test('JCS vectors match', () => {
  for (const v of file.jcs) assert.equal(canonicalize(JSON.parse(v.json)), v.canonical, v.name);
});

test('canonical tool list: name, inputSchema, readOnlyHint only; hand-checked text and hash', () => {
  const expected = '[{"annotations":{"readOnlyHint":true},"inputSchema":{"properties":{"id":{"type":"string"}},"required":["id"],"type":"object"},"name":"delivery_status"},'
    + '{"annotations":{"readOnlyHint":true},"inputSchema":{"properties":{"limit":{"maximum":100,"minimum":1,"type":"integer"}},"type":"object"},"name":"list_templates"},'
    + '{"inputSchema":{"properties":{"body":{"type":"string"},"subject":{"type":"string"},"to":{"format":"email","type":"string"}},"required":["to","subject","body"],"type":"object"},"name":"send_email"}]';
  assert.equal(canonicalToolList(byName.base.input), expected);
  assert.equal(fingerprintTools(byName.base.input), 'sha-256:' + createHash('sha256').update(expected, 'utf8').digest('base64url'));
  assert.match(fingerprintTools(byName.base.input), TFP_RE);
  assert.equal(fingerprintTools({ tools: [] }), 'sha-256:' + createHash('sha256').update('[]').digest('base64url'));
  assert.throws(() => fingerprintTools({ tools: [{ description: 'no name' }] }));
  assert.throws(() => fingerprintTools('nope'));
});

test('fingerprint vectors: canonical form and tfp; pairs same or different', () => {
  for (const f of file.fingerprints) {
    assert.equal(canonicalToolList(f.input), f.canonical, f.name);
    assert.equal(fingerprintTools(f.input), f.tfp, f.name);
  }
  for (const p of file.pairs) assert.equal(byName[p.a].tfp === byName[p.b].tfp, p.same_tfp, `${p.a} / ${p.b}`);
});

test('checkDrift: match, drift, absent, malformed signed value', () => {
  const tfp = byName.base.tfp;
  assert.equal(checkDrift({ tfp }, byName.reordered.input).status, 'match');
  assert.equal(checkDrift({ tfp }, byName.paginated.input).status, 'match');
  const d = checkDrift({ tfp }, byName['schema-changed'].input);
  assert.deepEqual([d.status, d.expected, d.actual], ['drift', tfp, byName['schema-changed'].tfp]);
  assert.equal(checkDrift({ tfp: null }, byName['schema-changed'].input).status, 'absent');
  assert.equal(checkDrift({}, byName['schema-changed'].input).status, 'absent');
  assert.equal(checkDrift({ tfp: 'sha256:x' }, byName.base.input).status, 'drift');
  assert.equal(checkDrift({ tfp }, 'not a list').status, 'drift');
});

test('listAllTools: follows nextCursor; caps pages; checkClientDrift never throws', async () => {
  const pages = { undefined: { tools: [byName.base.input.tools[1]], nextCursor: 'b' }, b: { tools: [byName.base.input.tools[0]], nextCursor: 'c' }, c: { tools: [byName.base.input.tools[2]] } };
  const seen = [];
  const client = { listTools: async (p) => { seen.push(p?.cursor); return pages[p?.cursor]; } };
  const all = await listAllTools(client);
  assert.deepEqual(seen, [undefined, 'b', 'c']);
  assert.equal(fingerprintTools(all), byName.base.tfp);
  assert.equal((await checkClientDrift({ tfp: byName.base.tfp }, client)).status, 'match');
  const endless = { listTools: async () => ({ tools: [], nextCursor: 'again' }) };
  await assert.rejects(listAllTools(endless), /too many/);
  const r = await checkClientDrift({ tfp: byName.base.tfp }, endless);
  assert.equal(r.status, 'drift');
  assert.ok(MAX_TOOL_PAGES >= 10);
  const broken = { listTools: async () => { throw new Error('closed'); } };
  assert.equal((await checkClientDrift({ tfp: byName.base.tfp }, broken)).status, 'drift');
  let called = false;
  assert.equal((await checkClientDrift({ tfp: null }, { listTools: async () => { called = true; return { tools: [] }; } })).status, 'absent');
  assert.equal(called, false, 'no tfp: the client does not need to list tools');
});

test('tfp token vectors: verdicts and drift checks', () => {
  assert.match(file.spec, /^Capability Resolution 0\.3, open specification by 7IT Solutions/);
  assert.ok(!('d' in file.keys.test));
  for (const v of file.tokens) {
    const r = verifyToken(v.jws, [file.keys.test], v.now, { iss: v.iss });
    assert.equal(r.ok, v.expect.valid, v.name);
    if (!v.expect.valid) { assert.equal(r.error, v.expect.error, v.name); continue; }
    for (const d of v.drift) assert.equal(checkDrift(r.payload, byName[d.tools].input).status, d.expect, `${v.name} vs ${d.tools}`);
  }
});
