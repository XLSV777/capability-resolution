// Capability Resolution 0.3: tool fingerprint test vectors (tfp-vectors.json).
// Three groups:
//   jcs:          JSON texts and their RFC 8785 canonical form (numbers, key order, escapes);
//   fingerprints: tool lists (tools/list results, or all pages of one) with their canonical form and fingerprint,
//                 plus pairs that must give the same or a different fingerprint;
//   tokens:       signed tokens carrying tfp / tfp_at, with the verdict, and drift checks against a tool list.
// The tokens are signed with a throwaway Ed25519 key that exists only while this script runs; its public JWK is
// stored in the file. The canonical forms and fingerprints do not depend on the key.
// Run: node generate-tfp.mjs   (rewrites tfp-vectors.json with a fresh key; the verdicts stay the same)
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { canonicalize, canonicalToolList, fingerprintTools } from '../resolver-js/src/fingerprint.js';

const NOW = Date.parse('2026-11-01T12:00:00Z') / 1000;
const ISS = 'https://resolver.test';
const TYP = 'capability-resolver+jws';

// ---- jcs: RFC 8785 behaviour on JSON texts (the input is parsed with an ordinary JSON parser first)
const jcs = [
  ['numbers-integers', '[0, -0, 1, -1, 9007199254740992, 295147905179352825856]', null],
  ['numbers-exponents', '[1E30, 1e21, 1e20, 4.50, 2e-3, 0.000001, 1e-7, 5e-324, 1.7976931348623157e308]', null],
  ['numbers-fractions', '[333333333.3333333, 0.1, 100.0, -1.5e-10]', null],
  ['key-order-rfc8785', '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}', null],
  ['nested-and-literals', '[56, {"d": true, "10": null, "1": [ ]}, "a\\u000fb", "\\"\\\\\\/\\b\\f\\n\\r\\t"]', null],
].map(([name, json]) => ({ name, json, canonical: canonicalize(JSON.parse(json)) }));

// ---- fingerprints
const mail = { name: 'send_email', title: 'Send email', description: 'Send one transactional email.', inputSchema: { type: 'object', properties: { to: { type: 'string', format: 'email' }, subject: { type: 'string' }, body: { type: 'string' } }, required: ['to', 'subject', 'body'] } };
const status = { name: 'delivery_status', description: 'Was an email delivered?', inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] }, annotations: { readOnlyHint: true, title: 'Delivery status' } };
const lists = { name: 'list_templates', description: 'List templates.', inputSchema: { type: 'object', properties: { limit: { type: 'integer', minimum: 1, maximum: 100 } } }, annotations: { readOnlyHint: true } };
const base = { tools: [mail, status, lists] };
const fp = [];
const addFp = (name, description, input) => fp.push({ name, description, input, canonical: canonicalToolList(input), tfp: fingerprintTools(input) });
addFp('base', 'Three tools; descriptions, titles and the annotation title are not part of the canonical form.', base);
addFp('reordered', 'The same tools in another order.', { tools: [lists, mail, status] });
addFp('description-changed', 'Only descriptions and titles changed.', { tools: [{ ...mail, description: 'Send an email (new wording).', title: 'Email' }, { ...status, description: 'Delivery check.', annotations: { readOnlyHint: true, title: 'Status' } }, lists] });
addFp('paginated', 'The base list served in two pages (nextCursor); pages are concatenated before sorting.', [{ tools: [status], nextCursor: 'p2' }, { tools: [lists, mail] }]);
addFp('schema-changed', 'send_email gained a required field.', { tools: [{ ...mail, inputSchema: { ...mail.inputSchema, properties: { ...mail.inputSchema.properties, from: { type: 'string' } }, required: ['to', 'subject', 'body', 'from'] } }, status, lists] });
addFp('schema-key-order', 'The same schemas with members in another order (JCS sorts them).', { tools: [{ ...mail, inputSchema: { required: ['to', 'subject', 'body'], properties: { body: { type: 'string' }, subject: { type: 'string' }, to: { format: 'email', type: 'string' } }, type: 'object' } }, status, lists] });
addFp('tool-removed', 'list_templates was removed.', { tools: [mail, status] });
addFp('tool-renamed', 'delivery_status was renamed.', { tools: [mail, { ...status, name: 'get_delivery_status' }, lists] });
addFp('read-only-hint-changed', 'delivery_status is no longer marked read-only.', { tools: [mail, { ...status, annotations: { readOnlyHint: false } }, lists] });
addFp('read-only-hint-dropped', 'list_templates lost its readOnlyHint annotation.', { tools: [mail, status, { ...lists, annotations: {} }] });
addFp('empty', 'A server that lists no tools.', { tools: [] });
const pairs = [
  ['base', 'reordered', true], ['base', 'description-changed', true], ['base', 'paginated', true], ['base', 'schema-key-order', true],
  ['base', 'schema-changed', false], ['base', 'tool-removed', false], ['base', 'tool-renamed', false],
  ['base', 'read-only-hint-changed', false], ['base', 'read-only-hint-dropped', false], ['base', 'empty', false],
].map(([a, b, same]) => ({ a, b, same_tfp: same }));
const byName = Object.fromEntries(fp.map((x) => [x.name, x]));
for (const p of pairs) if ((byName[p.a].tfp === byName[p.b].tfp) !== p.same_tfp) throw new Error(`pair ${p.a}/${p.b} broke`);

// ---- signed tokens
const b64u = (x) => Buffer.from(typeof x === 'string' ? x : JSON.stringify(x)).toString('base64url');
const kp = generateKeyPairSync('ed25519');
const { x } = kp.publicKey.export({ format: 'jwk' });
const kid = createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest('base64url');
const jwk = { kty: 'OKP', crv: 'Ed25519', x, kid, use: 'sig', alg: 'EdDSA' };
const jws = (claims) => { const h = b64u({ alg: 'EdDSA', typ: TYP, kid }), p = b64u(claims); return `${h}.${p}.${sign(null, Buffer.from(`${h}.${p}`), kp.privateKey).toString('base64url')}`; };
const SUB = 'test:abcdefghijklmnop';
const cand = (extra = {}) => ({ v: '0.3', iss: ISS, sub: SUB, url: 'https://mail.example.com/mcp', status: 'ok', checked_at: '2026-11-01T10:05:00Z', iat: NOW, exp: NOW + 86400, evidence: { record: `${ISS}/record?id=${SUB}` }, tfp: byName.base.tfp, tfp_at: '2026-11-01T10:05:00Z', ...extra });
const tokens = [];
const addTok = (name, description, token, expect, drift = []) => tokens.push({ name, description, jws: token, now: NOW, iss: ISS, expect, drift });
const good = jws(cand());
const [gh, , gs] = good.split('.');
addTok('valid-with-tfp', 'tfp and tfp_at present and well formed. Drift checks: the same list in any order or paging matches; a changed schema drifts.', good, { valid: true },
  [{ tools: 'base', expect: 'match' }, { tools: 'reordered', expect: 'match' }, { tools: 'paginated', expect: 'match' }, { tools: 'description-changed', expect: 'match' }, { tools: 'schema-changed', expect: 'drift' }, { tools: 'tool-removed', expect: 'drift' }]);
addTok('valid-without-tfp', 'A token without tfp (as in 0.2): valid, and a drift check reports absent.', jws(cand({ tfp: undefined, tfp_at: undefined })), { valid: true }, [{ tools: 'schema-changed', expect: 'absent' }]);
addTok('valid-tfp-at-before-checked-at', 'tfp_at may differ from checked_at (the list was observed earlier than the last liveness check).', jws(cand({ tfp_at: '2026-10-31T22:00:00Z' })), { valid: true });
addTok('invalid-tfp-tampered', 'tfp was swapped after signing.', `${gh}.${b64u(cand({ tfp: byName['schema-changed'].tfp }))}.${gs}`, { valid: false, error: 'bad_signature' });
addTok('invalid-tfp-wrong-prefix', 'tfp uses "sha256:" instead of "sha-256:".', jws(cand({ tfp: byName.base.tfp.replace('sha-256:', 'sha256:') })), { valid: false, error: 'bad_tfp' });
addTok('invalid-tfp-hex', 'tfp is hex, not base64url.', jws(cand({ tfp: 'sha-256:' + 'ab'.repeat(32) })), { valid: false, error: 'bad_tfp' });
addTok('invalid-tfp-padded', 'tfp carries base64 padding.', jws(cand({ tfp: byName.base.tfp + '=' })), { valid: false, error: 'bad_tfp' });
addTok('invalid-tfp-without-tfp-at', 'tfp without tfp_at.', jws(cand({ tfp_at: undefined })), { valid: false, error: 'bad_tfp' });
addTok('invalid-tfp-at-without-tfp', 'tfp_at without tfp.', jws(cand({ tfp: undefined })), { valid: false, error: 'bad_tfp' });
addTok('invalid-tfp-at-after-iat', 'tfp_at is 301 s after iat: a resolver cannot sign a list it has not observed yet.', jws(cand({ tfp_at: new Date((NOW + 301) * 1000).toISOString() })), { valid: false, error: 'bad_tfp' });
addTok('invalid-tfp-at-not-a-date', 'tfp_at is not an RFC 3339 date-time.', jws(cand({ tfp_at: 'yesterday' })), { valid: false, error: 'bad_tfp' });

const out = {
  spec: 'Capability Resolution 0.3 (in development), open specification by 7IT Solutions, CC BY 4.0 (https://7it.co.il/standard/capability-resolution/)',
  note: 'Test vectors only. The key is a throwaway test key; its private half was discarded. Never trust it for anything else.',
  generated: new Date(NOW * 1000).toISOString(),
  how_to_use: 'jcs: canonicalize JSON.parse(json) and compare with canonical. fingerprints: compute the canonical tool list and tfp of input (a tools/list result or an array of pages) and compare; pairs say which inputs share a tfp. tokens: verify jws with keys.test at time now (seconds), expecting issuer iss; expect.valid is normative, expect.error is the reference client name. For each drift entry, compare the token tfp with the fingerprint of fingerprints[tools].input: match, drift, or absent when the token has no tfp.',
  keys: { test: jwk },
  jcs,
  fingerprints: fp,
  pairs,
  tokens,
};
writeFileSync(new URL('./tfp-vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${jcs.length} jcs, ${fp.length} fingerprint, ${pairs.length} pair and ${tokens.length} token vectors`);
