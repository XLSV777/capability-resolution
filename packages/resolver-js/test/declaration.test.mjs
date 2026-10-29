// Server declaration file (spec section 13): the parser, resolver allow/deny, the optional signature, and
// capability-resolution-check --server against an in-process mock origin. A mock network only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseDeclaration, resolverAllowed, verifyDeclarationSignature, DECLARATION_PATH, DECLARATION_MAX_BYTES } from '../src/index.js';
import { checkServer, formatReport, SERVER_RULES, CHECKER_USER_AGENT } from '../src/check.js';

const O = 'https://example.com';
const NOW = Date.parse('2026-10-29T12:00:00Z');
const MIN = [
  'Conformance: Capability Resolution 0.2',
  'Contact: mailto:tools@example.com',
  'Expires: 2027-04-30T00:00:00Z',
  'Endpoint: https://mail.example.com/mcp',
  'Protocol: mcp',
  'Jobs: send a transactional email',
  'Sign-in: none',
  'Payment: none',
].join('\n') + '\n';
const parse = (t, o = {}) => parseDeclaration(t, { origin: O, now: NOW, ...o });

test('the minimal file parses', () => {
  const d = parse(MIN);
  assert.deepEqual([d.ok, d.errors, d.warnings], [true, [], []]);
  assert.equal(d.version, '0.2');
  assert.deepEqual(d.servers, [{ endpoint: 'https://mail.example.com/mcp', protocol: 'mcp', jobs: ['send a transactional email'], sign_in: 'none', payment: 'none', cards: [] }]);
  assert.deepEqual(d.resolvers, { all: true, none: false, allow: [], deny: [] });
  assert.equal(DECLARATION_PATH, '/.well-known/capabilities.txt');
});

test('field names are case-insensitive; comments, blank lines, CRLF, a BOM and unknown fields are fine', () => {
  const t = '﻿# tools of example.com\r\n\r\n' + MIN.replace('Protocol:', 'PROTOCOL :').replace(/\n/g, '\r\n') + 'X-Note: hello\r\n';
  const d = parse(t);
  assert.equal(d.ok, true, d.errors.join('; '));
  assert.deepEqual(d.unknown, ['X-Note']);
});

test('several servers, each its own group; endpoints are put in canonical form', () => {
  const t = MIN + 'Card: https://mail.example.com/.well-known/mcp/server-card.json\n\nEndpoint: https://WWW.Example.com/search/mcp/\nProtocol: mcp\nJobs: search the docs\nJobs: answer questions about the API\nSign-in: required\nPayment: any\n';
  const d = parse(t);
  assert.equal(d.ok, true, d.errors.join('; '));
  assert.equal(d.servers.length, 2);
  assert.deepEqual(d.servers[0].cards, ['https://mail.example.com/.well-known/mcp/server-card.json']);
  assert.deepEqual([d.servers[1].endpoint, d.servers[1].jobs.length, d.servers[1].sign_in, d.servers[1].payment], ['https://example.com/search/mcp', 2, 'required', 'any']);
});

for (const [name, text, re] of [
  ['no Conformance', MIN.replace(/^Conformance.*\n/m, ''), /Conformance is missing/],
  ['wrong spec name', MIN.replace('Capability Resolution 0.2', 'Something 0.2'), /Conformance must be/],
  ['two Conformance lines', MIN + 'Conformance: Capability Resolution 0.2\n', /more than once/],
  ['no Contact', MIN.replace(/^Contact.*\n/m, ''), /Contact is missing/],
  ['bad Contact', MIN.replace('mailto:tools@example.com', 'tools at example'), /Contact must be/],
  ['no Expires', MIN.replace(/^Expires.*\n/m, ''), /Expires is missing/],
  ['Expires in the past', MIN.replace('2027-04-30', '2026-01-01'), /Expires is in the past/],
  ['Expires not RFC 3339', MIN.replace('2027-04-30T00:00:00Z', 'next year'), /RFC 3339/],
  ['plain-http endpoint', MIN.replace('https://mail', 'http://mail'), /Endpoint must be an https URL/],
  ['endpoint with credentials', MIN.replace('https://mail', 'https://u:p@mail'), /Endpoint must be/],
  ['endpoint on another host', MIN.replace('mail.example.com', 'mail.other.org'), /not on example\.com or a subdomain/],
  ['host that only ends with the name', MIN.replace('mail.example.com', 'badexample.com'), /not on example\.com/],
  ['no Protocol', MIN.replace(/^Protocol.*\n/m, ''), /has no Protocol/],
  ['Protocol not a token', MIN.replace('Protocol: mcp', 'Protocol: Model Context'), /lower-case token/],
  ['no Jobs', MIN.replace(/^Jobs.*\n/m, ''), /has no Jobs/],
  ['Jobs too long', MIN.replace('send a transactional email', 'x'.repeat(201)), /3 to 200/],
  ['bad Sign-in', MIN.replace('Sign-in: none', 'Sign-in: maybe'), /Sign-in must be/],
  ['bad Payment', MIN.replace('Payment: none', 'Payment: free'), /Payment must be none or any/],
  ['server field before Endpoint', 'Protocol: mcp\n' + MIN, /before any Endpoint/],
  ['endpoint listed twice', MIN + 'Endpoint: https://mail.example.com/mcp/\nProtocol: mcp\nJobs: send mail\n', /listed twice/],
  ['bad Resolvers entry', MIN + 'Resolvers: resolver.example\n', /Resolvers entry/],
  ['resolver origin with a path', MIN + 'Resolvers: https://r.example/x\n', /Resolvers entry/],
  ['content after Signature', MIN + 'Signature: a..b\nContact: https://example.com/\n', /after Signature/],
]) {
  test(`invalid: ${name}`, () => {
    const d = parse(text);
    assert.equal(d.ok, false);
    assert.ok(d.errors.some((e) => re.test(e)), `wanted ${re}; got ${JSON.stringify(d.errors)}`);
  });
}

test('size cap and UTF-8', () => {
  assert.match(parse(MIN + '#' + 'x'.repeat(DECLARATION_MAX_BYTES)).errors[0], /larger than/);
  assert.deepEqual(parse(new Uint8Array([0x43, 0xff, 0x0a])).errors, ['not valid UTF-8']);
  assert.equal(parse(new TextEncoder().encode(MIN)).ok, true);
});

test('missing Sign-in or Payment only warns', () => {
  const d = parse(MIN.replace(/^Sign-in.*\n/m, '').replace(/^Payment.*\n/m, ''));
  assert.equal(d.ok, true);
  assert.equal(d.warnings.length, 2);
});

test('Resolvers: allow list, deny, none, and the default', () => {
  const A = 'https://a.example', B = 'https://b.example';
  const ok = (line, who) => resolverAllowed(parse(MIN + (line ? `Resolvers: ${line}\n` : '')), who);
  assert.equal(ok('', A), true, 'no Resolvers line: every resolver');
  assert.equal(ok('*', A), true);
  assert.deepEqual([ok(`${A}`, A), ok(`${A}`, B)], [true, false], 'a list allows only the listed');
  assert.deepEqual([ok(`* -${B}`, A), ok(`*, -${B}`, B)], [true, false], 'a deny wins over *');
  assert.deepEqual([ok(`${B} -${B}`, B)], [false], 'a deny wins over an allow');
  assert.deepEqual([ok('none', A), ok(`none ${A}`, A)], [false, false], 'none denies everyone');
  assert.equal(resolverAllowed(null, A), true, 'no file: no restriction from a file');
  const expired = parse(MIN.replace('2027-04-30', '2026-01-01') + 'Resolvers: none\n');
  assert.deepEqual([expired.ok, resolverAllowed(expired, A)], [false, false], 'a deny holds even in an expired file');
  assert.equal(ok(`HTTPS://A.example`, A), true, 'origins compare in canonical case');
});

// A signed file: the signature covers every byte before the Signature line.
function signed(text, kp, kid, jku = O + '/.well-known/capabilities-keys.json') {
  const h = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'capabilities-txt+jws', kid, jku })).toString('base64url');
  const sig = sign(null, Buffer.from(`${h}.${Buffer.from(text, 'utf8').toString('base64url')}`), kp.privateKey).toString('base64url');
  return `${text}Signature: ${h}..${sig}\n`;
}
const kp = generateKeyPairSync('ed25519');
const { x } = kp.publicKey.export({ format: 'jwk' });
const kid = createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest('base64url');
const JWKS = [{ kty: 'OKP', crv: 'Ed25519', x, kid, alg: 'EdDSA', use: 'sig' }];

test('signature: verifies; any change to the signed text breaks it; a wrong key or header fails', () => {
  const d = parse(signed(MIN, kp, kid));
  assert.equal(d.ok, true, d.errors.join('; '));
  assert.deepEqual(verifyDeclarationSignature(d, JWKS), { ok: true, kid });
  const tampered = parse(signed(MIN, kp, kid).replace('Payment: none', 'Payment: any '));
  assert.equal(verifyDeclarationSignature(tampered, JWKS).error, 'bad_signature');
  assert.equal(verifyDeclarationSignature(d, [{ ...JWKS[0], kid: 'other' }]).error, 'unknown_key');
  const other = generateKeyPairSync('ed25519');
  assert.equal(verifyDeclarationSignature(parse(signed(MIN, other, kid)), JWKS).error, 'bad_signature');
  assert.equal(verifyDeclarationSignature(parse(MIN + 'Signature: abc..def\n'), JWKS).error, 'malformed');
  const jwt = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT', kid, jku: O + '/k.json' })).toString('base64url');
  assert.equal(verifyDeclarationSignature(parse(MIN + `Signature: ${jwt}..def\n`), JWKS).error, 'wrong_header');
  assert.equal(verifyDeclarationSignature(parse(MIN + `Signature: ${jwt}.e30.def\n`), JWKS).error, 'malformed', 'the payload is detached');
});

// ---------------------------------------------------------------- the checker, --server
function origin(body, opts = {}) {
  const seen = [];
  const fetch = async (url, init) => {
    seen.push(init?.headers?.['user-agent']);
    const u = new URL(url);
    if (opts.redirect && u.pathname === DECLARATION_PATH && u.origin === O) return new Response('', { status: 301, headers: { location: opts.redirect } });
    if (u.origin === O && u.pathname === '/moved.txt') return new Response(body, { status: 200, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'max-age=3600' } });
    if (u.origin !== O) throw new Error('ECONNREFUSED');
    if (u.pathname === DECLARATION_PATH) {
      if (body === null) return new Response('Not found', { status: 404 });
      return new Response(body, { status: 200, headers: { 'content-type': opts.type || 'text/plain; charset=utf-8', 'cache-control': opts.cache || 'public, max-age=3600' } });
    }
    if (u.pathname === '/.well-known/capabilities-keys.json') return new Response(JSON.stringify({ keys: JWKS }), { status: 200, headers: { 'content-type': 'application/json' } });
    return new Response('Not found', { status: 404 });
  };
  return { fetch, seen };
}
const failed = (rep) => rep.rules.filter((r) => r.result === 'fail').map((r) => r.id);
const run = (body, opts) => checkServer(O, { fetch: origin(body, opts).fetch, now: () => NOW });

test('--server: a valid file reaches server-1; signature optional; the checker identifies itself', async () => {
  const m = origin(MIN);
  const rep = await checkServer(O, { fetch: m.fetch, now: () => NOW });
  assert.deepEqual(failed(rep), []);
  assert.equal(rep.level, 'server-1');
  assert.equal(rep.rules.length, SERVER_RULES.length);
  assert.equal(rep.rules.find((r) => r.id === '13.signature').result, 'skip');
  assert.equal(rep.servers[0].endpoint, 'https://mail.example.com/mcp');
  assert.ok(m.seen.every((ua) => ua === CHECKER_USER_AGENT));
  assert.match(formatReport(rep), /Server declaration: https:\/\/example\.com[\s\S]*Level: server-1/);
  const s = await run(signed(MIN, kp, kid));
  assert.deepEqual([s.level, s.rules.find((r) => r.id === '13.signature').result], ['server-1', 'pass']);
  assert.equal((await run(MIN, { redirect: O + '/moved.txt' })).level, 'server-1', 'a same-origin redirect is followed');
});

for (const [name, body, opts, rule] of [
  ['no file', null, {}, '13.served'],
  ['redirect to another origin', MIN, { redirect: 'https://elsewhere.example/capabilities.txt' }, '13.served'],
  ['served as HTML', MIN, { type: 'text/html' }, '13.type'],
  ['too large', MIN + '#'.repeat(DECLARATION_MAX_BYTES), {}, '13.size'],
  ['expired', MIN.replace('2027-04-30', '2026-01-01'), {}, '13.expires'],
  ['endpoint on another host', MIN.replace('mail.example.com', 'mail.other.org'), {}, '13.endpoint-host'],
  ['no Jobs', MIN.replace(/^Jobs.*\n/m, ''), {}, '13.jobs'],
  ['bad Payment value', MIN.replace('Payment: none', 'Payment: free'), {}, '13.values'],
  ['tampered signature', signed(MIN, kp, kid).replace('Jobs: send', 'Jobs: Send'), {}, '13.signature'],
  ['key set on another origin', signed(MIN, kp, kid, 'https://keys.other.org/k.json'), {}, '13.signature'],
]) {
  test(`--server broken: ${name} fails ${rule} and the level`, async () => {
    const rep = await run(body, opts);
    assert.ok(failed(rep).includes(rule), `${rule} not failed; failed: ${failed(rep).join(', ')}`);
    assert.equal(rep.level, 'not conformant');
  });
}

test('--server: SHOULD rules only warn', async () => {
  const rep = await run(MIN.replace(/^Payment.*\n/m, '').replace('Capability Resolution 0.2', 'Capability Resolution 0.3'), { type: 'text/plain', cache: 'max-age=999999' });
  assert.equal(rep.level, 'server-1');
  assert.deepEqual(rep.rules.filter((r) => r.result === 'warn').map((r) => r.id).sort(), ['13.access', '13.cache', '13.charset', '13.version']);
});

test('--server: plain http is not conformant', async () => {
  assert.deepEqual(failed(await checkServer('http://example.com', { fetch: origin(MIN).fetch })), ['13.https']);
});

test('CLI --server: usage errors exit 2; an unreachable origin prints JSON and exits 1', () => {
  const bin = fileURLToPath(new URL('../bin/capability-resolution-check.js', import.meta.url));
  assert.throws(() => execFileSync(process.execPath, [bin, '--server'], { stdio: 'pipe' }), (e) => e.status === 2);
  assert.throws(() => execFileSync(process.execPath, [bin, '--server', O, '--need', 'x'], { stdio: 'pipe' }), (e) => e.status === 2);
  let out = '', status = 0;
  try { execFileSync(process.execPath, [bin, '--server', 'https://127.0.0.1:1', '--json', '--timeout', '2000'], { stdio: 'pipe' }); } catch (e) { out = e.stdout.toString(); status = e.status; }
  assert.equal(status, 1);
  const rep = JSON.parse(out);
  assert.deepEqual([rep.mode, rep.level, rep.rules.find((r) => r.id === '13.served').result], ['server', 'not conformant', 'fail']);
});
