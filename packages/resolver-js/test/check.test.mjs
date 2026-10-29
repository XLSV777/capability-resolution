// capability-resolution-check against an in-process mock resolver (good, and broken one rule at a time).
// The fuller run against the reference resolver code lives in 7IT-LANDING (scripts/resolver-check-local.mts).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { checkResolver, formatReport, RULES, CHECKER_USER_AGENT } from '../src/check.js';

const O = 'https://resolver.test';
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

function mock(breakIt = {}) {
  const kp = generateKeyPairSync('ed25519');
  const { x } = kp.publicKey.export({ format: 'jwk' });
  const kid = createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest('base64url');
  const servers = [['https://mail.example.com/mcp', 'ok'], ['https://send.example.org/mcp', 'sign_in']];
  const idOf = (u) => 'mock:' + createHash('sha256').update(u).digest('hex').replace(/[^a-z2-7]/g, '').padEnd(16, 'a').slice(0, 16);
  const tok = (url, status, extra = {}) => {
    const nowS = Math.floor(Date.now() / 1000);
    const c = { v: '0.2', iss: O, sub: idOf(url), url, status, checked_at: '2026-10-28T10:05:00Z', iat: nowS, exp: nowS + 172800, evidence: { record: O + '/record' }, ...extra, ...(breakIt.claims || {}) };
    const h = b64u({ alg: 'EdDSA', typ: breakIt.typ || 'capability-resolver+jws', kid }), p = b64u(c);
    return `${h}.${p}.${sign(null, Buffer.from(`${h}.${p}`), kp.privateKey).toString('base64url')}`;
  };
  const json = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
  const err = (status, error) => (breakIt.textErrors ? new Response(error, { status }) : json(status, { v: '0.2', error, note: 'n' }));
  const seen = [];
  const fetch = async (url, init) => {
    seen.push(init?.headers?.['user-agent']);
    const u = new URL(url);
    if (u.origin !== O) throw new Error('ECONNREFUSED');
    const q = (k) => u.searchParams.get(k);
    if (u.pathname === '/.well-known/capability-resolver') return json(200, { v: '0.2', iss: breakIt.iss || O, resolve: O + '/resolve', record: (breakIt.recordOrigin || O) + '/record', keys: [{ kty: 'OKP', crv: 'Ed25519', x, kid, use: 'sig', alg: 'EdDSA' }], policy_url: O + '/policy', id_namespace: 'mock', constraints: ['no_sign_in'] }, { 'cache-control': 'max-age=3600' });
    if (u.pathname === '/policy') return new Response('policy', { status: 200 });
    if (u.pathname === '/resolve') {
      const need = q('need') || '';
      if (need.length < 3 || need.length > 200) return err(400, 'bad_need');
      const cons = (q('constraints') || '').split(',').filter(Boolean);
      const unknown = cons.filter((c) => c !== 'no_sign_in');
      if (breakIt.refuseUnknown && unknown.length) return err(400, 'bad_constraint');
      const list = servers.filter(([, s]) => !(cons.includes('no_sign_in') && !breakIt.ignoreNoSignIn) || s === 'ok');
      return json(200, { v: '0.2', iss: O, ignored: unknown, candidates: list.map(([u2, s]) => ({ id: idOf(u2), url: u2, status: s, jws: breakIt.unsigned ? undefined : tok(u2, s, breakIt.leakNeed ? { need } : {}) })) });
    }
    if (u.pathname === '/record') {
      const id = q('id'), url2 = q('url');
      if (id && !/^[a-z0-9-]+:[a-z2-7]{16}$/.test(id)) return err(400, 'bad_id');
      const hit = servers.find(([s]) => s === url2 || idOf(s) === id);
      if (!hit) return breakIt.no404 ? json(200, {}) : err(404, 'not_found');
      return json(200, { jws: tok(hit[0], hit[1], { name: 'Mail', first_seen: '2026-10-02', anchor: null, proof: null }) });
    }
    return err(404, 'not_found');
  };
  return { fetch, seen };
}
const failed = (rep) => rep.rules.filter((r) => r.result === 'fail').map((r) => r.id);

test('a resolver that follows the spec reaches resolver-1; the checker identifies itself', async () => {
  const m = mock();
  const rep = await checkResolver(O, { fetch: m.fetch });
  assert.deepEqual(failed(rep), []);
  assert.equal(rep.level, 'resolver-1');
  assert.equal(rep.rules.length, RULES.length);
  assert.match(rep.spec, /^Capability Resolution 0\.2, open draft by 7IT Solutions/);
  assert.ok(m.seen.every((ua) => ua === CHECKER_USER_AGENT));
  assert.match(formatReport(rep), /Level: resolver-1/);
});

for (const [name, breakIt, rule] of [
  ['discovery iss names another origin', { iss: 'https://other.test' }, '5.iss'],
  ['record endpoint on another origin', { recordOrigin: 'https://other.test' }, '5.same-origin'],
  ['unsigned candidates', { unsigned: true }, '6.1.signed'],
  ['plain-text errors', { textErrors: true }, '6.1.errors'],
  ['unknown constraint refused', { refuseUnknown: true }, '6.2.unknown'],
  ['listed constraint not applied', { ignoreNoSignIn: true }, '6.2.applied'],
  ['unknown id answers 200', { no404: true }, '6.3.not-found'],
  ['wrong typ', { typ: 'JWT' }, '8.header'],
  ['token lives 49 hours', { claims: { exp: Math.floor(Date.now() / 1000) + 49 * 3600 } }, '8.lifetime'],
  ['token carries the need', { leakNeed: true }, '8.no-caller-data'],
  ['url not canonical', { claims: { url: 'https://WWW.Mail.example.com/mcp/' } }, '8.url'],
  ['checked_at after signing', { claims: { checked_at: '2099-01-01T00:00:00Z' } }, '9.honest'],
]) {
  test(`broken: ${name} fails ${rule} and the level`, async () => {
    const rep = await checkResolver(O, { fetch: mock(breakIt).fetch });
    assert.ok(failed(rep).includes(rule), `${rule} not failed; failed: ${failed(rep).join(', ')}`);
    assert.equal(rep.level, 'not conformant');
  });
}

test('plain http and unreachable resolvers are not conformant', async () => {
  assert.deepEqual(failed(await checkResolver('http://resolver.test', { fetch: mock().fetch })), ['5.https']);
  const down = await checkResolver('https://down.test', { fetch: mock().fetch });
  assert.deepEqual([failed(down), down.level], [['5.served'], 'not conformant']);
});

test('CLI: usage error exits 2; an unreachable origin prints JSON and exits 1', () => {
  const bin = fileURLToPath(new URL('../bin/capability-resolution-check.js', import.meta.url));
  assert.throws(() => execFileSync(process.execPath, [bin], { stdio: 'pipe' }), (e) => e.status === 2);
  let out = '', status = 0;
  try { execFileSync(process.execPath, [bin, 'https://127.0.0.1:1', '--json', '--timeout', '2000'], { stdio: 'pipe' }); } catch (e) { out = e.stdout.toString(); status = e.status; }
  assert.equal(status, 1);
  const rep = JSON.parse(out);
  assert.equal(rep.level, 'not conformant');
  assert.equal(rep.rules.find((r) => r.id === '5.served').result, 'fail');
});
