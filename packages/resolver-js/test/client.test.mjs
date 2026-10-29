// What the library states about itself (spec name, User-Agent, conformance) and the section 7 edges.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createResolverClient, verifyToken, SPEC, SPEC_URL, USER_AGENT, conformance, MAX_TTL_S } from '../src/index.js';

const T0 = Date.parse('2026-10-28T12:00:00Z'), T0s = T0 / 1000;
const A = 'https://resolver-a.example', B = 'https://resolver-b.example';
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
function makeKey() {
  const kp = generateKeyPairSync('ed25519');
  const { x } = kp.publicKey.export({ format: 'jwk' });
  const kid = createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest('base64url');
  return { priv: kp.privateKey, jwk: { kty: 'OKP', crv: 'Ed25519', x, kid, use: 'sig', alg: 'EdDSA' } };
}
const jws = (claims, k) => { const h = b64u({ alg: 'EdDSA', typ: 'capability-resolver+jws', kid: k.jwk.kid }), p = b64u(claims); return `${h}.${p}.${sign(null, Buffer.from(`${h}.${p}`), k.priv).toString('base64url')}`; };
const claims = (iss, extra = {}) => ({ v: '0.2', iss, sub: 'x:' + 'a'.repeat(16), url: 'https://a.example.com/mcp', status: 'ok', checked_at: '2026-10-28T10:05:00Z', iat: T0s, exp: T0s + 3600, evidence: {}, ...extra });

// A mock network that records every request and its init; per-origin behaviour.
function net(spec) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    const u = new URL(url), r = spec[u.origin];
    if (!r) throw new Error('ECONNREFUSED');
    if (u.pathname === '/.well-known/capability-resolver') return { ok: true, status: 200, json: async () => ({ v: '0.2', iss: u.origin, resolve: u.origin + '/resolve', record: u.origin + '/record', keys: r.keys || [r.key.jwk], policy_url: u.origin + '/p', ...(r.doc || {}) }) };
    if (r.status) return { ok: false, status: r.status, json: async () => ({}) };
    if (u.pathname === '/resolve') return { ok: true, status: 200, json: async () => ({ v: '0.2', candidates: r.candidates() }) };
    if (u.pathname === '/record') return { ok: true, status: 200, json: async () => ({ jws: r.record() }) };
    return { ok: false, status: 404, json: async () => ({}) };
  };
  return { fetch, calls };
}

test('the library names the spec, its editors and its license', () => {
  assert.equal(SPEC.text, 'Capability Resolution 0.2, open draft by 7IT Solutions, CC BY 4.0 (https://7it.co.il/standard/capability-resolution/)');
  assert.deepEqual([SPEC.name, SPEC.version, SPEC.editors, SPEC.license, SPEC.url], ['Capability Resolution', '0.2', '7IT Solutions', 'CC BY 4.0', SPEC_URL]);
  assert.ok(Object.isFrozen(SPEC));
  assert.equal(conformance, 'client-1');
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.private, true, 'cannot be published by mistake');
  assert.equal(pkg.capabilityResolution?.conformance, 'client-1');
  assert.match(pkg.description, /open draft by 7IT Solutions/);
});

test('every request carries the library User-Agent, with the conformance level and the spec URL', async () => {
  assert.equal(USER_AGENT, 'capability-resolver-client/0.2 (client-1; +https://7it.co.il/standard/capability-resolution/)');
  const k = makeKey();
  const n = net({ [A]: { key: k, candidates: () => [{ jws: jws(claims(A), k) }], record: () => jws(claims(A), k) } });
  const rc = createResolverClient({ resolvers: [A], fetch: n.fetch, now: () => T0, userAgent: 'my-agent/1.0' });
  await rc.resolve('send an email');
  await rc.record({ id: 'x:' + 'a'.repeat(16) });
  assert.equal(n.calls.length, 3);
  for (const c of n.calls) {
    assert.equal(c.init.headers['user-agent'], 'my-agent/1.0 ' + USER_AGENT, 'the app token goes first; the library token stays');
    assert.equal(c.init.redirect, 'error', 'no redirect can move the client to plain http or another origin');
  }
  assert.equal(rc.conformance, 'client-1');
});

test('7.3 fail open: rate-limited and bad resolvers are skipped, the next one answers', async () => {
  const k = makeKey();
  const n = net({ [A]: { key: k, status: 429 }, [B]: { key: k, candidates: () => [{ jws: jws(claims(B), k) }] } });
  const r = await createResolverClient({ resolvers: [A, B], fetch: n.fetch, now: () => T0 }).resolve('send an email');
  assert.deepEqual([r.resolver, r.errors[0].error], [B, 'http 429']);
  const slow = async () => new Promise(() => {}); // never answers; the timeout must end it
  const r2 = await createResolverClient({ resolvers: [A], fetch: (u, i) => Promise.race([slow(), new Promise((_, no) => i.signal.addEventListener('abort', () => no(new Error('timeout'))))]), timeoutMs: 50 }).resolve('send an email');
  assert.deepEqual([r2.resolver, r2.candidates.length, r2.errors[0].error], [null, 0, 'timeout']);
  const r3 = await createResolverClient({ resolvers: [A], fetch: async () => { throw new TypeError('boom'); } }).resolve('send an email');
  assert.equal(r3.candidates.length, 0);
});

test('7.3 a discovery document whose iss is another origin is not used', async () => {
  const k = makeKey();
  const n = net({ [A]: { key: k, doc: { iss: B }, candidates: () => [{ jws: jws(claims(A), k) }] } });
  const r = await createResolverClient({ resolvers: [A], fetch: n.fetch, now: () => T0 }).resolve('send an email');
  assert.deepEqual([r.candidates.length, r.errors[0].error], [0, 'iss is not this origin']);
});

test('7.4 a key outside its nbf/exp window is not used; a token without a usable url is not a candidate', async () => {
  const k = makeKey();
  const retired = { ...k.jwk, exp: T0s - 86400 };
  assert.deepEqual(verifyToken(jws(claims(A), k), [retired], T0s), { ok: false, error: 'unknown_key' });
  const future = { ...k.jwk, nbf: T0s + 86400 };
  assert.deepEqual(verifyToken(jws(claims(A), k), [future], T0s), { ok: false, error: 'unknown_key' });
  const n = net({ [A]: { key: k, candidates: () => [{ jws: jws(claims(A, { url: 'http://plain.example.com/mcp' }), k) }] } });
  const r = await createResolverClient({ resolvers: [A], fetch: n.fetch, now: () => T0 }).resolve('send an email');
  assert.deepEqual([r.candidates.length, r.errors[0].error], [0, 'unverified_candidate: malformed']);
});

test('7.4 record: wrong issuer is refused, the next resolver is asked', async () => {
  const k = makeKey();
  const n = net({ [A]: { key: k, record: () => jws(claims(B), k) }, [B]: { key: k, record: () => jws(claims(B), k) } });
  const rec = await createResolverClient({ resolvers: [A, B], fetch: n.fetch, now: () => T0 }).record({ url: 'https://a.example.com/mcp' });
  assert.equal(rec.resolver, B);
  assert.equal(rec.iss, B);
});

test('7.5 no auto-connect: the client only ever calls resolver origins', async () => {
  const k = makeKey();
  const n = net({ [A]: { key: k, candidates: () => [{ jws: jws(claims(A), k) }] } });
  const r = await createResolverClient({ resolvers: [A], fetch: n.fetch, now: () => T0 }).resolve('send an email');
  assert.equal(r.candidates[0].url, 'https://a.example.com/mcp');
  assert.ok(n.calls.every((c) => new URL(c.url).origin === A), 'the candidate server was never contacted');
});

test('7.6 cache: discovery reused within one hour, refetched after; answers never served after exp', async () => {
  const k = makeKey();
  let now = T0;
  const n = net({ [A]: { key: k, candidates: () => [{ jws: jws(claims(A, { iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + 600 }), k) }] } });
  const rc = createResolverClient({ resolvers: [A], fetch: n.fetch, now: () => now });
  const disco = () => n.calls.filter((c) => c.url.endsWith('/.well-known/capability-resolver')).length;
  await rc.resolve('send an email');
  now += 599_000;
  const cached = await rc.resolve('send an email');
  assert.equal(n.calls.length, 2, 'second answer from cache');
  assert.equal(cached.candidates.length, 1);
  now += 2_000; // past exp
  await rc.resolve('send an email');
  assert.equal(n.calls.length, 3, 'asked again after exp');
  now += 3_600_000;
  await rc.resolve('send an email');
  assert.equal(disco(), 2, 'discovery refetched after one hour');
  assert.ok(MAX_TTL_S === 172800);
});

test('7.7 status is history: each candidate keeps its checked_at', async () => {
  const k = makeKey();
  const n = net({ [A]: { key: k, candidates: () => [{ jws: jws(claims(A, { status: 'sign_in' }), k) }] } });
  const r = await createResolverClient({ resolvers: [A], fetch: n.fetch, now: () => T0 }).resolve('send an email');
  assert.deepEqual([r.candidates[0].status, r.candidates[0].checked_at], ['sign_in', '2026-10-28T10:05:00Z']);
});
