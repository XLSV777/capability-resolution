// capability-resolver-client tests: a mock fetch and throwaway Ed25519 keys; nothing leaves the machine.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { createResolverClient, verifyToken, DEFAULT_RESOLVERS, MAX_TTL_S, CLOCK_SKEW_S } from '../src/index.js';

const T0 = Date.parse('2026-10-28T12:00:00Z');
const T0s = T0 / 1000;
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
function makeKey() {
  const kp = generateKeyPairSync('ed25519');
  const { x } = kp.publicKey.export({ format: 'jwk' });
  const kid = createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest('base64url');
  return { priv: kp.privateKey, jwk: { kty: 'OKP', crv: 'Ed25519', x, kid, use: 'sig', alg: 'EdDSA' } };
}
const jws = (claims, k, typ = 'capability-resolver+jws') => {
  const h = b64u({ alg: 'EdDSA', typ, kid: k.jwk.kid }), p = b64u(claims);
  return `${h}.${p}.${sign(null, Buffer.from(`${h}.${p}`), k.priv).toString('base64url')}`;
};
const claims = (iss, url, extra = {}) => ({ v: '0.2', iss, sub: '7maps:' + 'a'.repeat(16), url, status: 'ok', checked_at: '2026-10-28T10:05:00Z', iat: T0s, exp: T0s + MAX_TTL_S, ...extra });

// A mock network of resolvers: origin -> { key, candidates(url) | throws }.
function network(spec) {
  const calls = [];
  const fetch = async (url) => {
    calls.push(String(url));
    const u = new URL(url);
    const r = spec[u.origin];
    if (!r || r.down) throw new Error('connect ECONNREFUSED');
    if (u.pathname === '/.well-known/capability-resolver') return { ok: true, status: 200, json: async () => r.doc || { v: '0.2', resolve: u.origin + '/resolve', record: u.origin + '/record', keys: [r.key.jwk], policy_url: u.origin + '/policy' } };
    if (u.pathname === '/resolve') return { ok: true, status: 200, json: async () => ({ v: '0.2', candidates: r.candidates(u) }) };
    if (u.pathname === '/record') return { ok: true, status: 200, json: async () => ({ jws: jws(claims(u.origin, 'https://a.example.com/mcp'), r.key) }) };
    return { ok: false, status: 404, json: async () => ({}) };
  };
  return { fetch, calls };
}
const A = 'https://resolver-a.example', B = 'https://resolver-b.example';

test('empty resolver list by default: no network, empty answer', async () => {
  assert.deepEqual([...DEFAULT_RESOLVERS], []);
  const { fetch, calls } = network({});
  const rc = createResolverClient({ fetch });
  assert.deepEqual(await rc.resolve('send an email'), { resolver: null, candidates: [], errors: [] });
  assert.equal(calls.length, 0);
});

test('signature verifies; plain fields ignored in favour of signed claims', async () => {
  const k = makeKey();
  const { fetch } = network({ [A]: { key: k, candidates: () => [{ id: 'x', url: 'https://evil.example/mcp', status: 'ok', jws: jws(claims(A, 'https://a.example.com/mcp'), k) }] } });
  const rc = createResolverClient({ resolvers: [A], fetch, now: () => T0 });
  const r = await rc.resolve('send an email');
  assert.equal(r.resolver, A);
  assert.equal(r.candidates.length, 1);
  assert.equal(r.candidates[0].url, 'https://a.example.com/mcp');
});

test('a resolver that returns any token that does not verify is skipped as a whole (spec 7.3)', async () => {
  const k = makeKey(), other = makeKey();
  const good = jws(claims(A, 'https://a.example.com/mcp'), k);
  const [h, , s] = good.split('.');
  const tampered = `${h}.${b64u(claims(A, 'https://evil.example/mcp'))}.${s}`;
  const { fetch } = network({ [A]: { key: k, candidates: () => [
    { jws: tampered }, { jws: jws(claims(A, 'https://b.example.com/mcp'), other) }, { jws: jws(claims(A, 'https://c.example.com/mcp'), k, 'JWT') },
    { jws: jws(claims(A, 'https://d.example.com/mcp', { exp: T0s + MAX_TTL_S + 60 }), k) }, { jws: jws(claims(B, 'https://e.example.com/mcp'), k) }, { jws: good },
  ] } });
  const r = await createResolverClient({ resolvers: [A], fetch, now: () => T0 }).resolve('send an email');
  assert.deepEqual([r.resolver, r.candidates.length], [null, 0]);
  assert.equal(r.errors[0].error, 'unverified_candidate: bad_signature');
  // Each bad token alone also skips the resolver, with its own reason.
  for (const [bad, why] of [[jws(claims(A, 'https://b.example.com/mcp'), other), 'unknown_key'], [jws(claims(A, 'https://c.example.com/mcp'), k, 'JWT'), 'wrong_type'],
    [jws(claims(A, 'https://d.example.com/mcp', { exp: T0s + MAX_TTL_S + 60 }), k), 'ttl_too_long'], [jws(claims(B, 'https://e.example.com/mcp'), k), 'wrong_issuer']]) {
    const n = network({ [A]: { key: k, candidates: () => [{ jws: good }, { jws: bad }] } });
    const r1 = await createResolverClient({ resolvers: [A], fetch: n.fetch, now: () => T0 }).resolve('send an email');
    assert.deepEqual([r1.candidates.length, r1.errors[0].error], [0, 'unverified_candidate: ' + why]);
  }
});

test('expiry honoured with clock tolerance', () => {
  const k = makeKey();
  const t = jws(claims(A, 'https://a.example.com/mcp'), k);
  assert.equal(verifyToken(t, [k.jwk], T0s + MAX_TTL_S + CLOCK_SKEW_S - 1).ok, true);
  assert.deepEqual(verifyToken(t, [k.jwk], T0s + MAX_TTL_S + CLOCK_SKEW_S + 1), { ok: false, error: 'expired' });
  assert.deepEqual(verifyToken(t, [k.jwk], T0s - CLOCK_SKEW_S - 1), { ok: false, error: 'not_yet_valid' });
});

test('cache until expiry, then ask again', async () => {
  const k = makeKey();
  let now = T0;
  const { fetch, calls } = network({ [A]: { key: k, candidates: () => [{ jws: jws(claims(A, 'https://a.example.com/mcp', { iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + 3600 }), k) }] } });
  const rc = createResolverClient({ resolvers: [A], fetch, now: () => now });
  await rc.resolve('send an email');
  const n1 = calls.filter((c) => new URL(c).pathname === '/resolve').length;
  now += 30 * 60_000;
  await rc.resolve('send an email');
  assert.equal(calls.filter((c) => new URL(c).pathname === '/resolve').length, n1, 'served from cache inside expiry');
  now += 31 * 60_000;
  await rc.resolve('send an email');
  assert.equal(calls.filter((c) => new URL(c).pathname === '/resolve').length, n1 + 1, 'asked again after expiry');
});

test('fail open: a down resolver is skipped; all down returns empty, never throws', async () => {
  const k = makeKey();
  const { fetch } = network({ [A]: { down: true }, [B]: { key: k, candidates: () => [{ jws: jws(claims(B, 'https://a.example.com/mcp'), k) }] } });
  const r = await createResolverClient({ resolvers: [A, B], fetch, now: () => T0 }).resolve('send an email');
  assert.equal(r.resolver, B);
  assert.equal(r.errors[0].resolver, A);
  const none = network({ [A]: { down: true }, [B]: { down: true } });
  const r2 = await createResolverClient({ resolvers: [A, B], fetch: none.fetch, now: () => T0 }).resolve('send an email');
  assert.deepEqual([r2.resolver, r2.candidates.length, r2.errors.length], [null, 0, 2]);
  assert.equal(await createResolverClient({ resolvers: [A], fetch: none.fetch }).record({ url: 'https://a.example.com/mcp' }), null);
});

test('constraints are sent as one list; http resolvers and off-origin endpoints refused', async () => {
  const k = makeKey();
  let seen = '';
  const { fetch } = network({
    [A]: { key: k, candidates: (u) => { seen = u.searchParams.get('constraints'); return [{ jws: jws(claims(A, 'https://a.example.com/mcp'), k) }]; } },
    [B]: { key: k, doc: { v: '0.2', resolve: 'https://elsewhere.example/resolve', keys: [k.jwk] }, candidates: () => [] },
  });
  await createResolverClient({ resolvers: [A], fetch, now: () => T0 }).resolve('read a database', { no_sign_in: true, read_only: true, max_ms: 800, payment: 'none' });
  assert.equal(seen, 'no_sign_in,read_only,max_ms:800,payment:none');
  assert.deepEqual(createResolverClient({ resolvers: ['http://plain.example', A] }).resolvers, [A]);
  const r = await createResolverClient({ resolvers: [B], fetch, now: () => T0 }).resolve('read a database');
  assert.equal(r.errors[0].error, 'endpoint on another origin');
});

test('pinned keys override the discovery document', async () => {
  const k = makeKey(), pinned = makeKey();
  const { fetch } = network({ [A]: { key: k, candidates: () => [{ jws: jws(claims(A, 'https://a.example.com/mcp'), k) }] } });
  const r = await createResolverClient({ resolvers: [A], fetch, now: () => T0, pinnedKeys: { [A]: [pinned.jwk] } }).resolve('send an email');
  assert.equal(r.candidates.length, 0, 'a key not pinned is not trusted');
});

test('record verifies; no console output, so the need never reaches logs', async () => {
  const k = makeKey();
  const out = [];
  const orig = { ...console };
  for (const m of ['log', 'error', 'warn', 'info', 'debug']) console[m] = (...a) => out.push(a.join(' '));
  try {
    const { fetch } = network({ [A]: { key: k, candidates: () => { throw new Error('x'); } } });
    const rc = createResolverClient({ resolvers: [A], fetch, now: () => T0 });
    const rec = await rc.record({ url: 'https://a.example.com/mcp' });
    assert.equal(rec.url, 'https://a.example.com/mcp');
    await rc.resolve('private need for patient zebra');
  } finally { Object.assign(console, orig); }
  assert.deepEqual(out, []);
});
