// A mocked fetch that plays one resolver (discovery, resolve) with a throwaway Ed25519 key. No network.
import { createHash, generateKeyPairSync, sign } from 'node:crypto';

export const RESOLVER = 'https://resolver.test';
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

export function mockResolver({ tamper = false } = {}) {
  const kp = generateKeyPairSync('ed25519');
  const { x } = kp.publicKey.export({ format: 'jwk' });
  const kid = createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest('base64url');
  const calls = [];
  const tok = (url, status) => {
    const now = Math.floor(Date.now() / 1000);
    const h = b64u({ alg: 'EdDSA', typ: 'capability-resolver+jws', kid });
    const p = b64u({ v: '0.2', iss: RESOLVER, sub: 'test:abcdefghijklmnop', url, status, checked_at: '2026-10-28T10:05:00Z', iat: now, exp: now + 3600, evidence: {} });
    const s = sign(null, Buffer.from(`${h}.${p}`), kp.privateKey).toString('base64url');
    return `${h}.${tamper ? b64u({ v: '0.2', iss: RESOLVER, url: 'https://evil.example.com/mcp', iat: now, exp: now + 3600 }) : p}.${s}`;
  };
  const fetch = async (url, init) => {
    calls.push({ url: String(url), ua: init?.headers?.['user-agent'] });
    const u = new URL(url);
    if (u.origin !== RESOLVER) throw new Error('only the resolver may be called');
    const json = (body) => new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    if (u.pathname === '/.well-known/capability-resolver') return json({ v: '0.2', iss: RESOLVER, resolve: RESOLVER + '/resolve', record: RESOLVER + '/record', keys: [{ kty: 'OKP', crv: 'Ed25519', x, kid, use: 'sig', alg: 'EdDSA' }], policy_url: RESOLVER + '/policy' });
    if (u.pathname === '/resolve') {
      const all = [['https://mail.example.com/mcp', 'ok'], ['https://send.example.org/mcp', 'sign_in']];
      const list = (u.searchParams.get('constraints') || '').includes('no_sign_in') ? all.filter(([, s]) => s === 'ok') : all;
      return json({ v: '0.2', iss: RESOLVER, candidates: list.map(([cu, s]) => ({ id: 'x', url: cu, status: s, jws: tok(cu, s) })) });
    }
    return new Response('{}', { status: 404 });
  };
  return { fetch, calls };
}
