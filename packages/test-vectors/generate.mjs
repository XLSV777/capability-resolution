// Capability Resolution 0.2: signed test vectors (draft, not on npm yet).
// Generates vectors.json with a throwaway Ed25519 key. The private key exists only while this script runs and is
// never written anywhere; the public JWK is stored in vectors.json (keys.test) and in test-key.public.jwk.json.
// Run: node generate.mjs   (rewrites both files with a fresh key; the verdicts stay the same)
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const NOW = Date.parse('2026-10-28T12:00:00Z') / 1000;
const ISS = 'https://resolver.test';
const TYP = 'capability-resolver+jws';
const MAX = 172800;

const b64u = (x) => Buffer.from(typeof x === 'string' ? x : JSON.stringify(x)).toString('base64url');
function makeKey() {
  const kp = generateKeyPairSync('ed25519');
  const { x } = kp.publicKey.export({ format: 'jwk' });
  const kid = createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest('base64url');
  return { priv: kp.privateKey, jwk: { kty: 'OKP', crv: 'Ed25519', x, kid, use: 'sig', alg: 'EdDSA' } };
}
const test = makeKey();
const other = makeKey(); // signs the "wrong key" vectors; its public key is published too

const header = (k, extra = {}) => ({ alg: 'EdDSA', typ: TYP, kid: k.jwk.kid, ...extra });
function jws(claims, k = test, head = header(k)) {
  const h = b64u(head), p = b64u(claims);
  return `${h}.${p}.${sign(null, Buffer.from(`${h}.${p}`), k.priv).toString('base64url')}`;
}
const SUB = 'test:abcdefghijklmnop';
const URL1 = 'https://mail.example.com/mcp';
const evidence = { record: `${ISS}/record?id=${SUB}`, method: `${ISS}/method` };
const cand = (extra = {}) => ({ v: '0.2', iss: ISS, sub: SUB, url: URL1, status: 'ok', checked_at: '2026-10-28T10:05:00Z', iat: NOW, exp: NOW + MAX, evidence, ...extra });
const rec = (extra = {}) => cand({ name: 'Mail', first_seen: '2026-10-02', anchor: { day: '2026-10-27', root: 'ab'.repeat(32), url: `${ISS}/roots/2026-10-27` }, proof: null, ...extra });

const good = jws(cand());
const [gh, , gs] = good.split('.');
const v = [];
const add = (name, description, token, expect, more = {}) => v.push({ name, description, jws: token, now: NOW, iss: ISS, keys: ['test'], ...more, expect });

// ---- valid
add('valid-candidate', 'A resolve candidate with every required claim, status ok.', good, { valid: true });
add('valid-sign-in', 'A candidate with status sign_in.', jws(cand({ status: 'sign_in' })), { valid: true });
add('valid-record', 'A record: adds name, first_seen, anchor and a null proof (level resolver-1).', jws(rec()), { valid: true }, { kind: 'record' });
add('valid-max-lifetime', 'Lifetime exactly 48 hours (172800 s).', jws(cand({ exp: NOW + MAX })), { valid: true });
add('valid-expired-inside-skew', 'exp is 299 s in the past: inside the 300 s tolerance.', jws(cand({ iat: NOW - 3600, exp: NOW - 299 })), { valid: true });
add('valid-iat-future-inside-skew', 'iat is 299 s in the future: inside the 300 s tolerance.', jws(cand({ iat: NOW + 299, exp: NOW + 3600 })), { valid: true });
add('valid-unknown-claim', 'An extra claim a client does not know is ignored.', jws(cand({ 'x-test-note': 'ignored' })), { valid: true });
add('valid-second-key', 'Signed with the second published key; both keys are in the set.', jws(cand(), other), { valid: true }, { keys: ['test', 'other'] });

// ---- invalid
add('invalid-tampered-payload', 'The payload was changed after signing (url swapped).', `${gh}.${b64u(cand({ url: 'https://evil.example.com/mcp' }))}.${gs}`, { valid: false, error: 'bad_signature' });
add('invalid-wrong-key-same-kid', 'Signed by another key but labelled with the test kid.', jws(cand(), other, header(test)), { valid: false, error: 'bad_signature' });
add('invalid-unknown-kid', 'Signed by a key that is not in the key set.', jws(cand(), other), { valid: false, error: 'unknown_key' });
add('invalid-key-retired', 'The key carries exp (rotation) in the past, so it is no longer used.', good, { valid: false, error: 'unknown_key' }, { keys: ['test-retired'] });
add('invalid-typ-jwt', 'Header typ is JWT, not capability-resolver+jws.', jws(cand(), test, header(test, { typ: 'JWT' })), { valid: false, error: 'wrong_type' });
add('invalid-no-kid', 'Header has no kid.', jws(cand(), test, { alg: 'EdDSA', typ: TYP }), { valid: false, error: 'malformed' });
add('invalid-alg-none', 'Unsigned token (alg none, empty signature part).', `${b64u({ alg: 'none', typ: TYP, kid: test.jwk.kid })}.${b64u(cand())}.`, { valid: false, error: 'malformed' });
add('invalid-alg-hs256', 'alg HS256 instead of EdDSA.', `${b64u({ alg: 'HS256', typ: TYP, kid: test.jwk.kid })}.${b64u(cand())}.${gs}`, { valid: false, error: 'malformed' });
add('invalid-two-parts', 'Not a compact JWS (two parts).', `${gh}.${b64u(cand())}`, { valid: false, error: 'malformed' });
add('invalid-no-exp', 'exp is missing.', jws(cand({ exp: undefined })), { valid: false, error: 'malformed' });
add('invalid-exp-string', 'exp is a string, not seconds.', jws(cand({ exp: String(NOW + 3600) })), { valid: false, error: 'malformed' });
add('invalid-lifetime-too-long', 'Lifetime 172801 s, one second over 48 hours.', jws(cand({ exp: NOW + MAX + 1 })), { valid: false, error: 'ttl_too_long' });
add('invalid-expired', 'exp is 301 s in the past.', jws(cand({ iat: NOW - 3600, exp: NOW - 301 })), { valid: false, error: 'expired' });
add('invalid-not-yet-valid', 'iat is 301 s in the future.', jws(cand({ iat: NOW + 301, exp: NOW + 3600 })), { valid: false, error: 'not_yet_valid' });
add('invalid-wrong-issuer', 'Signed with the resolver key but iss names another origin.', jws(cand({ iss: 'https://other.example' })), { valid: false, error: 'wrong_issuer' });

const retired = { ...test.jwk, nbf: NOW - 30 * 86400, exp: NOW - 86400 };
const out = {
  spec: 'Capability Resolution 0.2, open draft by 7IT Solutions, CC BY 4.0 (https://7it.co.il/standard/capability-resolution/)',
  note: 'Test vectors only. The keys are throwaway test keys; their private halves were discarded. Never trust them for anything else.',
  generated: new Date(NOW * 1000).toISOString(),
  how_to_use: 'For each vector: verify jws with the JWKs named in keys (from the keys map), at time now (seconds), expecting issuer iss. A client must reach expect.valid; when false, expect.error is the reason the reference client gives (error names are informative, the verdict is normative).',
  keys: { test: test.jwk, other: other.jwk, 'test-retired': retired },
  vectors: v,
};
writeFileSync(new URL('./vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
writeFileSync(new URL('./test-key.public.jwk.json', import.meta.url), JSON.stringify(test.jwk, null, 2) + '\n');
console.log(`wrote ${v.length} vectors (${v.filter((x) => x.expect.valid).length} valid, ${v.filter((x) => !x.expect.valid).length} invalid)`);
