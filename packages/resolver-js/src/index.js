// capability-resolver-client (draft, spec 0.2 "Capability Resolution", for use with the Model Context Protocol):
// a tiny client that asks an ordered list of resolvers which servers can do a job, verifies every answer,
// caches it until it expires, and fails open.
// Node 18+ built-ins only. It never connects to a server: the caller's own policy decides that.
//
//   import { createResolverClient } from 'capability-resolver-client';
//   const rc = createResolverClient({ resolvers: ['https://resolver.example'] }); // empty by default
//   const { candidates, errors } = await rc.resolve('send a transactional email', { no_sign_in: true });
//
// Client rules (spec section 7, conformance level client-1):
//   1. The resolver list is empty unless the caller adds origins; plain-http resolvers are never used.
//   2. Resolvers are asked in order.
//   3. Fail open: a resolver that is unreachable, slow, rate-limited, or returns anything that does not verify
//      is skipped. If none answers, the caller gets an empty list, never an exception.
//   4. Every candidate is verified (key from that resolver or pinned keys, `iss`, `iat`/`exp`) and only the
//      signed claims are used.
//   5. No auto-connect: this library never connects to, authorizes or calls a server.
//   6. Answers are cached until the earliest `exp` and never used after it; discovery for at most one hour.
//   7. `status` is history: it is returned with its `checked_at`, as observed.
import { createPublicKey, verify } from 'node:crypto';

export const SPEC_VERSION = '0.2';
export const SPEC_URL = 'https://7it.co.il/standard/capability-resolution/';
/** What this library implements, stated by the library itself. */
export const SPEC = Object.freeze({
  name: 'Capability Resolution',
  version: SPEC_VERSION,
  status: 'open draft',
  editors: '7IT Solutions',
  license: 'CC BY 4.0',
  url: SPEC_URL,
  text: `Capability Resolution ${SPEC_VERSION}, open draft by 7IT Solutions, CC BY 4.0 (${SPEC_URL})`,
});
/** The conformance level this library meets (spec section 12). */
export const conformance = 'client-1';
export const CLIENT_VERSION = '0.2.0';
/** Sent on every request, so a resolver can count declared client-1 clients. */
export const USER_AGENT = `capability-resolver-client/${SPEC_VERSION} (${conformance}; +${SPEC_URL})`;

export const MAX_TTL_S = 48 * 3600;
export const CLOCK_SKEW_S = 300;
export const DISCOVERY_MAX_AGE_MS = 3_600_000;
export const JWS_TYP = 'capability-resolver+jws';
export const STATUSES = Object.freeze(['ok', 'sign_in', 'down', 'unknown']);
export const DEFAULT_RESOLVERS = Object.freeze([]);
export const WELL_KNOWN_PATH = '/.well-known/capability-resolver';
// The server declaration file (spec section 13): parser, resolver allow/deny, optional signature.
export { DECLARATION_PATH, DECLARATION_MAX_BYTES, DECLARATION_MAX_AGE_S, DECLARATION_TYP, parseDeclaration, resolverAllowed, verifyDeclarationSignature, coveredHost } from './declaration.js';

const b64json = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
const B64U_RE = /^[A-Za-z0-9_-]+$/;

/** A key may carry nbf/exp (seconds) for rotation (spec section 5); outside that window it is not used. */
const keyUsable = (k, nowS) => !(Number.isFinite(k?.nbf) && k.nbf > nowS + CLOCK_SKEW_S) && !(Number.isFinite(k?.exp) && k.exp < nowS - CLOCK_SKEW_S);

/**
 * Verify one compact JWS (spec section 8). Returns { ok: true, payload } or { ok: false, error }.
 * Errors: malformed, wrong_type, unknown_key, bad_signature, ttl_too_long, not_yet_valid, expired, wrong_issuer.
 * @param {string} jws
 * @param {object[]} keys public JWKs (from discovery or pinned)
 * @param {number} [nowS] current time in seconds
 * @param {{ iss?: string }} [opts] iss: the resolver origin the token must name
 */
export function verifyToken(jws, keys, nowS = Math.floor(Date.now() / 1000), opts = {}) {
  const p = String(jws || '').split('.');
  if (p.length !== 3 || !p.every((s) => B64U_RE.test(s))) return { ok: false, error: 'malformed' };
  let head, payload;
  try { head = b64json(p[0]); payload = b64json(p[1]); } catch { return { ok: false, error: 'malformed' }; }
  if (!head || typeof head !== 'object' || !payload || typeof payload !== 'object') return { ok: false, error: 'malformed' };
  if (head.alg !== 'EdDSA' || typeof head.kid !== 'string' || !head.kid) return { ok: false, error: 'malformed' };
  if (head.typ !== JWS_TYP) return { ok: false, error: 'wrong_type' };
  const k = (keys || []).find((x) => x && x.kid === head.kid && x.kty === 'OKP' && x.crv === 'Ed25519' && keyUsable(x, nowS));
  if (!k) return { ok: false, error: 'unknown_key' };
  let good = false;
  try { good = verify(null, Buffer.from(`${p[0]}.${p[1]}`), createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: k.x }, format: 'jwk' }), Buffer.from(p[2], 'base64url')); } catch { good = false; }
  if (!good) return { ok: false, error: 'bad_signature' };
  const iat = payload.iat, exp = payload.exp;
  if (!Number.isFinite(iat) || !Number.isFinite(exp)) return { ok: false, error: 'malformed' };
  if (exp - iat > MAX_TTL_S) return { ok: false, error: 'ttl_too_long' };
  if (iat > nowS + CLOCK_SKEW_S) return { ok: false, error: 'not_yet_valid' };
  if (exp < nowS - CLOCK_SKEW_S) return { ok: false, error: 'expired' };
  if (opts.iss !== undefined && payload.iss !== opts.iss) return { ok: false, error: 'wrong_issuer' };
  return { ok: true, payload };
}

const constraintsParam = (c = {}) => [c.no_sign_in ? 'no_sign_in' : '', c.read_only ? 'read_only' : '', Number.isInteger(c.max_ms) && c.max_ms > 0 ? `max_ms:${c.max_ms}` : '', c.payment === 'none' ? 'payment:none' : ''].filter(Boolean).join(',');
const originOf = (u) => { try { const x = new URL(u); return x.protocol === 'https:' ? x.origin : ''; } catch { return ''; } };
// A candidate is usable only if its signed claims name a server: an id and an https URL with a known status.
const usableClaims = (p) => typeof p.sub === 'string' && p.sub && originOf(p.url) !== '' && STATUSES.includes(p.status);

/**
 * @param {{ resolvers?: string[], fetch?: typeof fetch, timeoutMs?: number, now?: () => number, pinnedKeys?: Record<string, object[]>, userAgent?: string }} [opts]
 *   resolvers: ordered https origins (empty by default). pinnedKeys: origin -> JWKs to use instead of the
 *   keys in the resolver's discovery document (recommended for clients that ship a default resolver).
 *   userAgent: a product token to put in front of this library's own User-Agent (the library's token stays).
 */
export function createResolverClient(opts = {}) {
  const resolvers = [...new Set((opts.resolvers || DEFAULT_RESOLVERS).map(originOf).filter(Boolean))];
  const doFetch = opts.fetch || globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? 5000;
  const now = opts.now || Date.now;
  const ua = opts.userAgent ? `${String(opts.userAgent).replace(/[\r\n]/g, ' ').slice(0, 120)} ${USER_AGENT}` : USER_AGENT;
  const discoCache = new Map(); // origin -> { at, doc }
  const answerCache = new Map(); // key -> { until, value }

  const getJson = async (url) => {
    const r = await doFetch(url, { headers: { accept: 'application/json', 'user-agent': ua }, redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
    if (!r || !r.ok) throw new Error('http ' + (r && r.status));
    if (r.url && originOf(r.url) === '') throw new Error('not https');
    return r.json();
  };
  const discover = async (origin) => {
    const c = discoCache.get(origin);
    if (c && now() - c.at < DISCOVERY_MAX_AGE_MS) return c.doc;
    const doc = await getJson(origin + WELL_KNOWN_PATH);
    if (!doc || typeof doc.resolve !== 'string' || !Array.isArray(doc.keys)) throw new Error('bad discovery document');
    if (doc.iss !== undefined && doc.iss !== origin) throw new Error('iss is not this origin');
    // Endpoints must stay on the resolver's own origin (a discovery document cannot send the client elsewhere).
    if (originOf(doc.resolve) !== origin || (doc.record && originOf(doc.record) !== origin)) throw new Error('endpoint on another origin');
    discoCache.set(origin, { at: now(), doc });
    return doc;
  };
  const keysFor = (origin, doc) => opts.pinnedKeys?.[origin] || doc.keys;

  /**
   * Ask the resolvers in order; the first one whose answer verifies completely and is not empty answers.
   * Never throws. Returns { resolver, candidates: [{ id, url, status, checked_at, exp, evidence, jws }], errors }.
   * A candidate is advice: connecting to it is the caller's own decision.
   */
  async function resolve(need, constraints = {}) {
    const errors = [];
    const text = String(need || '').replace(/\s+/g, ' ').trim().slice(0, 200);
    if (text.length < 3 || !resolvers.length) return { resolver: null, candidates: [], errors };
    const cq = constraintsParam(constraints);
    const ck = text + '\u0000' + cq;
    const hit = answerCache.get(ck);
    if (hit && hit.until > now()) return { ...hit.value, errors: [] };
    if (hit) answerCache.delete(ck);
    for (const origin of resolvers) {
      try {
        const doc = await discover(origin);
        const u = new URL(doc.resolve);
        u.searchParams.set('need', text);
        if (cq) u.searchParams.set('constraints', cq);
        const body = await getJson(u.toString());
        if (!Array.isArray(body?.candidates)) throw new Error('bad answer');
        const nowS = Math.floor(now() / 1000);
        const keys = keysFor(origin, doc);
        const candidates = [];
        let bad = '';
        for (const c of body.candidates.slice(0, 10)) {
          const v = verifyToken(c?.jws, keys, nowS, { iss: origin });
          if (!v.ok) { bad = v.error; break; }
          if (!usableClaims(v.payload)) { bad = 'malformed'; break; }
          const p = v.payload; // only signed claims are used; the plain fields next to the token are ignored
          candidates.push({ id: p.sub, url: p.url, status: p.status, checked_at: p.checked_at ?? null, exp: p.exp, evidence: p.evidence ?? null, jws: c.jws });
        }
        // Spec 7.3: a resolver that returns anything that does not verify is skipped as a whole.
        if (bad) { errors.push({ resolver: origin, error: 'unverified_candidate: ' + bad }); continue; }
        if (!candidates.length) { errors.push({ resolver: origin, error: 'no_candidates' }); continue; }
        const until = Math.min(...candidates.map((c) => c.exp * 1000));
        const value = { resolver: origin, candidates, errors };
        if (until > now()) answerCache.set(ck, { until, value: { resolver: origin, candidates } });
        return value;
      } catch (e) {
        errors.push({ resolver: origin, error: String(e?.message || e).slice(0, 80) });
      }
    }
    return { resolver: null, candidates: [], errors };
  }

  /** A signed record for one server, by id or url, from the first resolver that verifies. Never throws; null when none. */
  async function record({ id, url } = {}) {
    if (!id && !url) return null;
    for (const origin of resolvers) {
      try {
        const doc = await discover(origin);
        if (!doc.record) continue;
        const u = new URL(doc.record);
        if (id) u.searchParams.set('id', id); else u.searchParams.set('url', url);
        const body = await getJson(u.toString());
        const v = verifyToken(body?.jws, keysFor(origin, doc), Math.floor(now() / 1000), { iss: origin });
        if (v.ok && usableClaims(v.payload)) return { resolver: origin, ...v.payload, jws: body.jws };
      } catch { /* fail open: try the next resolver */ }
    }
    return null;
  }

  return { resolve, record, resolvers: [...resolvers], spec: SPEC, conformance };
}
