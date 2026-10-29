// capability-resolution-check: tests a resolver origin against the requirements of Capability Resolution 0.2
// that can be checked from outside (sections 5, 6, 8 and 9) and reports a level: resolver-1 or not conformant.
// With --server it checks a server declaration file instead (section 13): server-1 or not conformant.
// It only reads: GET requests to the discovery document, resolve, record and policy_url. It sends no user data;
// the need it asks is a fixed sample job unless the caller gives another.
import { createHash, randomBytes } from 'node:crypto';
import { verifyToken, SPEC, SPEC_VERSION, MAX_TTL_S, CLOCK_SKEW_S, STATUSES, JWS_TYP, WELL_KNOWN_PATH } from './index.js';
import { DECLARATION_PATH, DECLARATION_MAX_BYTES, DECLARATION_MAX_AGE_S, parseDeclaration, verifyDeclarationSignature } from './declaration.js';

export const CHECKER_USER_AGENT = `capability-resolution-check/${SPEC_VERSION} (+${SPEC.url})`;
export const DEFAULT_NEED = 'send a transactional email';

// Every rule the checker knows. must: true counts toward the level; must: false (SHOULD) only warns.
export const RULES = [
  ['5.https', '5', true, 'discovery origin uses https'],
  ['5.served', '5', true, 'GET /.well-known/capability-resolver answers 200 without a redirect'],
  ['5.json', '5', true, 'discovery is application/json and parses'],
  ['5.cache', '5', false, 'discovery is cacheable for at most one hour'],
  ['5.fields', '5', true, 'required fields: v "0.2", iss, resolve, record, keys, policy_url'],
  ['5.iss', '5', true, 'iss equals the origin serving the document'],
  ['5.same-origin', '5', true, 'resolve and record are on the iss origin'],
  ['5.keys', '5', true, 'keys are public Ed25519 JWKs (OKP, 32-byte x, kid, no private part)'],
  ['5.kid', '8', false, 'kid is the RFC 7638 thumbprint'],
  ['6.1.answer', '6.1', true, 'resolve answers 200 JSON with a candidates list'],
  ['6.1.max', '6.1', true, 'at most 10 candidates (and no more than max_candidates)'],
  ['6.1.signed', '6.1', true, 'no unsigned candidates'],
  ['6.1.status', '6.1', true, 'status is ok, sign_in, down or unknown'],
  ['6.1.answered', '6.1', false, 'resolve offers only ok and sign_in servers'],
  ['6.1.plain', '6.1', false, 'plain fields match the signed claims'],
  ['6.1.bad-need', '6.1', true, 'a need under 3 or over 200 characters gets 400'],
  ['6.1.errors', '6.1', true, 'errors are non-200 JSON {v, error, note}'],
  ['6.2.unknown', '6.2', true, 'unknown and malformed constraints are ignored, not refused'],
  ['6.2.ignored', '6.2', false, 'ignored constraints are listed in ignored'],
  ['6.2.applied', '6.2', true, 'a listed constraint is applied (no_sign_in gives only ok servers)'],
  ['6.3.by-id', '6.3', true, 'record?id= returns a signed record for a resolved server'],
  ['6.3.by-url', '6.3', true, 'record?url= returns the same server'],
  ['6.3.fields', '6.3', true, 'record claims add name, first_seen, anchor and proof'],
  ['6.3.proof', '6.3', true, 'proof is null or an rfc9162-sha256 inclusion proof'],
  ['6.3.not-found', '6.3', true, 'an unknown server id gets 404'],
  ['6.3.bad-id', '6.3', true, 'a malformed id gets 400'],
  ['8.header', '8', true, 'protected header: alg EdDSA, kid, typ capability-resolver+jws'],
  ['8.signature', '8', true, 'every token verifies with a key from discovery'],
  ['8.claims', '8', true, 'required claims: v, iss, sub, url, status, checked_at, iat, exp, evidence'],
  ['8.iss', '8', true, 'token iss equals the discovery iss'],
  ['8.lifetime', '8', true, 'exp - iat is at most 48 hours'],
  ['8.time', '8', true, 'iat and exp are current (300 s tolerance)'],
  ['8.url', '4, 8', true, 'url is in canonical form'],
  ['8.sub', '4, 8', true, 'sub is <namespace>:<local>, namespace as declared'],
  ['8.no-caller-data', '8, 9.4', true, 'tokens carry no need text, constraints or caller data'],
  ['9.policy', '9', true, 'policy_url answers over https'],
  ['9.never-hosts', '9.3', true, 'candidate URLs are not on the resolver origin'],
  ['9.honest', '9.6', true, 'checked_at is a time no later than signing'],
  ['9.rate-limit', '9.5', false, 'rate limits answer 429 with Retry-After'],
];

const originOf = (u) => { try { return new URL(u).origin; } catch { return ''; } };
const isHttps = (u) => { try { return new URL(u).protocol === 'https:'; } catch { return false; } };
const b64json = (s) => { try { return JSON.parse(Buffer.from(s, 'base64url').toString('utf8')); } catch { return null; } };
const thumb = (x) => createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest('base64url');
const NS_RE = /^[a-z0-9-]{1,32}$/;
const B32 = 'abcdefghijklmnopqrstuvwxyz234567';

// Section 4 canonical form, for checking a signed url.
export function canonicalUrl(raw) {
  try {
    const u = new URL(raw);
    if (u.protocol !== 'https:' || u.username || u.password) return '';
    const host = u.hostname.toLowerCase().replace(/^www\./, '') + (u.port && u.port !== '443' ? ':' + u.port : '');
    return 'https://' + host + u.pathname.replace(/\/+$/, '');
  } catch { return ''; }
}

/**
 * Check one resolver. Never throws for network problems; they become failed rules.
 * @param {string} target the resolver origin (any URL on it)
 * @param {{ fetch?: typeof fetch, need?: string, timeoutMs?: number, now?: () => number }} [opts]
 */
export async function checkResolver(target, opts = {}) {
  const doFetch = opts.fetch || globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? 10000;
  const now = opts.now || Date.now;
  const need = String(opts.need || DEFAULT_NEED).replace(/\s+/g, ' ').trim();
  const res = new Map(); // id -> { result, detail }
  const set = (id, ok, detail = '') => { const prev = res.get(id); if (prev?.result === 'fail') return; res.set(id, { result: ok ? 'pass' : 'fail', detail: ok ? (prev?.detail || detail) : detail }); };
  const skip = (id, detail) => { if (!res.has(id)) res.set(id, { result: 'skip', detail }); };

  const get = async (url) => {
    try {
      const r = await doFetch(url, { headers: { accept: 'application/json', 'user-agent': CHECKER_USER_AGENT }, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
      const text = await r.text().catch(() => '');
      let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
      const h = (n) => (r.headers?.get ? r.headers.get(n) : null) || '';
      return { status: r.status, type: h('content-type'), cache: h('cache-control'), location: h('location'), json };
    } catch (e) { return { status: 0, error: String(e?.cause?.code || e?.message || e).slice(0, 100) }; }
  };
  const errShape = (r) => r.status !== 200 && r.json && typeof r.json === 'object' && typeof r.json.v === 'string' && typeof r.json.error === 'string' && typeof r.json.note === 'string';

  const origin = originOf(target);
  const finish = () => report(origin || String(target), res, now);
  if (!origin) { set('5.https', false, 'not a URL'); return finish(); }
  if (!isHttps(origin)) { set('5.https', false, 'plain http; a client must not use it'); return finish(); }
  set('5.https', true);

  // ---- section 5: discovery
  const d = await get(origin + WELL_KNOWN_PATH);
  if (d.status !== 200) { set('5.served', false, d.status ? `HTTP ${d.status}${d.location ? ' to ' + d.location : ''}` : d.error); return finish(); }
  set('5.served', true);
  const doc = d.json;
  if (!/^application\/json\b/i.test(d.type) || !doc || typeof doc !== 'object') { set('5.json', false, `content-type "${d.type}"`); return finish(); }
  set('5.json', true);
  const maxAge = /max-age=(\d+)/i.exec(d.cache)?.[1];
  if (maxAge === undefined) set('5.cache', false, 'no Cache-Control max-age'); else set('5.cache', Number(maxAge) <= 3600, `max-age=${maxAge}`);
  const missing = ['iss', 'resolve', 'record', 'policy_url'].filter((k) => typeof doc[k] !== 'string' || !doc[k]);
  if (doc.v !== SPEC_VERSION) missing.unshift(`v (${JSON.stringify(doc.v)})`);
  if (!Array.isArray(doc.keys) || !doc.keys.length) missing.push('keys');
  set('5.fields', !missing.length, missing.length ? 'missing or wrong: ' + missing.join(', ') : '');
  set('5.iss', doc.iss === origin, doc.iss === origin ? '' : `iss ${JSON.stringify(doc.iss)} but served from ${origin}`);
  const offOrigin = ['resolve', 'record'].filter((k) => typeof doc[k] === 'string' && originOf(doc[k]) !== origin);
  set('5.same-origin', !offOrigin.length && !missing.includes('resolve') && !missing.includes('record'), offOrigin.map((k) => `${k} is ${doc[k]}`).join('; '));
  const keys = Array.isArray(doc.keys) ? doc.keys : [];
  const badKeys = keys.filter((k) => !k || k.kty !== 'OKP' || k.crv !== 'Ed25519' || typeof k.x !== 'string' || Buffer.from(k.x, 'base64url').length !== 32 || typeof k.kid !== 'string' || !k.kid || 'd' in k);
  set('5.keys', keys.length > 0 && !badKeys.length, badKeys.length ? `${badKeys.length} key(s) not public Ed25519 JWKs with kid` : (keys.length ? '' : 'no keys'));
  const notThumb = keys.filter((k) => k && typeof k.x === 'string' && k.kid !== thumb(k.x));
  set('5.kid', !notThumb.length, notThumb.length ? `${notThumb.length} kid(s) are not RFC 7638 thumbprints` : '');
  const ns = typeof doc.id_namespace === 'string' ? doc.id_namespace : null;

  // ---- section 9: policy page
  if (typeof doc.policy_url !== 'string' || !isHttps(doc.policy_url)) set('9.policy', false, 'policy_url missing or not https');
  else {
    try {
      const p = await doFetch(doc.policy_url, { headers: { 'user-agent': CHECKER_USER_AGENT }, signal: AbortSignal.timeout(timeoutMs) });
      set('9.policy', p.ok, p.ok ? '' : `HTTP ${p.status}`);
    } catch (e) { set('9.policy', false, String(e?.message || e).slice(0, 80)); }
  }
  skip('9.rate-limit', 'not tested: needs load; only checked if a 429 is seen');

  if (missing.length || offOrigin.length || !keys.length) return finish();
  const nowS = () => Math.floor(now() / 1000);

  // Every token the checker sees goes through the section 8 rules.
  const tokens = [];
  const probe = 'x-check-' + randomBytes(6).toString('hex'); // an unknown constraint: caller data that must not reach a token
  const checkToken = (jws, where, forbidden) => {
    const p = String(jws || '').split('.');
    const head = b64json(p[0] || ''), body = b64json(p[1] || '');
    set('8.header', !!head && head.alg === 'EdDSA' && typeof head.kid === 'string' && !!head.kid && head.typ === JWS_TYP, `${where}: header ${JSON.stringify(head)}`);
    const v = verifyToken(jws, keys, nowS());
    const sigOk = v.ok || ['ttl_too_long', 'expired', 'not_yet_valid'].includes(v.error);
    set('8.signature', sigOk, `${where}: ${v.error}`);
    if (!body || typeof body !== 'object') { set('8.claims', false, `${where}: payload is not JSON`); return null; }
    tokens.push(body);
    const need8 = ['v', 'iss', 'sub', 'url', 'status', 'checked_at', 'iat', 'exp', 'evidence'].filter((k) => !(k in body));
    const types = Number.isFinite(body.iat) && Number.isFinite(body.exp) && typeof body.sub === 'string' && typeof body.url === 'string' && STATUSES.includes(body.status) && body.evidence && typeof body.evidence === 'object';
    set('8.claims', !need8.length && types, `${where}: ${need8.length ? 'missing ' + need8.join(', ') : 'wrong claim types'}`);
    set('8.iss', body.iss === doc.iss, `${where}: iss ${JSON.stringify(body.iss)}`);
    if (Number.isFinite(body.iat) && Number.isFinite(body.exp)) {
      set('8.lifetime', body.exp - body.iat <= MAX_TTL_S && body.exp > body.iat, `${where}: lifetime ${body.exp - body.iat} s`);
      set('8.time', body.iat <= nowS() + CLOCK_SKEW_S && body.exp >= nowS() - CLOCK_SKEW_S, `${where}: iat ${body.iat}, exp ${body.exp}, now ${nowS()}`);
    }
    if (typeof body.url === 'string') {
      set('8.url', canonicalUrl(body.url) === body.url, `${where}: ${body.url} is not canonical`);
      const host = (() => { try { return new URL(body.url).hostname.replace(/^www\./, ''); } catch { return ''; } })();
      set('9.never-hosts', host && host !== new URL(origin).hostname.replace(/^www\./, ''), `${where}: ${body.url} is on the resolver host`);
    }
    if (typeof body.sub === 'string') {
      const m = /^([^:]+):(.+)$/.exec(body.sub);
      set('8.sub', !!m && NS_RE.test(m[1]) && (!ns || m[1] === ns), `${where}: sub ${JSON.stringify(body.sub)}${ns ? ', namespace ' + ns : ''}`);
    }
    const ca = Date.parse(body.checked_at);
    if (body.checked_at === null) set('9.honest', true); // no check on file: no claim made
    else set('9.honest', Number.isFinite(ca) && Number.isFinite(body.iat) && ca / 1000 <= body.iat + CLOCK_SKEW_S, `${where}: checked_at ${JSON.stringify(body.checked_at)} after iat`);
    // No caller data: no query-like claim names, no need text, no constraint text.
    const flat = JSON.stringify({ head, body: { ...body, url: undefined, sub: undefined, evidence: undefined } }).toLowerCase();
    const badKey = ['need', 'constraints', 'query', 'q', 'ip', 'caller', 'user', 'user_agent'].find((k) => k in body);
    const leaked = forbidden.find((f) => f && flat.includes(f.toLowerCase()));
    set('8.no-caller-data', !badKey && !leaked, `${where}: ${badKey ? 'claim "' + badKey + '"' : 'contains "' + leaked + '"'}`);
    return body;
  };

  // ---- section 6.1: resolve
  const rurl = (q) => { const u = new URL(doc.resolve); for (const [k, v] of Object.entries(q)) u.searchParams.set(k, v); return u.toString(); };
  const r = await get(rurl({ need }));
  const errorsSeen = [];
  if (r.status === 429) set('9.rate-limit', true, 'saw 429');
  let cands = [];
  if (r.status !== 200 || !r.json || !Array.isArray(r.json.candidates)) set('6.1.answer', false, r.status ? `HTTP ${r.status}` : r.error);
  else {
    set('6.1.answer', true);
    cands = r.json.candidates;
    const cap = Math.min(10, Number.isInteger(doc.max_candidates) ? doc.max_candidates : 10);
    set('6.1.max', cands.length <= cap, `${cands.length} candidates`);
    set('6.1.signed', cands.every((c) => typeof c?.jws === 'string' && c.jws.split('.').length === 3), 'a candidate has no jws');
    for (const [i, c] of cands.entries()) {
      if (typeof c?.jws !== 'string') continue;
      const body = checkToken(c.jws, `candidate ${i + 1}`, [need]);
      if (!body) continue;
      set('6.1.status', STATUSES.includes(body.status), `candidate ${i + 1}: status ${JSON.stringify(body.status)}`);
      set('6.1.answered', body.status === 'ok' || body.status === 'sign_in', `candidate ${i + 1}: ${body.status}`);
      set('6.1.plain', c.id === body.sub && c.url === body.url && c.status === body.status, `candidate ${i + 1}: plain fields differ from the token`);
    }
    if (!cands.length) for (const id of ['6.1.signed', '6.1.status', '6.1.answered', '6.1.plain']) skip(id, `no candidates for "${need}"; try --need`);
  }

  // Bad requests.
  const short = await get(rurl({ need: 'ab' }));
  const long = await get(rurl({ need: 'x'.repeat(201) }));
  set('6.1.bad-need', short.status === 400 && long.status === 400, `short need: HTTP ${short.status}, 201 characters: HTTP ${long.status}`);
  errorsSeen.push(['short need', short], ['long need', long]);

  // ---- section 6.2: constraints
  const u = await get(rurl({ need, constraints: `${probe},max_ms:abc` }));
  if (u.status === 200 && u.json && Array.isArray(u.json.candidates)) {
    set('6.2.unknown', true);
    const ign = Array.isArray(u.json.ignored) ? u.json.ignored : [];
    set('6.2.ignored', ign.includes(probe) && ign.includes('max_ms:abc'), `ignored: ${JSON.stringify(u.json.ignored ?? null)}`);
    for (const [i, c] of u.json.candidates.entries()) if (typeof c?.jws === 'string') checkToken(c.jws, `unknown-constraint candidate ${i + 1}`, [need, probe, 'max_ms:abc']);
  } else set('6.2.unknown', false, `HTTP ${u.status || u.error} for an unknown constraint`);
  const listed = Array.isArray(doc.constraints) ? doc.constraints : [];
  if (listed.includes('no_sign_in')) {
    const n = await get(rurl({ need, constraints: 'no_sign_in' }));
    if (n.status !== 200 || !Array.isArray(n.json?.candidates)) set('6.2.applied', false, `HTTP ${n.status || n.error}`);
    else {
      const sts = n.json.candidates.map((c) => b64json(String(c?.jws || '').split('.')[1] || '')?.status);
      set('6.2.applied', sts.every((s) => s === 'ok'), `no_sign_in returned statuses ${JSON.stringify(sts)}`);
      for (const [i, c] of n.json.candidates.entries()) if (typeof c?.jws === 'string') checkToken(c.jws, `no_sign_in candidate ${i + 1}`, [need, 'no_sign_in']);
    }
  } else skip('6.2.applied', 'discovery lists no testable constraint');

  // ---- section 6.3: record
  const first = cands.map((c) => b64json(String(c?.jws || '').split('.')[1] || '')).find((b) => b && typeof b.sub === 'string');
  const recUrl = (q) => { const x = new URL(doc.record); for (const [k, v] of Object.entries(q)) x.searchParams.set(k, v); return x.toString(); };
  if (first) {
    const byId = await get(recUrl({ id: first.sub }));
    const okRec = (rr) => rr.status === 200 && typeof rr.json?.jws === 'string';
    if (!okRec(byId)) set('6.3.by-id', false, `HTTP ${byId.status || byId.error}`);
    else {
      const b = checkToken(byId.json.jws, 'record by id', [need]);
      set('6.3.by-id', !!b && b.sub === first.sub, `record sub ${JSON.stringify(b?.sub)}`);
      if (b) {
        const lack = ['name', 'first_seen', 'anchor', 'proof'].filter((k) => !(k in b));
        set('6.3.fields', !lack.length, 'missing ' + lack.join(', '));
        const pr = b.proof;
        set('6.3.proof', pr === null || (pr && pr.type === 'rfc9162-sha256' && Number.isInteger(pr.leaf_index) && Number.isInteger(pr.tree_size) && Array.isArray(pr.path)), `proof ${JSON.stringify(pr)}`);
      }
    }
    const byUrl = await get(recUrl({ url: first.url }));
    if (!okRec(byUrl)) set('6.3.by-url', false, `HTTP ${byUrl.status || byUrl.error}`);
    else { const b = checkToken(byUrl.json.jws, 'record by url', [need]); set('6.3.by-url', !!b && b.sub === first.sub, `record sub ${JSON.stringify(b?.sub)} for ${first.url}`); }
  } else for (const id of ['6.3.by-id', '6.3.by-url', '6.3.fields', '6.3.proof']) skip(id, 'no candidate to look up');
  const unknownId = `${ns || (first?.sub || 'x:').split(':')[0] || 'x'}:${Array.from(randomBytes(16), (b) => B32[b & 31]).join('')}`;
  const nf = await get(recUrl({ id: unknownId }));
  set('6.3.not-found', nf.status === 404, `HTTP ${nf.status || nf.error} for ${unknownId}`);
  const bad = await get(recUrl({ id: 'not an id' }));
  set('6.3.bad-id', bad.status === 400, `HTTP ${bad.status || bad.error}`);
  errorsSeen.push(['unknown id', nf], ['malformed id', bad]);
  for (const [what, e] of errorsSeen) if (e.status && e.status !== 200) set('6.1.errors', errShape(e), `${what}: HTTP ${e.status} body ${JSON.stringify(e.json)?.slice(0, 80)}`);
  if (!tokens.length) for (const id of ['8.header', '8.signature', '8.claims', '8.iss', '8.lifetime', '8.time', '8.url', '8.sub', '8.no-caller-data', '9.never-hosts', '9.honest']) skip(id, 'no token to check');
  return finish();
}

function report(origin, res, now) {
  const rules = RULES.map(([id, section, must, title]) => {
    const r = res.get(id) || { result: 'skip', detail: 'not reached (an earlier rule failed)' };
    const result = r.result === 'fail' && !must ? 'warn' : r.result;
    return { id, section, must, title, result, ...(result === 'pass' || !r.detail ? {} : { detail: r.detail }) };
  });
  const failed = rules.filter((r) => r.must && r.result === 'fail');
  const untested = rules.filter((r) => r.must && r.result === 'skip');
  const level = !failed.length && !untested.length ? 'resolver-1' : 'not conformant';
  return {
    spec: SPEC.text,
    origin,
    checked_at: new Date(now()).toISOString(),
    level,
    counts: { pass: rules.filter((r) => r.result === 'pass').length, fail: failed.length, warn: rules.filter((r) => r.result === 'warn').length, not_tested: rules.filter((r) => r.result === 'skip').length },
    note: 'resolver-1 also needs at least one binding stated at policy_url and the section 9 obligations that cannot be seen from outside (neutrality, method changelog, log handling), and reading each listed server\'s declaration file (13.3, 13.4). This check covers what can be tested over HTTP.',
    rules,
  };
}

export function formatReport(rep) {
  const L = { pass: 'PASS', fail: 'FAIL', warn: 'WARN', skip: 'SKIP' };
  const lines = [`${rep.spec}`, `${rep.mode === 'server' ? 'Server declaration' : 'Resolver'}: ${rep.origin}   checked ${rep.checked_at}`, ''];
  for (const r of rep.rules) lines.push(`${L[r.result]}  ${('§' + r.section).padEnd(8)} ${r.must ? 'MUST  ' : 'SHOULD'}  ${r.title}${r.detail ? '\n                         ' + r.detail : ''}`);
  lines.push('', `Level: ${rep.level}  (${rep.counts.pass} passed, ${rep.counts.fail} failed, ${rep.counts.warn} warnings, ${rep.counts.not_tested} not tested)`);
  return lines.join('\n');
}

// ---------------------------------------------------------------- server declaration file (section 13)
// capability-resolution-check --server <origin>: fetches https://<origin>/.well-known/capabilities.txt the way a
// resolver must (13.4: https only, same-origin redirects only, size cap) and checks it. Level server-1 or not
// conformant. It does not connect to the declared servers: the file is a claim; observing them is a resolver's job.
export const SERVER_RULES = [
  ['13.https', '13.4', true, 'origin uses https'],
  ['13.served', '13.4', true, `GET ${DECLARATION_PATH} answers 200 (redirects only on the same origin, at most 3)`],
  ['13.type', '13.1', true, 'content-type is text/plain'],
  ['13.charset', '13.1', false, 'content-type names charset=utf-8'],
  ['13.size', '13.4', true, `at most ${DECLARATION_MAX_BYTES} bytes, valid UTF-8`],
  ['13.cache', '13.4', false, 'Cache-Control max-age is at most 24 hours'],
  ['13.lines', '13.1', false, 'every line is a comment, blank or "Field: value"'],
  ['13.conformance', '13.2', true, 'one Conformance: Capability Resolution <version>'],
  ['13.version', '13.2', false, `the version is ${SPEC_VERSION}`],
  ['13.contact', '13.2', true, 'at least one Contact (mailto:, https: or tel:)'],
  ['13.expires', '13.2', true, 'one Expires, an RFC 3339 date-time in the future'],
  ['13.expires-year', '13.2', false, 'Expires is at most a year ahead'],
  ['13.endpoints', '13.2', true, 'at least one Endpoint; each is https, without credentials, listed once'],
  ['13.endpoint-host', '13.3', true, 'each Endpoint is on the file host or a subdomain of it'],
  ['13.protocol', '13.2', true, 'each server has one Protocol token'],
  ['13.jobs', '13.2', true, 'each server has Jobs of 3 to 200 characters'],
  ['13.access', '13.2', false, 'each server states Sign-in and Payment'],
  ['13.values', '13.2', true, 'Sign-in, Payment, Card and Resolvers values are valid'],
  ['13.signature', '13.5', true, 'a Signature, when present, verifies with a key from its jku on the same origin'],
];

/**
 * Check one server origin's declaration file. Never throws for network problems.
 * @param {string} target the origin (any URL on it)
 * @param {{ fetch?: typeof fetch, timeoutMs?: number, now?: () => number }} [opts]
 */
export async function checkServer(target, opts = {}) {
  const doFetch = opts.fetch || globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? 10000;
  const now = opts.now || Date.now;
  const res = new Map();
  const set = (id, ok, detail = '') => { const prev = res.get(id); if (prev?.result === 'fail') return; res.set(id, { result: ok ? 'pass' : 'fail', detail: ok ? '' : detail }); };
  const skip = (id, detail) => { if (!res.has(id)) res.set(id, { result: 'skip', detail }); };
  const origin = originOf(target);
  const finish = (decl) => serverReport(origin || String(target), res, now, decl);
  if (!origin) { set('13.https', false, 'not a URL'); return finish(null); }
  if (!isHttps(origin)) { set('13.https', false, 'plain http; resolvers must not read it'); return finish(null); }
  set('13.https', true);

  // 13.4: fetch, following at most 3 redirects and only on the same origin.
  let url = origin + DECLARATION_PATH, r = null;
  for (let hop = 0; hop <= 3; hop++) {
    try { r = await doFetch(url, { headers: { accept: 'text/plain', 'user-agent': CHECKER_USER_AGENT }, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) }); }
    catch (e) { set('13.served', false, String(e?.cause?.code || e?.message || e).slice(0, 100)); return finish(null); }
    if (r.status < 300 || r.status > 399) break;
    const loc = r.headers.get('location') || '';
    let next = ''; try { next = new URL(loc, url).toString(); } catch { /* bad location */ }
    if (!next || originOf(next) !== origin) { set('13.served', false, `HTTP ${r.status} to ${loc || '(no location)'}: off-origin redirects are not followed`); return finish(null); }
    if (hop === 3) { set('13.served', false, 'more than 3 redirects'); return finish(null); }
    url = next;
  }
  if (r.status !== 200) { set('13.served', false, `HTTP ${r.status}`); return finish(null); }
  set('13.served', true);
  const type = r.headers.get('content-type') || '';
  set('13.type', /^text\/plain\b/i.test(type), `content-type "${type}"`);
  set('13.charset', /charset=utf-8/i.test(type), `content-type "${type}"`);
  const maxAge = /max-age=(\d+)/i.exec(r.headers.get('cache-control') || '')?.[1];
  set('13.cache', maxAge !== undefined && Number(maxAge) <= DECLARATION_MAX_AGE_S, maxAge === undefined ? 'no Cache-Control max-age' : `max-age=${maxAge}`);
  const bytes = new Uint8Array(await r.arrayBuffer().catch(() => new ArrayBuffer(0)));
  if (bytes.length > DECLARATION_MAX_BYTES) { set('13.size', false, `${bytes.length} bytes`); return finish(null); }
  const decl = parseDeclaration(bytes, { origin, now: now() });
  if (decl.errors.includes('not valid UTF-8')) { set('13.size', false, 'not valid UTF-8'); return finish(decl); }
  set('13.size', true);

  const rule = (id, re) => { const e = decl.errors.filter((x) => re.test(x)); set(id, !e.length, e.join('; ')); };
  const warn = (id, re) => { const w = decl.warnings.filter((x) => re.test(x)); set(id, !w.length, w.join('; ')); };
  warn('13.lines', /not a "Field: value"/);
  rule('13.conformance', /Conformance/);
  set('13.version', decl.version === SPEC_VERSION, `version ${JSON.stringify(decl.version)}`);
  rule('13.contact', /Contact/);
  rule('13.expires', /Expires/);
  warn('13.expires-year', /year ahead/);
  rule('13.endpoints', /Endpoint must|no Endpoint|listed twice|before any Endpoint|after Signature/);
  rule('13.endpoint-host', /or a subdomain of it/);
  rule('13.protocol', /Protocol/);
  rule('13.jobs', /Jobs/);
  warn('13.access', /has no (Sign-in|Payment)/);
  rule('13.values', /Sign-in|Payment|Card|Resolvers|has no value/);

  // 13.5: the optional signature; its key set must be on the same origin.
  if (decl.signature === null) skip('13.signature', 'no Signature (optional)');
  else {
    let head = null; try { head = JSON.parse(Buffer.from(decl.signature.split('.')[0], 'base64url').toString('utf8')); } catch { /* malformed */ }
    const jku = typeof head?.jku === 'string' ? head.jku : '';
    if (!jku || originOf(jku) !== origin) set('13.signature', false, `jku ${JSON.stringify(jku)} is not on ${origin}`);
    else {
      let keys = [];
      try {
        const k = await doFetch(jku, { headers: { accept: 'application/json', 'user-agent': CHECKER_USER_AGENT }, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
        keys = k.status === 200 ? (await k.json())?.keys || [] : [];
      } catch { /* keys stay empty */ }
      const v = verifyDeclarationSignature(decl, keys);
      set('13.signature', v.ok, v.ok ? '' : v.error);
    }
  }
  return finish(decl);
}

function serverReport(origin, res, now, decl) {
  const rules = SERVER_RULES.map(([id, section, must, title]) => {
    const r = res.get(id) || { result: 'skip', detail: 'not reached (an earlier rule failed)' };
    const result = r.result === 'fail' && !must ? 'warn' : r.result;
    return { id, section, must, title, result, ...(result === 'pass' || !r.detail ? {} : { detail: r.detail }) };
  });
  const failed = rules.filter((r) => r.must && r.result === 'fail');
  const untested = rules.filter((r) => r.must && r.result === 'skip' && r.id !== '13.signature');
  const level = !failed.length && !untested.length ? 'server-1' : 'not conformant';
  return {
    spec: SPEC.text,
    mode: 'server',
    origin,
    checked_at: new Date(now()).toISOString(),
    level,
    counts: { pass: rules.filter((r) => r.result === 'pass').length, fail: failed.length, warn: rules.filter((r) => r.result === 'warn').length, not_tested: rules.filter((r) => r.result === 'skip').length },
    servers: decl?.servers || [],
    resolvers: decl ? decl.resolvers : null,
    note: 'server-1 means the file is valid. It is a claim: resolvers still observe each server before they report a status.',
    rules,
  };
}
