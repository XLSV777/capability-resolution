// Server declaration file (Capability Resolution 0.2, section 13): a plain-text file a server owner publishes at
// https://<host>/.well-known/capabilities.txt. This module parses it, answers "may this resolver list these
// servers?" and verifies the optional signature. Node 18+ built-ins only; no network.
//
//   import { parseDeclaration, resolverAllowed } from 'capability-resolver-client/declaration';
//   const d = parseDeclaration(text, { origin: 'https://example.com' });
//   if (d.ok && resolverAllowed(d, 'https://resolver.example')) { ...the servers in d.servers are claims to verify... }
//
// The file is a claim, not proof: a resolver still observes every server before it reports a status.
import { createPublicKey, verify } from 'node:crypto';

export const DECLARATION_PATH = '/.well-known/capabilities.txt';
export const DECLARATION_MAX_BYTES = 32 * 1024;
export const DECLARATION_MAX_AGE_S = 86400; // a resolver never uses a copy older than 24 hours
export const DECLARATION_TYP = 'capabilities-txt+jws';
export const SIGN_IN_VALUES = Object.freeze(['none', 'optional', 'required']);
export const PAYMENT_VALUES = Object.freeze(['none', 'any']);
const SPEC_NAME = 'Capability Resolution';
const FIELD_RE = /^([A-Za-z][A-Za-z0-9-]*)[ \t]*:[ \t]*(.*?)[ \t]*$/;
const PROTOCOL_RE = /^[a-z][a-z0-9-]{0,31}$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/i;
const FILE_FIELDS = ['conformance', 'contact', 'expires', 'resolvers', 'signature'];
const SERVER_FIELDS = ['endpoint', 'protocol', 'jobs', 'sign-in', 'payment', 'card'];

const originOf = (u) => { try { const x = new URL(u); return x.protocol === 'https:' ? x.origin : ''; } catch { return ''; } };
/** True when host is the file's host or a subdomain of it (the hosts one file may speak for). */
export function coveredHost(host, fileHost) {
  const h = String(host || '').toLowerCase().replace(/^www\./, ''), f = String(fileHost || '').toLowerCase().replace(/^www\./, '');
  return !!h && !!f && (h === f || h.endsWith('.' + f));
}
function canonical(raw) {
  try {
    const u = new URL(raw);
    if (u.protocol !== 'https:' || u.username || u.password) return '';
    const host = u.hostname.toLowerCase().replace(/^www\./, '') + (u.port && u.port !== '443' ? ':' + u.port : '');
    return 'https://' + host + u.pathname.replace(/\/+$/, '');
  } catch { return ''; }
}

/**
 * Parse a declaration file. Never throws.
 * @param {string | Uint8Array} input the file body
 * @param {{ origin?: string, now?: number }} [opts] origin: where the file was fetched (endpoints must be on its
 *   host or a subdomain); now: ms, for the expiry check
 * @returns {{ ok: boolean, errors: string[], warnings: string[], version: string|null, contacts: string[],
 *   expires: string|null, expired: boolean, resolvers: { all: boolean, none: boolean, allow: string[], deny: string[] },
 *   servers: { endpoint: string, protocol: string|null, jobs: string[], sign_in: string|null, payment: string|null, cards: string[] }[],
 *   signature: string|null, signed_text: string|null, unknown: string[] }}
 */
export function parseDeclaration(input, opts = {}) {
  const errors = [], warnings = [];
  const out = { ok: false, errors, warnings, version: null, contacts: [], expires: null, expired: false, resolvers: { all: true, none: false, allow: [], deny: [] }, servers: [], signature: null, signed_text: null, unknown: [] };
  let text;
  if (typeof input === 'string') text = input;
  else {
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(input); } catch { errors.push('not valid UTF-8'); return out; }
  }
  if (Buffer.byteLength(text, 'utf8') > DECLARATION_MAX_BYTES) { errors.push(`larger than ${DECLARATION_MAX_BYTES} bytes`); return out; }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const fileHost = opts.origin ? (() => { try { return new URL(opts.origin).hostname; } catch { return ''; } })() : '';
  const now = opts.now ?? Date.now();

  let server = null, conformance = 0, expires = 0, resolverLines = 0, offset = 0;
  const lines = text.split(/(?<=\n)/);
  for (const [i, raw] of lines.entries()) {
    const lineStart = offset; offset += raw.length;
    const line = raw.replace(/\r?\n$/, '');
    const n = i + 1;
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    if (out.signature !== null) { errors.push(`line ${n}: content after Signature`); continue; }
    const m = FIELD_RE.exec(line);
    if (!m) { warnings.push(`line ${n}: not a "Field: value" line, ignored`); continue; }
    const name = m[1].toLowerCase(), value = m[2];
    if (!value) { errors.push(`line ${n}: ${m[1]} has no value`); continue; }
    if (SERVER_FIELDS.includes(name) && name !== 'endpoint' && !server) { errors.push(`line ${n}: ${m[1]} before any Endpoint`); continue; }
    switch (name) {
      case 'conformance': {
        conformance++;
        const cm = /^Capability Resolution (\d+\.\d+)$/.exec(value);
        if (!cm) errors.push(`line ${n}: Conformance must be "${SPEC_NAME} <version>"`); else out.version = cm[1];
        break;
      }
      case 'contact':
        if (!/^(mailto:[^\s@]+@[^\s@]+|https:\/\/\S+|tel:\+?[0-9-]+)$/i.test(value)) errors.push(`line ${n}: Contact must be a mailto:, https: or tel: URI`);
        else out.contacts.push(value);
        break;
      case 'expires': {
        expires++;
        const t = Date.parse(value);
        if (!RFC3339_RE.test(value) || !Number.isFinite(t)) { errors.push(`line ${n}: Expires must be an RFC 3339 date-time`); break; }
        out.expires = new Date(t).toISOString();
        if (t <= now) { out.expired = true; errors.push(`line ${n}: Expires is in the past`); }
        else if (t - now > 366 * 86400_000) warnings.push(`line ${n}: Expires is more than a year ahead`);
        break;
      }
      case 'resolvers': {
        resolverLines++;
        if (resolverLines === 1) out.resolvers.all = false;
        for (const tok of value.split(/[\s,]+/).filter(Boolean)) {
          if (tok === '*') out.resolvers.all = true;
          else if (tok.toLowerCase() === 'none') out.resolvers.none = true;
          else {
            const deny = tok.startsWith('-');
            const o = originOf(deny ? tok.slice(1) : tok);
            if (!o || o !== (deny ? tok.slice(1) : tok).replace(/\/$/, '').toLowerCase()) { errors.push(`line ${n}: Resolvers entry "${tok}" is not *, none, an https origin or -origin`); continue; }
            (deny ? out.resolvers.deny : out.resolvers.allow).push(o);
          }
        }
        break;
      }
      case 'signature':
        out.signature = value; out.signed_text = text.slice(0, lineStart);
        break;
      case 'endpoint': {
        const cu = canonical(value);
        server = { endpoint: cu || value, protocol: null, jobs: [], sign_in: null, payment: null, cards: [], line: n };
        out.servers.push(server);
        if (!cu) errors.push(`line ${n}: Endpoint must be an https URL without credentials`);
        else if (fileHost && !coveredHost(new URL(cu).hostname, fileHost)) errors.push(`line ${n}: Endpoint ${cu} is not on ${fileHost} or a subdomain of it`);
        break;
      }
      case 'protocol':
        if (server.protocol) errors.push(`line ${n}: a second Protocol for ${server.endpoint}`);
        else if (!PROTOCOL_RE.test(value)) errors.push(`line ${n}: Protocol must be a lower-case token such as mcp`);
        else server.protocol = value;
        break;
      case 'jobs':
        if (value.length < 3 || value.length > 200) errors.push(`line ${n}: Jobs must be 3 to 200 characters`);
        else server.jobs.push(value);
        break;
      case 'sign-in':
        if (server.sign_in) errors.push(`line ${n}: a second Sign-in for ${server.endpoint}`);
        else if (!SIGN_IN_VALUES.includes(value.toLowerCase())) errors.push(`line ${n}: Sign-in must be ${SIGN_IN_VALUES.join(', ')}`);
        else server.sign_in = value.toLowerCase();
        break;
      case 'payment':
        if (server.payment) errors.push(`line ${n}: a second Payment for ${server.endpoint}`);
        else if (!PAYMENT_VALUES.includes(value.toLowerCase())) errors.push(`line ${n}: Payment must be none or any`);
        else server.payment = value.toLowerCase();
        break;
      case 'card':
        if (!originOf(value)) errors.push(`line ${n}: Card must be an https URL`);
        else server.cards.push(value);
        break;
      default:
        out.unknown.push(m[1]);
    }
  }
  if (conformance !== 1) errors.push(conformance ? 'Conformance appears more than once' : 'Conformance is missing');
  if (!out.contacts.length && !errors.some((e) => e.includes('Contact'))) errors.push('Contact is missing');
  if (expires !== 1) errors.push(expires ? 'Expires appears more than once' : 'Expires is missing');
  if (!out.servers.length) errors.push('no Endpoint');
  for (const s of out.servers) {
    if (!s.protocol) errors.push(`line ${s.line}: ${s.endpoint} has no Protocol`);
    if (!s.jobs.length) errors.push(`line ${s.line}: ${s.endpoint} has no Jobs`);
    if (!s.sign_in) warnings.push(`line ${s.line}: ${s.endpoint} has no Sign-in`);
    if (!s.payment) warnings.push(`line ${s.line}: ${s.endpoint} has no Payment`);
    delete s.line;
  }
  const seen = new Set();
  for (const s of out.servers) { if (seen.has(s.endpoint)) errors.push(`${s.endpoint} is listed twice`); seen.add(s.endpoint); }
  out.ok = !errors.length;
  return out;
}

/**
 * May this resolver check and list the servers in the file (section 13.3)? A deny always wins, also in a file that
 * is expired or otherwise invalid; no file at all means no restriction from this file.
 * @param {ReturnType<typeof parseDeclaration> | null} decl
 * @param {string} resolverOrigin the resolver's iss
 */
export function resolverAllowed(decl, resolverOrigin) {
  if (!decl) return true;
  const o = originOf(resolverOrigin);
  const r = decl.resolvers;
  if (r.none || (o && r.deny.includes(o))) return false;
  return r.all || (!!o && r.allow.includes(o));
}

/**
 * Verify the optional Signature (section 13.5): a compact JWS with a detached payload over every byte of the file
 * before the Signature line, EdDSA (Ed25519), typ capabilities-txt+jws, its key in the JWK set named by jku.
 * @param {ReturnType<typeof parseDeclaration>} decl
 * @param {object[]} keys the JWKs from jku
 * @returns {{ ok: true, kid: string } | { ok: false, error: string }}
 */
export function verifyDeclarationSignature(decl, keys) {
  const p = String(decl?.signature || '').split('.');
  if (p.length !== 3 || p[1] !== '') return { ok: false, error: 'malformed' };
  let head;
  try { head = JSON.parse(Buffer.from(p[0], 'base64url').toString('utf8')); } catch { return { ok: false, error: 'malformed' }; }
  if (head?.alg !== 'EdDSA' || head?.typ !== DECLARATION_TYP || typeof head?.kid !== 'string' || typeof head?.jku !== 'string') return { ok: false, error: 'wrong_header' };
  const jwk = (Array.isArray(keys) ? keys : []).find((k) => k?.kid === head.kid && k.kty === 'OKP' && k.crv === 'Ed25519');
  if (!jwk) return { ok: false, error: 'unknown_key' };
  try {
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' });
    const input = Buffer.from(`${p[0]}.${Buffer.from(decl.signed_text, 'utf8').toString('base64url')}`);
    if (!verify(null, input, key, Buffer.from(p[2], 'base64url'))) return { ok: false, error: 'bad_signature' };
  } catch { return { ok: false, error: 'bad_signature' }; }
  return { ok: true, kid: head.kid };
}
