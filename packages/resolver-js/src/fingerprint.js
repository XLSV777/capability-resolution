// Tool fingerprint (Capability Resolution 0.3, sections 8.1 and 15): a short hash of the tool list a resolver
// observed. After connecting, a client computes the same hash from its own tools/list and compares. A mismatch means
// the server's tools changed since the resolver looked (drift), so the resolver's claim does not apply.
// Node 18+ built-ins only.
import { createHash } from 'node:crypto';

export const TFP_PREFIX = 'sha-256:';
/** "sha-256:" + 43 base64url characters (32 bytes, no padding). */
export const TFP_RE = /^sha-256:[A-Za-z0-9_-]{43}$/;
/** Paging limits a client applies while it collects tools/list pages (section 15). */
export const MAX_TOOL_PAGES = 100;
export const MAX_TOOLS = 10000;

/**
 * JSON Canonicalization Scheme (RFC 8785) for JSON values: no whitespace, object members sorted by the UTF-16 code
 * units of their names, strings and numbers serialized as ECMAScript JSON.stringify does (RFC 8785 sections 3.2.2
 * and 3.2.3). Throws on values that are not JSON (NaN, Infinity, functions, bigint, symbols, cycles).
 * Object members whose value is undefined are left out, as JSON.stringify does.
 */
export function canonicalize(value) {
  const seen = new Set();
  const walk = (v) => {
    if (v === null) return 'null';
    switch (typeof v) {
      case 'boolean': return v ? 'true' : 'false';
      case 'string': return JSON.stringify(v);
      case 'number':
        if (!Number.isFinite(v)) throw new TypeError('JCS: number is not finite');
        return JSON.stringify(v); // ECMAScript Number serialization; -0 becomes 0
      case 'object': {
        if (seen.has(v)) throw new TypeError('JCS: cyclic value');
        seen.add(v);
        let out;
        if (Array.isArray(v)) out = '[' + v.map((x) => (x === undefined ? 'null' : walk(x))).join(',') + ']';
        else {
          if (typeof v.toJSON === 'function') { seen.delete(v); return walk(v.toJSON()); }
          // Default sort compares UTF-16 code units, which is what RFC 8785 section 3.2.3 requires.
          const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
          out = '{' + keys.map((k) => JSON.stringify(k) + ':' + walk(v[k])).join(',') + '}';
        }
        seen.delete(v);
        return out;
      }
      default: throw new TypeError(`JCS: ${typeof v} is not a JSON value`);
    }
  };
  return walk(value);
}

const cmpUnits = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * The tools of a tools/list result, of several pages, or a plain array of tools.
 * @param {object|object[]} input a tools/list result ({ tools: [...] }), an array of such results, or an array of tools
 */
export function collectTools(input) {
  if (Array.isArray(input)) {
    if (input.length && input.every((p) => p && typeof p === 'object' && Array.isArray(p.tools))) return input.flatMap((p) => p.tools);
    return input;
  }
  if (input && typeof input === 'object' && Array.isArray(input.tools)) return input.tools;
  throw new TypeError('expected a tools/list result, an array of pages or an array of tools');
}

/**
 * The canonical form of a tool list (section 15): for each tool its name, its inputSchema and, when it is a boolean,
 * annotations.readOnlyHint. Descriptions, titles and every other field are left out. Sorted by name; ties (which a
 * conforming server never produces) by their own canonical text. Returns the JCS string.
 */
export function canonicalToolList(input) {
  const tools = collectTools(input);
  const items = tools.map((t) => {
    if (!t || typeof t !== 'object' || typeof t.name !== 'string') throw new TypeError('every tool needs a string name');
    const o = { name: t.name };
    if (t.inputSchema !== undefined) o.inputSchema = t.inputSchema;
    if (t.annotations && typeof t.annotations.readOnlyHint === 'boolean') o.annotations = { readOnlyHint: t.annotations.readOnlyHint };
    return { name: t.name, text: canonicalize(o) };
  });
  items.sort((a, b) => cmpUnits(a.name, b.name) || cmpUnits(a.text, b.text));
  return '[' + items.map((i) => i.text).join(',') + ']';
}

/**
 * The tool fingerprint: "sha-256:" + base64url(SHA-256(UTF-8(canonical form))).
 * @param {object|object[]} toolsListResult a tools/list result, all its pages, or an array of tools
 */
export function fingerprintTools(toolsListResult) {
  return TFP_PREFIX + createHash('sha256').update(canonicalToolList(toolsListResult), 'utf8').digest('base64url');
}

/**
 * Compare a candidate's signed fingerprint with the tool list the client sees after connecting.
 * Returns { status, expected, actual }:
 *   'match'   the lists are the same: the resolver's claim applies;
 *   'drift'   they differ, or the signed value is malformed: the client MUST NOT treat the candidate as matching the
 *             resolver's claim;
 *   'absent'  the candidate carries no fingerprint: nothing changes (fail open, as in 0.2).
 * @param {{ tfp?: string }} candidate a verified candidate or record (its signed claims)
 * @param {object|object[]} toolsListResult what the client's own tools/list returned (all pages)
 */
export function checkDrift(candidate, toolsListResult) {
  const expected = candidate && typeof candidate === 'object' ? candidate.tfp : undefined;
  if (expected === undefined || expected === null) return { status: 'absent', expected: null, actual: null };
  let actual = null;
  try { actual = fingerprintTools(toolsListResult); } catch { return { status: 'drift', expected, actual: null }; }
  if (typeof expected !== 'string' || !TFP_RE.test(expected)) return { status: 'drift', expected, actual };
  return { status: expected === actual ? 'match' : 'drift', expected, actual };
}

/**
 * Collect every page of tools/list from a client object with listTools({ cursor }) (the shape of the protocol's
 * reference SDK client). Stops at MAX_TOOL_PAGES pages or MAX_TOOLS tools and then throws, so a caller never
 * compares a partial list.
 * @param {{ listTools: (params?: { cursor?: string }) => Promise<{ tools: object[], nextCursor?: string }> }} client
 */
export async function listAllTools(client) {
  if (!client || typeof client.listTools !== 'function') throw new TypeError('client has no listTools()');
  const pages = [];
  let cursor;
  let count = 0;
  for (let i = 0; i < MAX_TOOL_PAGES; i++) {
    const page = await client.listTools(cursor === undefined ? undefined : { cursor });
    if (!page || !Array.isArray(page.tools)) throw new TypeError('tools/list returned no tools array');
    pages.push(page);
    count += page.tools.length;
    if (count > MAX_TOOLS) throw new RangeError('tool list too long');
    if (typeof page.nextCursor !== 'string' || !page.nextCursor) return pages;
    cursor = page.nextCursor;
  }
  throw new RangeError('too many tools/list pages');
}

/**
 * After connecting to a candidate, before the first tool call: list all tools and compare. Never throws; a list
 * that cannot be read counts as drift when a fingerprint was signed, and as absent otherwise.
 * @returns {Promise<{ status: 'match'|'drift'|'absent', expected: string|null, actual: string|null, error?: string }>}
 */
export async function checkClientDrift(candidate, client) {
  if (!candidate || candidate.tfp === undefined || candidate.tfp === null) return { status: 'absent', expected: null, actual: null };
  try { return checkDrift(candidate, await listAllTools(client)); }
  catch (e) { return { status: 'drift', expected: candidate.tfp, actual: null, error: String(e?.message || e).slice(0, 80) }; }
}
