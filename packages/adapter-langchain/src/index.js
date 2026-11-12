// Capability Resolution 0.3 for LangChain JS (example adapter).
// Capability Resolution 0.3, open specification by 7IT Solutions, CC BY 4.0. Code MIT.
//
// CapabilityResolverTool extends Tool from '@langchain/core/tools' (string input: implement name, description and
// _call(arg)). The input is the job in plain words. The output is JSON with signed, verified candidates. The tool
// never connects to a candidate: connecting stays your app's decision.
//
// When your app does connect, candidateTools() checks the candidate's signed tool fingerprint against the server's own
// tools/list right after connecting and before any tool is called, and only then loads the tools.
import { Tool } from '@langchain/core/tools';
import { createResolverClient, checkClientDrift, SPEC } from 'capability-resolver-client';

export class CapabilityResolverTool extends Tool {
  static lc_name() { return 'CapabilityResolverTool'; }

  name = 'capability_resolve';

  description = 'Find remote servers that can do a job. Input: the job in plain words, for example "send a '
    + 'transactional email" (no user content, file names or credentials). Returns JSON with signed, expiring '
    + 'candidates and the status observed at their last check. It does not connect to any server.';

  /**
   * @param {{ resolvers?: string[], client?: object, constraints?: { no_sign_in?: boolean, read_only?: boolean, max_ms?: number, payment?: 'none' }, pinnedKeys?: Record<string, object[]>, fetch?: typeof fetch, timeoutMs?: number, userAgent?: string } & Record<string, unknown>} [fields]
   *   Resolver options go to the client; anything else (verbose, callbacks, metadata, ...) goes to Tool.
   *   resolvers: default the client's default, 7Maps by 7IT Solutions (https://7it.co.il, key pinned); your own list
   *   replaces it, and [] means none.
   */
  constructor(fields = {}) {
    const { resolvers, client, constraints, pinnedKeys, fetch, timeoutMs, userAgent, ...toolFields } = fields;
    super(toolFields);
    this.client = client || createResolverClient({ resolvers, pinnedKeys, fetch, timeoutMs, userAgent });
    this.constraints = constraints || {};
  }

  /** @param {string} input the job */
  async _call(input) {
    const r = await this.client.resolve(String(input ?? ''), this.constraints);
    return JSON.stringify({
      spec: SPEC.text,
      resolver: r.resolver,
      candidates: r.candidates.map((c) => ({ id: c.id, url: c.url, status: c.status, checked_at: c.checked_at, expires: new Date(c.exp * 1000).toISOString(), tfp: c.tfp ?? null, jws: c.jws })),
    });
  }
}

/** Thrown when a candidate's tools changed since the resolver observed them (spec 0.3, section 7 rule 8). */
export class CapabilityDriftError extends Error {
  constructor(result) {
    super('capability drift: the server\'s tools/list does not match the fingerprint the resolver signed');
    this.name = 'CapabilityDriftError';
    this.result = result;
  }
}

/**
 * Right after connecting to a candidate and before the first tool call: list every page of the server's tools and
 * compare with the candidate's signed fingerprint (tfp). Never throws.
 * Returns { status: 'match' | 'drift' | 'absent', expected, actual }. 'absent': the resolver signed no fingerprint,
 * nothing changes (fail open). 'drift': do not treat the candidate as matching the resolver's claim.
 * @param {{ tfp?: string|null }} candidate a candidate from this adapter's output or from the resolver client
 * @param {object} mcpClient a connected client with listTools() (or pass opts.listTools)
 * @param {{ listTools?: (params?: { cursor?: string }) => Promise<{ tools: object[], nextCursor?: string }> }} [opts]
 *   listTools: how to read one tools/list page, for clients whose method has another shape
 */
export function checkCandidateTools(candidate, mcpClient, opts = {}) {
  const lister = opts.listTools ? { listTools: opts.listTools } : mcpClient;
  return checkClientDrift(candidate, lister);
}

/**
 * Check, then load the tools with your own loader (for example () => loadMcpTools(name, client) from
 * @langchain/mcp-adapters). Throws CapabilityDriftError on drift, so no tool of a drifted server is loaded. A
 * candidate without a fingerprint passes, as in 0.2.
 * @template T
 * @param {{ tfp?: string|null }} candidate
 * @param {object} mcpClient a connected client with listTools() (or pass opts.listTools)
 * @param {() => Promise<T>} load
 * @param {{ listTools?: Function }} [opts]
 * @returns {Promise<T>}
 */
export async function candidateTools(candidate, mcpClient, load, opts = {}) {
  const r = await checkCandidateTools(candidate, mcpClient, opts);
  if (r.status === 'drift') throw new CapabilityDriftError(r);
  return load();
}
