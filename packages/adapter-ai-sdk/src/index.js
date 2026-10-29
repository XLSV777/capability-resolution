// Capability Resolution 0.3 for the Vercel AI SDK (example adapter).
// Capability Resolution 0.3 (in development), open specification by 7IT Solutions, CC BY 4.0. Code MIT.
//
// resolveTool() returns an AI SDK tool (`tool()` from 'ai', AI SDK 7: description, inputSchema, execute) that asks
// the resolvers you list which servers can do a job. The answer is signed, verified advice: the tool never connects
// to a candidate. Connecting stays your app's decision (user approval, an allowlist, an org policy).
//
// When your app does connect, candidateTools() checks the candidate's signed tool fingerprint against the server's own
// tools/list right after connecting and before any tool is called, and only then hands you the tools.
import { tool, jsonSchema } from 'ai';
import { createResolverClient, checkClientDrift, SPEC } from 'capability-resolver-client';

/**
 * @param {{ resolvers?: string[], client?: ReturnType<typeof createResolverClient>, pinnedKeys?: Record<string, object[]>, fetch?: typeof fetch, timeoutMs?: number, userAgent?: string }} [opts]
 *   resolvers: ordered https resolver origins (none by default, so the tool answers an empty list until you add some).
 */
export function resolveTool(opts = {}) {
  const { client, ...clientOpts } = opts;
  const rc = client || createResolverClient(clientOpts);
  return tool({
    description: 'Find remote servers that can do a job. Asks Capability Resolution resolvers and returns signed, '
      + 'expiring candidates with the status observed at their last check. It does not connect to any server.',
    inputSchema: jsonSchema({
      type: 'object',
      properties: {
        need: { type: 'string', minLength: 3, maxLength: 200, description: 'The job in plain words, for example "send a transactional email". No user content, file names or credentials.' },
        no_sign_in: { type: 'boolean', description: 'Only servers that answered without sign-in.' },
        read_only: { type: 'boolean', description: 'Only servers with a read-only tool for the job.' },
      },
      required: ['need'],
      additionalProperties: false,
    }),
    execute: async ({ need, no_sign_in, read_only }) => {
      const r = await rc.resolve(need, { no_sign_in: !!no_sign_in, read_only: !!read_only });
      return {
        spec: SPEC.text,
        resolver: r.resolver,
        candidates: r.candidates.map((c) => ({ id: c.id, url: c.url, status: c.status, checked_at: c.checked_at, expires: new Date(c.exp * 1000).toISOString(), tfp: c.tfp ?? null, jws: c.jws })),
      };
    },
  });
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
 *   listTools: how to read one tools/list page, for clients whose method has another shape (for example
 *   (p) => client.listTools({ params: p }))
 */
export function checkCandidateTools(candidate, mcpClient, opts = {}) {
  const lister = opts.listTools ? { listTools: opts.listTools } : mcpClient;
  return checkClientDrift(candidate, lister);
}

/**
 * Check, then return the client's AI SDK tools (mcpClient.tools()). Throws CapabilityDriftError on drift, so no tool
 * of a drifted server reaches the model. A candidate without a fingerprint passes, as in 0.2.
 * @param {{ tfp?: string|null }} candidate
 * @param {{ tools: () => Promise<object> }} mcpClient a connected MCP client from the AI SDK
 * @param {{ listTools?: Function }} [opts]
 */
export async function candidateTools(candidate, mcpClient, opts = {}) {
  const r = await checkCandidateTools(candidate, mcpClient, opts);
  if (r.status === 'drift') throw new CapabilityDriftError(r);
  return mcpClient.tools();
}
