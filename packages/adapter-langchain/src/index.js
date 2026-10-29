// Capability Resolution 0.2 for LangChain JS (draft example adapter).
// Capability Resolution 0.2, open draft by 7IT Solutions, CC BY 4.0. Code MIT.
//
// CapabilityResolverTool extends Tool from '@langchain/core/tools' (string input: implement name, description and
// _call(arg)). The input is the job in plain words. The output is JSON with signed, verified candidates. The tool
// never connects to a candidate: connecting stays your app's decision.
import { Tool } from '@langchain/core/tools';
import { createResolverClient, SPEC } from 'capability-resolver-client';

export class CapabilityResolverTool extends Tool {
  static lc_name() { return 'CapabilityResolverTool'; }

  name = 'capability_resolve';

  description = 'Find remote servers that can do a job. Input: the job in plain words, for example "send a '
    + 'transactional email" (no user content, file names or credentials). Returns JSON with signed, expiring '
    + 'candidates and the status observed at their last check. It does not connect to any server.';

  /**
   * @param {{ resolvers?: string[], client?: object, constraints?: { no_sign_in?: boolean, read_only?: boolean, max_ms?: number, payment?: 'none' }, pinnedKeys?: Record<string, object[]>, fetch?: typeof fetch, timeoutMs?: number, userAgent?: string } & Record<string, unknown>} [fields]
   *   Resolver options go to the client; anything else (verbose, callbacks, metadata, ...) goes to Tool.
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
      candidates: r.candidates.map((c) => ({ id: c.id, url: c.url, status: c.status, checked_at: c.checked_at, expires: new Date(c.exp * 1000).toISOString(), jws: c.jws })),
    });
  }
}
