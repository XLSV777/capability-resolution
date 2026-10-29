// Capability Resolution 0.2 for the Vercel AI SDK (example adapter).
// Capability Resolution 0.2, open specification by 7IT Solutions, CC BY 4.0. Code MIT.
//
// resolveTool() returns an AI SDK tool (`tool()` from 'ai', AI SDK 7: description, inputSchema, execute) that asks
// the resolvers you list which servers can do a job. The answer is signed, verified advice: the tool never connects
// to a candidate. Connecting stays your app's decision (user approval, an allowlist, an org policy).
import { tool, jsonSchema } from 'ai';
import { createResolverClient, SPEC } from 'capability-resolver-client';

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
        candidates: r.candidates.map((c) => ({ id: c.id, url: c.url, status: c.status, checked_at: c.checked_at, expires: new Date(c.exp * 1000).toISOString(), jws: c.jws })),
      };
    },
  });
}
