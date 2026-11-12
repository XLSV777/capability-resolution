# capability-resolver-ai-sdk

By 7IT Solutions: https://7it.co.il/standard/capability-resolution/

```sh
npm install capability-resolver-ai-sdk ai
```

**Capability Resolution 0.3, open specification by 7IT Solutions, CC BY 4.0.** A thin Vercel AI SDK (v7) tool over
`capability-resolver-client`, for use with the Model Context Protocol and other tool protocols.

```js
import { resolveTool } from 'capability-resolver-ai-sdk';
const tools = { find_servers: resolveTool() }; // asks 7Maps, the client's default resolver
const result = await generateText({ model, tools, prompt: 'Which server can send a transactional email?' });
```

Default resolver: 7Maps, run by 7IT Solutions (`https://7it.co.il`, its key pinned), from `capability-resolver-client`.
Set `resolvers` to use your own list or several resolvers, for example `resolveTool({ resolvers: ['https://resolver.your-company.example'] })`;
`resolvers: []` means none, and the tool then answers an empty list.

The tool returns signed, verified candidates as advice and never connects to them. Connecting stays your app's
decision.

Tests: `npm test` (a mocked fetch; nothing leaves the machine). Without `ai` installed, `ai` resolves
to a stub of its documented `tool()` and `jsonSchema()` unless the real package is installed (see `test/hooks.mjs`).

## After connecting: tool fingerprint (0.3)

When your app connects to a candidate, check the resolver's signed tool fingerprint before the first tool call:

```js
import { candidateTools, checkCandidateTools, CapabilityDriftError } from 'capability-resolver-ai-sdk';

const tools = await candidateTools(candidate, mcpClient); // checks, then mcpClient.tools()
```

`candidateTools` lists every page of the server's tools, compares the fingerprint, and throws `CapabilityDriftError` when
the tools changed since the resolver observed them. A candidate without a fingerprint passes, as in 0.2.
`checkCandidateTools` returns `{ status: 'match' | 'drift' | 'absent' }` without throwing. `mcpClient` is the AI SDK
client from `createMCPClient()` (`@ai-sdk/mcp`); its pages are read with `listTools({ params: { cursor } })`. Pass
`{ listTools: (p) => ... }` when your client's method has another shape, for example `(p) => sdkClient.listTools(p)`.

Checked end to end on 2026-11-05 with `ai` 7.0.163, `@ai-sdk/mcp` 2.0.91 and a paginated server.

Model Context Protocol and MCP are trademarks of their respective owners; this adapter and the specification are
independent and not endorsed by them.
