# capability-resolver-langchain

By 7IT Solutions: https://7it.co.il/standard/capability-resolution/

```sh
npm install capability-resolver-langchain @langchain/core
```

**Capability Resolution 0.3, open specification by 7IT Solutions, CC BY 4.0.** A thin LangChain JS `Tool` subclass over
`capability-resolver-client`, for use with the Model Context Protocol and other tool protocols.

```js
import { CapabilityResolverTool } from 'capability-resolver-langchain';
const finder = new CapabilityResolverTool({ resolvers: ['https://resolver.example'], constraints: { no_sign_in: true } });
const json = await finder.invoke('send a transactional email');
```

The input is the job in plain words; the output is JSON with signed, verified candidates. The tool never connects
to a candidate. Connecting stays your app's decision. With no resolvers listed it answers an empty list.

Tests: `npm test` (a mocked fetch; nothing leaves the machine). Without `@langchain/core` installed,
`@langchain/core/tools` resolves to a stub of its documented `Tool` class unless the real package is installed
(see `test/hooks.mjs`).

## After connecting: tool fingerprint (0.3)

When your app connects to a candidate, check the resolver's signed tool fingerprint before the first tool call:

```js
import { candidateTools, checkCandidateTools, CapabilityDriftError } from 'capability-resolver-langchain';

const tools = await candidateTools(candidate, client, () => loadMcpTools(name, client)); // checks, then loads
```

`candidateTools` lists every page of the server's tools, compares the fingerprint, and throws `CapabilityDriftError` when
the tools changed since the resolver observed them. A candidate without a fingerprint passes, as in 0.2.
`checkCandidateTools` returns `{ status: 'match' | 'drift' | 'absent' }` without throwing. Pass
`{ listTools: (p) => ... }` when your client's method has another shape. `client` is the protocol SDK `Client`
(`@modelcontextprotocol/client` 2.x, the one `@langchain/mcp-adapters` 2.x takes); its `listTools({ cursor })` is read
as is.

Checked end to end on 2026-11-05 with `@langchain/core` 1.3.4, `@langchain/mcp-adapters` 2.0.2 and a paginated server.

Model Context Protocol and MCP are trademarks of their respective owners; this adapter and the specification are
independent and not endorsed by them.
