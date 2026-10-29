# capability-resolver-ai-sdk (draft example, not on npm yet)

**Capability Resolution 0.2, open draft by 7IT Solutions, CC BY 4.0.** A thin Vercel AI SDK (v7) tool over
`capability-resolver-client`, for use with the Model Context Protocol and other tool protocols.

```js
import { resolveTool } from 'capability-resolver-ai-sdk';
const tools = { find_servers: resolveTool({ resolvers: ['https://resolver.example'] }) };
const result = await generateText({ model, tools, prompt: 'Which server can send a transactional email?' });
```

The tool returns signed, verified candidates as advice and never connects to them. Connecting stays your app's
decision. With no resolvers listed it answers an empty list.

Tests: `npm test` (a mocked fetch; nothing leaves the machine). Nothing is installed in this draft, so `ai` resolves
to a stub of its documented `tool()` and `jsonSchema()` unless the real package is installed (see `test/hooks.mjs`).

Model Context Protocol and MCP are trademarks of their respective owners; this adapter and the specification are
independent and not endorsed by them.
