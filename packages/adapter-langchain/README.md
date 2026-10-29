# capability-resolver-langchain

By 7IT Solutions: https://7it.co.il/standard/capability-resolution/

```sh
npm install capability-resolver-langchain @langchain/core
```

**Capability Resolution 0.2, open specification by 7IT Solutions, CC BY 4.0.** A thin LangChain JS `Tool` subclass over
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

Model Context Protocol and MCP are trademarks of their respective owners; this adapter and the specification are
independent and not endorsed by them.
