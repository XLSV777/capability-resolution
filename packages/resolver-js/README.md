# capability-resolver-client

By 7IT Solutions: https://7it.co.il/standard/capability-resolution/

```sh
npm install capability-resolver-client
```

**Capability Resolution 0.2, open specification by 7IT Solutions, CC BY 4.0.** Spec: https://7it.co.il/standard/capability-resolution/
This library implements conformance level `client-1`. The code is MIT.

A small client for the spec, for use with the Model Context Protocol. It asks an ordered list of resolvers
which servers can do a job and returns signed, expiring candidates. Node 18 or later, built-ins only.

```js
import { createResolverClient } from 'capability-resolver-client';

const rc = createResolverClient({ resolvers: ['https://resolver.example'] }); // the list is empty by default
const { candidates } = await rc.resolve('send a transactional email', { no_sign_in: true });
```

What it does, following section 7 of the spec:

1. The resolver list is empty unless you add origins. Plain-http resolvers are never used, and redirects are refused.
2. Resolvers are asked in order.
3. Fail open. A resolver that fails, times out, is rate-limited, or returns anything that does not verify is
   skipped as a whole. If every resolver fails, the answer is an empty list. It never throws.
4. Every token is verified: EdDSA over Ed25519, a key from that resolver's discovery document (or your pinned keys,
   honouring a key's `nbf`/`exp`), `iss` equal to that resolver, and the 48-hour and 300-second rules of section 8.
   Only the signed claims are used.
5. It never connects to a server. A candidate is advice; what to connect to stays your client's own decision.
6. Answers are cached until their earliest expiry and never used after it; discovery for at most one hour.
7. Each candidate keeps its `checked_at`: status is what was observed then, not a promise.

It sends the job text to the resolvers you list and nowhere else, and logs nothing.

## What the library states about itself

- `SPEC`: name, version, editors, license and URL of the spec (`SPEC.text` is the one-line form).
- `conformance`: `'client-1'`.
- Every request carries `User-Agent: capability-resolver-client/0.2 (client-1; +https://7it.co.il/standard/capability-resolution/)`.
  Pass `userAgent: 'my-app/1.0'` to put your own product token in front of it; the library token stays.

`pinnedKeys` lets a client that ships a default resolver pin that resolver's keys.

## Checker

`capability-resolution-check <resolver origin> [--json] [--need "<job>"]` tests a resolver against every
requirement of sections 5, 6, 8 and 9 that can be checked over HTTP and prints PASS/FAIL per rule with its section,
then the level (`resolver-1` or `not conformant`). Exit code 0 at `resolver-1`, 1 otherwise. It only sends GET
requests, with a fixed sample job.

`capability-resolution-check --server <origin> [--json]` checks a server owner's declaration file,
`https://<origin>/.well-known/capabilities.txt` (spec section 13), the way a resolver reads it: https only, redirects
only on the same origin, 32 KiB at most. It prints PASS/FAIL per rule and the level (`server-1` or
`not conformant`); exit code 0 at `server-1`. It does not connect to the declared servers.

## Server declaration file

```js
import { parseDeclaration, resolverAllowed } from 'capability-resolver-client/declaration';

const d = parseDeclaration(text, { origin: 'https://example.com' }); // { ok, errors, warnings, servers, resolvers, ... }
if (resolverAllowed(d, 'https://resolver.example')) { /* d.servers are claims; observe them before listing */ }
```

`resolverAllowed` returns false on a deny even when the file is expired or invalid. `verifyDeclarationSignature(d, keys)`
checks the optional `Signature` line.

## Tests

`npm test` runs the client tests, the signed test vectors in `../test-vectors`, and the checker against good and
broken in-process mock resolvers. A mock network only; nothing leaves the machine.

Model Context Protocol and MCP are trademarks of their respective owners; this client and the specification are
independent and not endorsed by them.
