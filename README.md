# Capability Resolution

An open draft specification for one question an AI agent, client or gateway can ask over HTTP:
**"which servers can do this job, and did they answer when last checked?"**

A resolver answers with a short list of candidates. Each candidate is signed by the resolver (JWS, EdDSA over Ed25519)
and expires within 48 hours. The client verifies every answer, fails open when anything is wrong, and always keeps the
final decision: a candidate is advice, never an instruction to connect.

- **Spec:** [spec/capability-resolution-0.2.md](spec/capability-resolution-0.2.md), also at https://7it.co.il/standard/capability-resolution/
- **Version:** 0.2 (draft), 2026-10-29
- **Editors:** 7IT Solutions. We welcome co-editors from other resolver, gateway or client projects.
- **License:** the spec text is CC BY 4.0 ([LICENSE-SPEC.md](LICENSE-SPEC.md)); the code is MIT ([LICENSE](LICENSE)).
- **Status:** an independent proposal, for use with the Model Context Protocol and other tool protocols. Not part of the
  Model Context Protocol specification, and not endorsed by Anthropic, the MCP maintainers, the Linux Foundation or any
  vendor.
- **Trademarks:** Model Context Protocol and MCP are trademarks of their respective owners.

## How it works

1. **Discover.** `GET https://<resolver>/.well-known/capability-resolver` returns the resolver's endpoints and public keys.
2. **Ask.** `GET <resolve>?need=send%20a%20transactional%20email&constraints=no_sign_in` returns at most 10 candidates.
3. **Verify.** The client checks each token's signature, issuer and lifetime, and drops anything that does not verify.
4. **Decide.** The client or its user decides whether to connect. The resolver only recommends.

Server owners can publish a short declaration file at `/.well-known/capabilities.txt` (section 13): what their servers
do, whether they need sign-in or payment, a contact, and which resolvers may list them. A resolver must respect a deny
and still check each server itself: the file is a claim, not proof. See [examples/capabilities.txt](examples/capabilities.txt).

Any party may run a resolver. How a resolver chooses and orders candidates is its own method and is outside the spec.

## What is in this repository

| Folder | What |
| --- | --- |
| [spec/](spec/) | The specification text. |
| [packages/resolver-js](packages/resolver-js) | `capability-resolver-client`: a Node 18+ client with no dependencies (conformance `client-1`), and the `capability-resolution-check` CLI that tests a resolver (`resolver-1`) or a declaration file (`server-1`). |
| [packages/test-vectors](packages/test-vectors) | Signed test tokens, valid and invalid, with expected verdicts and the public test key. |
| [packages/adapter-ai-sdk](packages/adapter-ai-sdk) | Example: `resolveTool()` for the Vercel AI SDK. |
| [packages/adapter-langchain](packages/adapter-langchain) | Example: `CapabilityResolverTool` for LangChain JS. |
| [examples/](examples/) | A declaration file and an `llms.txt` summary of the spec for agents. |
| [proof/](proof/) | The exact text of each version with its RFC 3161 and OpenTimestamps proofs. |

The packages are not on npm yet. To try them, clone this repository:

```sh
cd packages/resolver-js
npm test
node bin/capability-resolution-check.js https://<resolver origin>
node bin/capability-resolution-check.js --server https://<your host>
```

## Contributing

Issues and pull requests are welcome: questions, corrections, a second implementation, or a request to co-edit.
See [CONTRIBUTING.md](CONTRIBUTING.md).
