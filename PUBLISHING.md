# Publishing the npm packages

Four packages, all version 0.2.0, MIT, by 7IT Solutions (https://7it.co.il/standard/capability-resolution/):

| Order | Folder | npm name |
| --- | --- | --- |
| 1 | packages/resolver-js | `capability-resolver-client` |
| 2 | packages/test-vectors | `capability-resolution-test-vectors` |
| 3 | packages/adapter-ai-sdk | `capability-resolver-ai-sdk` |
| 4 | packages/adapter-langchain | `capability-resolver-langchain` |

The client goes first because both adapters depend on `capability-resolver-client@^0.2.0`. The repository root is
a private npm workspace (never published) so `npm ci` and `npm test` cover all four packages at once.

## Option A: GitHub Actions (recommended, adds provenance)

1. On npmjs.com, create an access token: Access Tokens, Generate New Token, Granular Access Token, permission
   "Read and write", packages "All packages" (the names do not exist yet, so a token limited to named packages
   cannot create them), and allow it to publish without a 2FA prompt.
2. In GitHub, XLSV777/capability-resolution, Settings, Secrets and variables, Actions, New repository secret:
   name `NPM_TOKEN`, value the token.
3. Run it: Actions, "Publish to npm", Run workflow (or publish a GitHub release). The workflow runs `npm ci`, the
   full test suite, then `npm publish --provenance --access public` for each package in the order above. A
   version that is already on npm is skipped, so a re-run is safe.

## Option B: from a local machine

```sh
npm login                      # or: npm config set //registry.npmjs.org/:_authToken <token>
npm ci
npm test
cd packages/resolver-js       && npm publish --access public --provenance=false && cd ../..
cd packages/test-vectors      && npm publish --access public --provenance=false && cd ../..
cd packages/adapter-ai-sdk    && npm publish --access public --provenance=false && cd ../..
cd packages/adapter-langchain && npm publish --access public --provenance=false && cd ../..
```

`publishConfig.provenance` is true in each package, and provenance can only be generated inside a supported CI
runner, so a local publish needs `--provenance=false`. Option A is preferred for that reason.

## Before a new version

- Bump `version` in every package that changed, and `CLIENT_VERSION` in `packages/resolver-js/src/index.js`
  (a test checks they match). If the client's minor version changes, update the adapters' dependency range.
- `npm test` at the root, and `npm pack --dry-run` in each package folder: only `src`, `bin` (client),
  `README.md`, `LICENSE` and, for the vectors, the JSON files and `generate.mjs` may be listed.
- After publishing, check each page on npmjs.com shows the provenance badge and the right README.
