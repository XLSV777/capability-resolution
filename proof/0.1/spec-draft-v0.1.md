# MCP Capability Resolution

**Version 0.1 (draft), 2026-10-28.** INTERNAL DRAFT. Not published, not submitted, not shared. The founder approves
the final text before anything goes out (see launch-notes.md).

- **Working name:** MCP Capability Resolution (short: MCR).
- **Other names considered:**
  1. MCP Resolver Protocol.
  2. Open Capability Lookup for MCP (OCL).
- **License of this text:** Creative Commons Attribution 4.0 International (CC BY 4.0). Reference code is MIT.
- **Editors:** TBD (7IT Solutions). We are looking for co-editors from other resolver, gateway or client projects.
- **Status:** an independent proposal. It is not part of the Model Context Protocol specification and is not
  endorsed by Anthropic, the MCP maintainers, the Linux Foundation or any vendor.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only
when, they appear in capitals.

## 1. Purpose

An AI agent, its client or its gateway often needs a tool for a job and does not know which MCP server has one. It
also cannot tell, before connecting, whether that server answers today. Today it guesses, searches the web, or loads
tool lists from several servers.

This spec defines a small HTTP protocol for asking a **resolver** a single question: "which MCP servers can do this
job, and did they answer when last checked?" The answer is a short list of candidates. Each candidate is signed by
the resolver and expires.

It works like DNS for capabilities:

- Many resolvers can exist and a client may use several.
- Answers are signed and expire.
- The client keeps the final decision.

A resolver never hosts servers, never connects a client to a server, and never sells placement.

What this spec is not:

- **Not a registry.** Registries (for example the Official MCP Registry) record what publishers declare. A
  resolver adds what it observed, and MAY use registries as a source.
- **Not a server description format.** Server Cards and the AI Catalog (SEP-2127) describe a server. A resolver
  MAY point to them.
- **Not a ranking method.** How a resolver chooses and orders candidates is its own method. It is outside this
  spec, and the spec does not require a resolver to disclose it.

## 2. Terms

- **Server:** a remote MCP server reachable at an https URL.
- **Canonical URL:** the server URL in the form given in section 4.
- **Resolver:** an HTTP service that implements sections 5 and 6.
- **Need:** a short plain-language description of a job, for example "send a transactional email".
- **Constraint:** a filter the client asks the resolver to apply (section 6.2).
- **Candidate:** one server in a resolve answer, carrying a signed token.
- **Record:** a resolver's signed statement about one server (section 6.3).
- **Token:** a JWS in compact serialization, signed by the resolver (section 8).
- **Client:** anything that calls a resolver: an agent host, an MCP client, a gateway or a plugin.

## 3. Overview

```
client                                            resolver (one of several)
  | GET /.well-known/mcp-resolver  ------------->  {v, resolve, record, keys[], policy_url}
  | GET <resolve>?need=...&constraints=... ----->  {candidates: [{id, url, status, checked_at, expires, evidence, jws}]}
  | verify each jws with keys[]; drop what fails
  | GET <record>?id=... (optional) ------------->  {signed record, anchor, proof}
  | apply the client's own policy; maybe connect to the server (never the resolver's decision)
```

## 4. Server identity

**Canonical URL.** To form it, a resolver or client:

1. Parses the URL.
2. Requires the `https` scheme and refuses URLs that carry credentials.
3. Lower-cases the host and removes a leading `www.`.
4. Removes port 443 (keeps any other port).
5. Removes the query, the fragment and any trailing slashes.

Two candidates with the same canonical URL are the same server, across resolvers.

**Server ID.** A resolver gives each server a stable ID of the form `<namespace>:<local>`.

- `namespace` is declared in the resolver's discovery document: 1 to 32 characters, lower-case letters, digits and
  hyphens.
- `local` is opaque to clients.
- An ID MUST stay the same for as long as the resolver tracks that canonical URL, and MUST NOT be reused for
  another server.
- IDs are scoped to their resolver. Clients match servers across resolvers by canonical URL, not by ID.
- A resolver MAY derive the ID from the canonical URL. The reference implementation uses 16 base32 characters of
  SHA-256 over `"mcp-server\n" + canonical URL`.

## 5. Discovery

A resolver publishes `GET /.well-known/mcp-resolver` on its own origin, over https, as `application/json`:

```json
{
  "v": "0.1",
  "resolver": "Example Resolver",
  "iss": "https://resolver.example",
  "resolve": "https://resolver.example/resolve",
  "record": "https://resolver.example/record",
  "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": "<base64url>", "kid": "<RFC 7638 thumbprint>", "use": "sig", "alg": "EdDSA" }],
  "policy_url": "https://resolver.example/policy",
  "id_namespace": "example",
  "max_candidates": 10,
  "max_ttl_s": 172800,
  "constraints": ["no_sign_in", "read_only", "max_ms", "payment"],
  "conformance": "resolver-1"
}
```

| Field | Required | Meaning |
|---|---|---|
| `v` | yes | Spec version, `"0.1"`. |
| `iss` | yes | The resolver's origin. It MUST equal the origin serving this document, and every token's `iss`. |
| `resolve`, `record` | yes | Endpoint URLs. They MUST be on the same origin as `iss`. |
| `keys` | yes | Current public keys as JWKs (RFC 8037). Each key has a `kid`. A key MAY carry `nbf` and `exp` (seconds) for rotation. |
| `policy_url` | yes | A human-readable page covering the obligations in section 9 and the method changelog. |
| `resolver` | no | Display name. |
| `id_namespace`, `max_candidates`, `max_ttl_s`, `constraints`, `conformance` | no | As named. Unknown fields MUST be ignored. |

The document SHOULD be cacheable for up to one hour.

## 6. Endpoints

### 6.1 resolve

`GET <resolve>?need=<text>&constraints=<list>`

- `need`: 3 to 200 characters of plain text.
- `constraints`: optional (6.2).

The answer, `200 application/json`:

```json
{
  "v": "0.1",
  "iss": "https://resolver.example",
  "constraints": "no_sign_in,read_only",
  "ignored": ["unknown_thing"],
  "issued_at": "2026-10-28T12:00:00.000Z",
  "candidates": [
    {
      "id": "example:abcdefghijklmnop",
      "url": "https://mail.example.com/mcp",
      "status": "ok",
      "checked_at": "2026-10-28T10:05:00Z",
      "expires": "2026-10-30T12:00:00.000Z",
      "evidence": { "record": "https://resolver.example/record?id=example:abcdefghijklmnop", "method": "https://resolver.example/method" },
      "jws": "<compact JWS>"
    }
  ]
}
```

Rules for the answer:

- At most 10 candidates, in the resolver's order of preference. An empty list is a valid answer.
- `status` is one of the following:
  - `ok`: the server answered and listed tools without sign-in.
  - `sign_in`: the server answered and requires sign-in.
  - `down`: the server did not answer at its last check.
  - `unknown`: there is no check on file.
- A resolve answer SHOULD contain only `ok` and `sign_in` servers.
- `checked_at` is when the resolver last observed that status.
- `evidence` points to where the claim can be checked further. It MAY take the shape of an `evidenceRef` from the
  MCP trust-annotations work (SEP-1913) when that settles.
- The fields next to `jws` are a convenience. Clients MUST use the values inside the verified token (section 7).
- Errors use a non-200 status with `{v, error, note}`:
  - `400` for a bad request.
  - `404` for an unknown server.
  - `429` for rate limits.
  - `503` when the resolver cannot answer or cannot sign.
- A resolver MUST NOT return unsigned candidates.

### 6.2 Constraints

`constraints` is a comma-separated list. Version 0.1 defines:

| Item | Meaning |
|---|---|
| `no_sign_in` | Only servers that answered without sign-in. |
| `read_only` | Only servers with a read-only tool for the need, as the resolver judges it. |
| `max_ms:<n>` | Only servers whose handshake took at most `n` milliseconds (1 to 60000) at the last check. |
| `payment:none` / `payment:any` | `none`: only servers that declare no payment requirement. `any` is the default. |

A resolver MUST apply every constraint it lists in its discovery document. It MUST ignore unknown or malformed
items and SHOULD return them in `ignored`. New constraints are added by a version of this spec or under an
`x-<namespace>-` prefix.

### 6.3 record

`GET <record>?id=<id>` or `GET <record>?url=<server url>` returns one signed record:

```json
{
  "v": "0.1", "iss": "https://resolver.example", "sub": "example:abcdefghijklmnop",
  "url": "https://mail.example.com/mcp", "name": "Mail", "status": "ok",
  "checked_at": "2026-10-28T10:05:00Z", "first_seen": "2026-10-02",
  "iat": 1793188800, "exp": 1793361600,
  "evidence": { "record": "...", "method": "..." },
  "anchor": { "day": "2026-10-27", "root": "<hex>", "url": "https://resolver.example/roots/2026-10-27" },
  "proof": null,
  "expires": "2026-10-30T12:00:00.000Z",
  "jws": "<compact JWS over the same claims>"
}
```

- `anchor` (optional): the newest signed history head of the resolver that covers the data behind the record.
- `proof`: `null`, or a Merkle inclusion proof of the record in the anchor (`{type: "rfc9162-sha256", leaf_index,
  tree_size, path[]}`). Conformance level `resolver-2` requires it.

## 7. Client behaviour

1. **Resolver list.** A client holds an ordered list of resolver origins. This spec ships no default: the list is
   empty unless the client's maker or its user adds resolvers. Plain-http resolvers MUST NOT be used.
2. **Order.** The client asks resolvers in order and MAY ask several in parallel. It MAY merge answers by
   canonical URL.
3. **Fail open.** A resolver that is unreachable, slow, rate-limited or returns anything that does not verify is
   skipped. If no resolver answers, the client continues exactly as it would without this protocol. A resolver
   MUST NOT become a single point of failure.
4. **Verify.** For each candidate the client:
   1. verifies the JWS with a key from that resolver's `keys`, or with pinned keys;
   2. checks that the token's `iss` is that resolver;
   3. checks `iat` and `exp` (section 8);
   4. uses only the signed claims.

   A client that ships a default resolver SHOULD pin that resolver's keys.
5. **No auto-connect.** A candidate is advice. A client MUST NOT connect to, authorize or call a server only
   because a resolver named it. Connecting follows the client's own policy, for example user approval, an
   allowlist or an organisation policy.
6. **Cache.** Answers MAY be cached until the earliest `exp` among their tokens, and MUST NOT be used after it.
   Discovery documents MAY be cached for up to one hour.
7. **Status is history.** `status` is what was observed at `checked_at`, not a promise about the next call.

## 8. Signatures and expiry

- **Format.** JWS compact serialization (RFC 7515) with `alg` `EdDSA` over Ed25519 (RFC 8037). The protected
  header MUST contain `alg`, `kid`, and `typ` = `mcp-resolver+jws`.
- **Claims.**
  - Required: `v`, `iss`, `sub` (server ID), `url` (canonical URL), `status`, `checked_at`, `iat` and `exp` (in
    seconds), and `evidence`.
  - Records add `name`, `first_seen`, `anchor` and `proof`.
  - Tokens MUST NOT contain the need text, constraints, or anything about the caller. A token can then be
    forwarded or logged without revealing what was asked.
- **Expiry.** `exp - iat` MUST NOT exceed 48 hours (172800 s). Clients MUST reject a token when any of these hold:
  - its lifetime is longer than 48 hours;
  - `exp` is more than 300 seconds in the past;
  - `iat` is more than 300 seconds in the future.
- **Key IDs.** `kid` SHOULD be the RFC 7638 thumbprint of the public key.

## 9. Resolver obligations

A conforming resolver:

1. **Neutrality.** It MUST NOT accept payment, or anything of value, for including or ordering a candidate. It
   MUST NOT favour servers it operates or is paid by. If it has any such relationship, it MUST disclose it at
   `policy_url`.
2. **Method changes.** It MUST keep a dated changelog of material changes to how it selects candidates at
   `policy_url`. It does not have to publish the method itself.
3. **Never hosts.** It MUST NOT host, proxy or impersonate the servers it resolves. Candidate URLs point to the
   servers themselves.
4. **No user data.** It MUST NOT store the need text together with anything that identifies the caller. It MUST
   NOT put caller data in tokens, and MUST NOT sell or share query logs. Aggregate counts are allowed.
5. **Rate limits.** It SHOULD apply rate limits and answer `429` with `Retry-After` when it does.
6. **Honest status.** It MUST NOT report a status it did not observe, and MUST NOT sign a `checked_at` later than
   the observation.

## 10. Privacy

The need text can reveal what a user is working on. Accordingly:

- clients SHOULD send only the job, never user content, file names or credentials;
- resolvers follow section 9.4;
- tokens carry no query data (section 8).

A client that wants less exposure can ask several resolvers, or use a local resolver.

## 11. Security considerations

- **Poisoning.** A server owner or a crowd of fake reports may try to push a server into answers. Resolvers SHOULD
  rely on their own observations for status and treat third-party reports as untrusted input. Clients reduce the
  effect by using several resolvers and keeping their own connect policy (7.5).
- **Impersonating a resolver.** Discovery is over https only, and endpoints must stay on the resolver's origin.
  Clients that ship a default resolver pin its keys.
- **Key rotation.** A resolver publishes the new key next to the old one before signing with it. It keeps the old
  key until every token signed with it has expired (at least 48 hours), and records rotations at `policy_url`. If
  a key is compromised, the resolver removes it at once. Clients refetch discovery hourly, so a removed key stops
  verifying within an hour plus the cache time.
- **Replay.** A token is a dated statement, not a session credential. Replay inside its lifetime only repeats a
  true statement about the past. `exp` bounds staleness, and clients judge freshness by `checked_at`.
- **Third-party text.** Server names and descriptions are untrusted text. Clients MUST NOT treat them as
  instructions.
- **Tokens prove the resolver's claim, not the server's identity.** Connecting still needs the usual MCP
  authorization and TLS.

## 12. Conformance levels

| Level | Requires |
|---|---|
| `resolver-1` | Sections 5, 6.1 to 6.3 (with `proof` allowed to be null), 8 and 9. |
| `resolver-2` | Level 1, plus `proof` on every record, and an append-only signed history whose heads are published daily. |
| `client-1` | Section 7 rules 1 to 7, and section 8 verification. |

## 13. Well-known URI registration (to file after review)

- URI suffix: `mcp-resolver`.
- Change controller: the editors of this specification (to be transferred to a standards body if one adopts it).
- Specification document: this document.
- Status: provisional. To be filed under RFC 8615 ("Specification Required") once the text is stable.

The suffix does not collide with registered or proposed suffixes as of 2026-10-28:

- `agent-card.json`, `api-catalog` and `oauth-protected-resource` are registered.
- `ai-catalog.json`, `mcp`, `mcp.json`, `mcp/server-card.json` and `mcp-server` are proposed.

## 14. Relation to other work

- **Server Cards and AI Catalog (SEP-2127).** These say what is at a known server. MCR says which servers fit a
  job and how they behaved. A candidate's `evidence` MAY link a server card.
- **Official MCP Registry.** Publisher-declared lifecycle, no health and no signed records. Resolvers MAY use it
  as a source.
- **Trust annotations, `evidenceRef` (SEP-1913, open).** `evidence` is meant to align with it.
- **A2A Agent Card signing.** These are self-signed by the agent. MCR tokens are signed by a third party, about
  someone else's server.
- **DNS-based MCP discovery drafts (draft-morrison-mcp-dns-discovery, draft-serra-mcp-discovery-uri).** These
  bootstrap one domain's own server. They are complementary.

## 15. Changelog

- 0.1 (2026-10-28): first internal draft. Reference resolver (7Maps) and client (resolver-js) built behind a switch;
  nothing published.
