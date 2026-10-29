# Capability Resolution

**Version 0.2 (draft), 2026-10-29.**

- **This version:** https://7it.co.il/standard/capability-resolution/0.2/
- **Latest version:** https://7it.co.il/standard/capability-resolution/
- **Source, issues and reference code:** https://github.com/XLSV777/capability-resolution
- **Editors:** 7IT Solutions. We welcome co-editors from other resolver, gateway or client projects.
- **License:** CC BY 4.0. Reference code: MIT.
- **Status:** an independent proposal, for use with the Model Context Protocol and other tool protocols. Not part of
  the Model Context Protocol specification, and not endorsed by Anthropic, the MCP maintainers, the Linux Foundation
  or any vendor.
- **Trademarks:** Model Context Protocol and MCP are trademarks of their respective owners.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as in RFC 2119 and RFC 8174 when, and only
when, they appear in capitals.

This document has two parts:

- **The core (sections 1 to 14)** is independent of any tool protocol. It says "server" for any network service an
  AI client can call for a job.
- **A binding (section 15)** says what a server and its canonical URL are for one tool protocol. This version
  defines one binding, for use with the Model Context Protocol.

## 1. Purpose

An AI agent, its client or its gateway often needs a tool for a job and does not know which server has one. It also
cannot tell, before connecting, whether that server answers today. Today it guesses, searches the web, or loads tool
lists from several servers.

This spec defines a small HTTP protocol for asking a **resolver** a single question: "which servers can do this job,
and did they answer when last checked?" The answer is a short list of candidates. Each candidate is signed by the
resolver and expires.

It works like DNS for capabilities:

- Many resolvers can exist and a client may use several.
- Answers are signed and expire.
- The client keeps the final decision.

A resolver never hosts servers, never connects a client to a server, and never sells placement.

What this spec is not:

- **Not a registry.** Registries record what publishers declare. A resolver adds what it observed, and MAY use
  registries as a source.
- **Not a server description format.** Server description documents describe a server. A resolver MAY point to them.
  The declaration file (section 13) is only a short pointer list that an owner writes by hand: endpoints, jobs,
  contact and which resolvers may list them.
- **Not a ranking method.** How a resolver chooses and orders candidates is its own method. It is outside this
  spec, and the spec does not require a resolver to disclose it.

## 2. Terms

- **Server:** a network service that offers tools to AI clients, reachable at an https URL. A binding (section 15)
  says which services count as servers for one tool protocol.
- **Binding:** the rules that apply this core to one tool protocol (section 15).
- **Declaration file:** the plain-text file a server owner publishes at `/.well-known/capabilities.txt` (section 13).
- **Canonical URL:** the server URL in the form given in section 4.
- **Resolver:** an HTTP service that implements sections 5 and 6.
- **Need:** a short plain-language description of a job, for example "send a transactional email".
- **Constraint:** a filter the client asks the resolver to apply (section 6.2).
- **Candidate:** one server in a resolve answer, carrying a signed token.
- **Record:** a resolver's signed statement about one server (section 6.3).
- **Token:** a JWS in compact serialization, signed by the resolver (section 8).
- **Client:** anything that calls a resolver: an agent host, a tool client, a gateway or a plugin.

## 3. Overview

```
client                                                   resolver (one of several)
  | GET /.well-known/capability-resolver  ------------->  {v, resolve, record, keys[], policy_url}
  | GET <resolve>?need=...&constraints=... ------------>  {candidates: [{id, url, status, checked_at, expires, evidence, jws}]}
  | verify each jws with keys[]; drop what fails
  | GET <record>?id=... (optional) -------------------->  {signed record, anchor, proof}
  | apply the client's own policy; maybe connect to the server (never the resolver's decision)
```

## 4. Server identity

**Canonical URL.** The binding says which URL of a server is its address. To put that URL in canonical form, a
resolver or client:

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
  SHA-256 over `"capability-server\n" + canonical URL`.

## 5. Discovery

A resolver publishes `GET /.well-known/capability-resolver` on its own origin, over https, as `application/json`:

```json
{
  "v": "0.2",
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
| `v` | yes | Spec version, `"0.2"`. |
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
  "v": "0.2",
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
- `status` is one of the following (the binding says what each one means for its protocol):
  - `ok`: the server answered and offered its tools without sign-in.
  - `sign_in`: the server answered and requires sign-in.
  - `down`: the server did not answer at its last check.
  - `unknown`: there is no check on file.
- A resolve answer SHOULD contain only `ok` and `sign_in` servers.
- `checked_at` is when the resolver last observed that status.
- `evidence` points to where the claim can be checked further.
- The fields next to `jws` are a convenience. Clients MUST use the values inside the verified token (section 7).
- Errors use a non-200 status with `{v, error, note}`:
  - `400` for a bad request.
  - `404` for an unknown server.
  - `429` for rate limits.
  - `503` when the resolver cannot answer or cannot sign.
- A resolver MUST NOT return unsigned candidates.

### 6.2 Constraints

`constraints` is a comma-separated list. This version defines:

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
  "v": "0.2", "iss": "https://resolver.example", "sub": "example:abcdefghijklmnop",
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
  header MUST contain `alg`, `kid`, and `typ` = `capability-resolver+jws`.
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
- **Tokens prove the resolver's claim, not the server's identity.** Connecting still needs the tool protocol's own
  authorization and TLS.

## 12. Conformance levels

| Level | Requires |
|---|---|
| `resolver-1` | Sections 5, 6.1 to 6.3 (with `proof` allowed to be null), 8 and 9, the resolver rules of 13.3 and 13.4, and at least one binding. |
| `resolver-2` | Level 1, plus `proof` on every record, and an append-only signed history whose heads are published daily. |
| `client-1` | Section 7 rules 1 to 7, and section 8 verification. |
| `server-1` | The server's host publishes a valid declaration file (section 13) that lists the server, fetchable under the rules of 13.4. A signature is not required. |

## 13. Server declaration file

Any server owner can publish one small text file that says which servers the site runs, what jobs they do, and
which resolvers may check and list them. It works like `robots.txt` and `security.txt`: a file anyone can write by
hand and place on a site, with no account and no registration.

```
GET https://<host>/.well-known/capabilities.txt
```

A minimal file:

```
Conformance: Capability Resolution 0.2
Contact: mailto:tools@example.com
Expires: 2027-04-30T00:00:00Z
Endpoint: https://mail.example.com/mcp
Protocol: mcp
Jobs: send a transactional email
Sign-in: none
Payment: none
```

### 13.1 Format

- The file is served as `text/plain`, SHOULD carry `charset=utf-8`, and MUST be valid UTF-8. A leading byte order
  mark is ignored.
- Each line is blank, a comment starting with `#`, or a field: `Name: value`. Field names are case-insensitive.
  Lines end with LF or CRLF. Spaces around the value are ignored.
- Fields that this version does not define are ignored. Lines that are not fields are ignored.
- The file has two kinds of fields. **File fields** apply to the whole file and may appear anywhere before
  `Signature`. **Server fields** belong to a server group: a group starts at an `Endpoint` line and runs until the
  next `Endpoint` line or the end of the file. A server field before the first `Endpoint` is an error.

There is no JSON form in this version. A server that wants a richer description already has one (a Server Card or
an agent card) and points to it with `Card`.

### 13.2 Fields

File fields:

| Field | Required | Value |
|---|---|---|
| `Conformance` | yes, once | `Capability Resolution <version>`, for example `Capability Resolution 0.2`. |
| `Contact` | yes, one or more | A `mailto:`, `https:` or `tel:` URI where the owner can be reached about these servers. |
| `Expires` | yes, once | An RFC 3339 date-time after which the file is stale. It SHOULD be less than a year ahead. |
| `Resolvers` | no, one or more | Which resolvers may check and list the servers (13.3). Absent means every resolver. |
| `Signature` | no, last | A signature over the file (13.5). |

Server fields, one group per server:

| Field | Required | Value |
|---|---|---|
| `Endpoint` | yes, starts a group | The server's https URL, the one a client connects to. It is compared in the canonical form of section 4, and each endpoint appears once. |
| `Protocol` | yes, once | A lower-case token naming the tool protocol. A binding defines its token (section 15 defines `mcp`). |
| `Jobs` | yes, one or more | A plain-language job the server does, 3 to 200 characters, in the same words a client would use for a need (section 6.1). Repeat the field for more jobs. |
| `Sign-in` | SHOULD, once | `none`, `optional` or `required`. |
| `Payment` | SHOULD, once | `none` (no call is charged) or `any` (some calls may be charged), matching the `payment` constraint (6.2). |
| `Card` | no, one or more | An https URL of a description document for this server, for example a Server Card or an agent card. |

A file is **valid** when it parses under 13.1, has every required field with a valid value, has not expired, and
every `Endpoint` is covered by its host (13.3).

### 13.3 Scope and the Resolvers field

**Which servers a file speaks for.** A file speaks only for endpoints on its own host or a subdomain of that host.
`https://example.com/.well-known/capabilities.txt` may list `https://mail.example.com/mcp`, but never
`https://mail.other.org/mcp`. Resolvers MUST ignore any endpoint outside that scope. For an endpoint, a resolver
uses the file on the endpoint's own host if there is one, and otherwise MAY use the file of a parent host that
lists it.

**Resolvers.** The value is a list of items separated by spaces or commas. The field may repeat; the items add up.

- `*`: every resolver may check and list these servers.
- `https://resolver.example`: this resolver may (an allow list).
- `-https://resolver.example`: this resolver may not (a deny).
- `none`: no resolver may.

A resolver is identified by its `iss` origin (section 5). A resolver is allowed when it is named or `*` is present,
and it is not denied and `none` is absent. A deny always wins over an allow.

A resolver:

1. MUST read the declaration file of a server's host (13.4) before it first lists that server, and again whenever
   its copy is older than 24 hours while it lists it.
2. MUST respect a deny. A denied resolver MUST NOT return the file's servers as candidates or serve records for them,
   from this file or from any other source, for as long as the deny stands. It stops as soon as it reads the deny,
   so within 24 hours of the owner publishing it (rule 1). Tokens it signed earlier may stay valid until they expire
   (section 8). It MAY keep the canonical URL to remember the deny.
3. MUST respect a deny in a file that has expired or is otherwise invalid. An invalid file grants nothing, but its
   deny still holds.
4. MUST treat the file as a claim, not proof. The file never sets a `status`. A resolver reports only what it
   observes (section 9.6): it checks each declared server itself before listing it, and when its observation and the
   file disagree (for example `Sign-in: none` but the server asks for sign-in), the observation wins. A resolver MAY
   use the declared `Payment` for the `payment:none` constraint, and SHOULD say at `policy_url` that it does.
5. MAY use the file to learn about servers it did not know. Allowing a resolver does not oblige it to list anything.
6. MUST treat `Jobs` and every other value as untrusted text (section 11).

A site without a file sets no rule here. Resolvers then work as they did before this section.

### 13.4 Fetching

A resolver or a checker that reads the file:

- uses https only, and never reads the file over plain http;
- sends a `User-Agent` that names the resolver;
- follows at most 3 redirects, and only to the same origin. A redirect to another origin means there is no file;
- reads at most 32 KiB (32768 bytes) and treats a larger file as invalid;
- on `200`, parses the file; on `404` or another `4xx`, treats the site as having no file;
- on a `5xx` or a network error, keeps using its last good copy for up to 7 days, and keeps any deny in it after
  that until a fetch succeeds;
- caches the file as its `Cache-Control` allows, but never uses a copy older than 24 hours when a fetch is possible.

Owners SHOULD serve the file with `Cache-Control: max-age` of at most 86400.

### 13.5 Signature (optional)

An owner MAY sign the file. The `Signature` field is then the last field, and its value is a JWS in compact
serialization with a detached payload (RFC 7515, Appendix F): `<header>..<signature>`.

- The payload is every byte of the file before the start of the `Signature` line.
- The protected header MUST contain `alg` `EdDSA` (Ed25519, RFC 8037), `typ` = `capabilities-txt+jws`, `kid`, and
  `jku`: an https URL on the same origin as the file that returns a JWK set (`{"keys": [...]}`).
- Content after the `Signature` line is an error.

A valid signature shows that whoever controls the key set on that origin wrote these exact bytes. It does not show
that the claims are true, and an unsigned file is as valid as a signed one. A resolver MAY prefer signed files when
two sources disagree.

### 13.6 Security considerations for the file

- **Suppressing someone else's server.** The scope rule in 13.3 stops a site from denying, or claiming, servers on a
  host it does not control.
- **False claims.** A file can claim jobs a server cannot do. Resolvers observe before listing (13.3 rule 4), so a
  false claim at most asks a resolver to look.
- **Fetching as an attack.** Resolvers fetch from many origins. The https-only, same-origin redirect and size rules
  in 13.4 bound what a hostile origin can make a resolver do.

## 14. Well-known URI registrations (to file after review)

Two suffixes, each filed under RFC 8615 ("Specification Required") once the text is stable:

| URI suffix | Used by | Section |
|---|---|---|
| `capability-resolver` | a resolver's discovery document (JSON) | 5 |
| `capabilities.txt` | a server owner's declaration file (plain text) | 13 |

For each:

- Change controller: the editors of this specification (to be transferred to a standards body if one adopts it).
- Specification document: this document.
- Status: provisional.
- Related information: none.

Neither suffix collides with a registered or proposed suffix as of 2026-10-29
(https://www.iana.org/assignments/well-known-uris/):

- `agent-card.json`, `api-catalog` and `oauth-protected-resource` are registered.
- `ai-catalog.json`, `mcp`, `mcp.json`, `mcp/server-card.json` and `mcp-server` are proposed.
- `agents.txt` and `agents.json` are proposed in draft-car-agents-txt-wellknown-00 (June 2026), a per-path list of
  what web agents may do on a site. `capabilities.txt` is a different file: it lists tool servers for resolvers and
  says which resolvers may list them.
- `capabilities.txt` was chosen over `capability.txt` (singular, a near twin), `capability-resolution` (too close to
  `capability-resolver`) and names with a protocol in them (the core is protocol-neutral). The `.txt` ending, as in
  `security.txt`, tells owners that it is a text file they edit by hand.

## 15. Binding for use with the Model Context Protocol

This section applies the core to servers that speak the Model Context Protocol. A resolver that follows it says so
at its `policy_url`.

- **Server.** A remote server that implements the Model Context Protocol over its Streamable HTTP transport (or the
  older HTTP with SSE transport) at an https endpoint. Local servers that run over stdio are out of scope.
- **Canonical URL.** The server's endpoint URL, the one a client connects to (for example
  `https://mail.example.com/mcp`), put in canonical form by section 4. A server whose endpoint moves is a new
  server unless the resolver follows a permanent redirect from the old endpoint.
- **Status.**
  - `ok`: the server completed initialization and listed its tools without authorization.
  - `sign_in`: the server answered and required authorization (for example HTTP 401 with the protocol's
    authorization metadata).
  - `down` and `unknown`: as in the core.
- **Handshake time** (`max_ms`): the time from the first request to a completed initialization.
- **Read-only** (`read_only`): a tool the server marks as read-only, or that the resolver judges read-only from its
  description.
- **Evidence.** `evidence` MAY take the shape of an `evidenceRef` from the trust-annotations work in that protocol
  (SEP-1913) when that settles. A candidate's `evidence` MAY link the server's Server Card.
- **Connecting.** A candidate does not replace the protocol's own authorization and TLS when the client connects.
- **Declaration file.** The `Protocol` token is `mcp`. `Endpoint` is the endpoint URL above. `Sign-in: required`
  means the server answers with the protocol's authorization challenge. `Card` SHOULD point to the server's Server
  Card when it has one. A server reaches `server-1` when its host publishes a valid file that lists it. Example, for
  a site with two servers:

  ```
  # https://example.com/.well-known/capabilities.txt
  Conformance: Capability Resolution 0.2
  Contact: mailto:tools@example.com
  Contact: https://example.com/support
  Expires: 2027-04-30T00:00:00Z
  Resolvers: * -https://resolver.unwanted.example

  Endpoint: https://mail.example.com/mcp
  Protocol: mcp
  Jobs: send a transactional email
  Jobs: check whether an email was delivered
  Sign-in: none
  Payment: none
  Card: https://mail.example.com/mcp/server-card

  Endpoint: https://example.com/billing/mcp
  Protocol: mcp
  Jobs: create an invoice
  Sign-in: required
  Payment: any
  ```

  A resolver that reads it still connects to each endpoint and records what it observes (13.3 rule 4).

## 16. Relation to other work

- **Server Cards and AI Catalog (SEP-2127).** These say what is at a known server. Capability Resolution says which
  servers fit a job and how they behaved. A declaration file points to a Server Card with `Card` instead of
  repeating it.
- **robots.txt (RFC 9309), security.txt (RFC 9116) and llms.txt.** The declaration file borrows their shape: one
  text file at a fixed path, `Field: value` lines, `Contact` and `Expires` from security.txt, and an allow and deny
  list read by automated visitors, as in robots.txt.
- **agents.txt (draft-car-agents-txt-wellknown).** Says what web agents may do on a site's paths. The declaration
  file says which tool servers a site runs and which resolvers may list them. A site can publish both.
- **The MCP Registry (registry.modelcontextprotocol.io).** Publisher-declared lifecycle, no health and no signed
  records. Resolvers MAY use it as a source.
- **Trust annotations, `evidenceRef` (SEP-1913, open).** `evidence` is meant to align with it (section 15).
- **A2A Agent Card signing.** These are self-signed by the agent. Capability Resolution tokens are signed by a third
  party, about someone else's server.
- **DNS-based discovery drafts for that protocol (draft-morrison-mcp-dns-discovery,
  draft-serra-mcp-discovery-uri).** These bootstrap one domain's own server. They are complementary.

## 17. Changelog

- 0.2 (2026-10-29): added the server declaration file, `/.well-known/capabilities.txt` (section 13): plain
  `Field: value` lines with `Endpoint`, `Protocol`, `Jobs`, `Sign-in`, `Payment`, `Card`, `Contact`, `Expires`,
  `Conformance`, a `Resolvers` allow and deny list, and an optional detached signature. Resolvers must respect a
  deny, treat the file as a claim and observe before listing, and fetch it over https with same-origin redirects
  only, 32 KiB at most, cached at most 24 hours. New conformance level `server-1`; `resolver-1` now includes the
  resolver rules of 13.3 and 13.4. Second IANA stub (`capabilities.txt`). Sections from 13 on are renumbered: the
  registrations are now 14, the binding 15.
- 0.2 (2026-10-28): renamed to Capability Resolution, a tool-agnostic core plus a binding for use with the Model
  Context Protocol (now section 15). The well-known suffix is now `capability-resolver` (was `mcp-resolver`), the JWS
  `typ` is `capability-resolver+jws` (was `mcp-resolver+jws`), and the reference ID hash prefix is
  `"capability-server\n"` (was `"mcp-server\n"`), so reference IDs change. `v` is `"0.2"`. Trademark notice added.
- 0.1 (2026-10-28): first draft, not published. Its exact text was timestamped (RFC 3161 and OpenTimestamps) and
  is kept with its proofs in the source repository.
