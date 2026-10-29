# capability-resolution-test-vectors

By 7IT Solutions: https://7it.co.il/standard/capability-resolution/

```sh
npm install capability-resolution-test-vectors
```

Capability Resolution 0.2 test vectors.

Signed tokens with their expected verdicts, for checking a client's signature and expiry handling (spec section 8)
against the same inputs as the reference client.

- `vectors.json`: the key set (`keys`) and the vectors. Each vector has `jws`, `now` (seconds), `iss`, the key names
  to verify with, and `expect` (`valid`, and for invalid vectors the reference client's `error`).
- `test-key.public.jwk.json`: the main test key as a public JWK.
- `generate.mjs`: rebuilds both files with a fresh throwaway key. The private key is never written to disk.

The verdict (`valid`) is what a conforming client must reach. Error names are what the reference client returns and
are informative only.

Capability Resolution 0.2, open specification by 7IT Solutions, CC BY 4.0. The vectors are MIT, like the reference code.
