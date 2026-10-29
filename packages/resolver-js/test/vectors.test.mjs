// The signed test vectors (packages/test-vectors) through the client's verifier: every verdict must match.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyToken } from '../src/index.js';

const file = JSON.parse(readFileSync(new URL('../../test-vectors/vectors.json', import.meta.url), 'utf8'));

test('vector file: throwaway key published, both verdicts present', () => {
  assert.ok(file.keys.test && !('d' in file.keys.test), 'public test key only');
  assert.match(file.spec, /^Capability Resolution 0\.2, open draft by 7IT Solutions, CC BY 4\.0/);
  assert.ok(file.vectors.some((v) => v.expect.valid) && file.vectors.some((v) => !v.expect.valid));
  const pub = JSON.parse(readFileSync(new URL('../../test-vectors/test-key.public.jwk.json', import.meta.url), 'utf8'));
  assert.deepEqual(pub, file.keys.test);
});

for (const v of file.vectors) {
  test(`vector ${v.name}: ${v.expect.valid ? 'valid' : 'invalid (' + v.expect.error + ')'}`, () => {
    const keys = v.keys.map((n) => file.keys[n]);
    const r = verifyToken(v.jws, keys, v.now, { iss: v.iss });
    assert.equal(r.ok, v.expect.valid, v.description);
    if (!v.expect.valid) assert.equal(r.error, v.expect.error, v.description);
  });
}
