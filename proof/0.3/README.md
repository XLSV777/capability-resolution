# Timestamp proof: Capability Resolution 0.3

This folder proves that `capability-resolution-0.3.md` existed, byte for byte, on 5 November 2026.
Two independent timestamps cover the same SHA-256 hash. Only the hash was sent out, never the text.

| What | Value |
| --- | --- |
| File | `capability-resolution-0.3.md` (the same bytes as `spec/capability-resolution-0.3.md`) |
| SHA-256 | `e347e32a75789ce70a6b2e1c942763aca55d0fa082e2a9defb7903a40b4f8c85` |
| RFC 3161 time (FreeTSA) | 2026-11-05 07:31:37 UTC |
| Bitcoin block (OpenTimestamps) | pending: the calendars anchor within a few hours, then this file and the `.ots` are updated |

## Files

- `capability-resolution-0.3.md`: the exact stamped copy.
- `capability-resolution-0.3.sha256`, `digest.bin`: the hash, as text and as 32 raw bytes.
- `spec.tsq`, `spec.tsr`: the RFC 3161 request and the signed reply from FreeTSA.
- `capability-resolution-0.3.md.ots`: the OpenTimestamps proof (alice and bob calendars).
- `ots-a.bin`, `ots-b.bin`: the original calendar receipts, kept as received.

## 1. Check the hash

```sh
sha256sum capability-resolution-0.3.md
# e347e32a75789ce70a6b2e1c942763aca55d0fa082e2a9defb7903a40b4f8c85
```

On Windows: `certutil -hashfile capability-resolution-0.3.md SHA256`.

## 2. Verify the RFC 3161 timestamp (FreeTSA)

Get the FreeTSA root and signing certificates from https://freetsa.org/index_en.php (`cacert.pem` and `tsa.crt`), then:

```sh
openssl ts -reply -in spec.tsr -text
openssl ts -verify -data capability-resolution-0.3.md -in spec.tsr -CAfile cacert.pem -untrusted tsa.crt
# Verification: OK
```

## 3. Verify the Bitcoin anchor (OpenTimestamps)

With the official client (https://github.com/opentimestamps/opentimestamps-client):

```sh
ots info capability-resolution-0.3.md.ots
ots verify capability-resolution-0.3.md.ots
```

`ots verify` needs a local Bitcoin node. Without one, use the web verifier at https://opentimestamps.org (drop in both the file and the `.ots`), or compare the merkle root that `ots info` computes with the block's merkle root on any block explorer.
