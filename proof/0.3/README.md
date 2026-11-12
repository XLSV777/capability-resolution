# Timestamp proof: Capability Resolution 0.3

This folder proves that `capability-resolution-0.3.md` existed, byte for byte, on 5 November 2026.
Two independent timestamps cover the same SHA-256 hash. Only the hash was sent out, never the text.

| What | Value |
| --- | --- |
| File | `capability-resolution-0.3.md` (the same bytes as `spec/capability-resolution-0.3.md`) |
| SHA-256 | `e347e32a75789ce70a6b2e1c942763aca55d0fa082e2a9defb7903a40b4f8c85` |
| RFC 3161 time (FreeTSA) | 2026-11-05 07:31:37 UTC |
| Bitcoin block (OpenTimestamps) | height 974641, mined 2026-11-05 07:57:24 UTC |
| Block hash | `000000000000000000008ebda47eb5532da7b2ff88002ccb0995b756dd2fa133` |
| Block merkle root | `8167986ee1da6bc773ede3b495bb643af2b7288ae0bc8f3175303d128d0e0c9b` |

## Files

- `capability-resolution-0.3.md`: the exact stamped copy.
- `capability-resolution-0.3.sha256`, `digest.bin`: the hash, as text and as 32 raw bytes.
- `spec.tsq`, `spec.tsr`: the RFC 3161 request and the signed reply from FreeTSA.
- `capability-resolution-0.3.md.ots`: the complete OpenTimestamps proof, anchored in Bitcoin through two calendars (alice and bob).
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

`ots verify` needs a local Bitcoin node. Without one, use the web verifier at https://opentimestamps.org (drop in both the file and the `.ots`), or check by hand: `ots info` shows both paths ending in a Bitcoin attestation at block 974641, and the value they compute must equal that block's merkle root (shown above) on any block explorer.

Note: Bitcoin block times can be off by up to about two hours, so the anchor proves the file existed no later than roughly the time of block 974641. The RFC 3161 reply gives the precise time.
