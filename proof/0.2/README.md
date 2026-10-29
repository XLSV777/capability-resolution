# Timestamp proof: Capability Resolution 0.2

This folder proves that `capability-resolution-0.2.md` existed, byte for byte, on 29 October 2026.
Two independent timestamps cover the same SHA-256 hash. Only the hash was sent out, never the text.

| What | Value |
| --- | --- |
| File | `capability-resolution-0.2.md` (the same bytes as `spec/capability-resolution-0.2.md`) |
| SHA-256 | `2169d03f74709ccacc9e1d082f7312ab85b83eba6a8cdc641fe5d25c5f1f4c76` |
| RFC 3161 time (FreeTSA) | 2026-10-29 07:21:55 UTC |
| Bitcoin block (OpenTimestamps) | height 973658, mined 2026-10-29 07:40:57 UTC |
| Block hash | `00000000000000000001bd0ff39e662af35fa8687f2c1a09d21a38adfeb98059` |
| Block merkle root | `c5deed1d704caaaac6dc91f6dae6ad68de9e3c0afc146e6b455f2d008a282c1e` |

## Files

- `capability-resolution-0.2.md`: the exact stamped copy.
- `capability-resolution-0.2.sha256`, `digest.bin`: the hash, as text and as 32 raw bytes.
- `spec.tsq`, `spec.tsr`: the RFC 3161 request and the signed reply from FreeTSA.
- `capability-resolution-0.2.md.ots`: the complete OpenTimestamps proof, anchored in Bitcoin through two calendars (alice and bob).
- `ots-a.bin`, `ots-b.bin`: the original calendar receipts, kept as received.

## 1. Check the hash

```sh
sha256sum capability-resolution-0.2.md
# 2169d03f74709ccacc9e1d082f7312ab85b83eba6a8cdc641fe5d25c5f1f4c76
```

On Windows: `certutil -hashfile capability-resolution-0.2.md SHA256`.

## 2. Verify the RFC 3161 timestamp (FreeTSA)

Get the FreeTSA root and signing certificates from https://freetsa.org/index_en.php (`cacert.pem` and `tsa.crt`), then:

```sh
openssl ts -reply -in spec.tsr -text
openssl ts -verify -data capability-resolution-0.2.md -in spec.tsr -CAfile cacert.pem -untrusted tsa.crt
# Verification: OK
```

## 3. Verify the Bitcoin anchor (OpenTimestamps)

With the official client (https://github.com/opentimestamps/opentimestamps-client):

```sh
ots info capability-resolution-0.2.md.ots
ots verify capability-resolution-0.2.md.ots
```

`ots verify` needs a local Bitcoin node. Without one, use the web verifier at https://opentimestamps.org (drop in both the file and the `.ots`), or check by hand: `ots info` shows both paths ending in a Bitcoin attestation at block 973658, and the value they compute must equal that block's merkle root (shown above) on any block explorer.

Note: Bitcoin block times can be off by up to about two hours, so the anchor proves the file existed no later than roughly the time of block 973658. The RFC 3161 reply gives the precise time.
