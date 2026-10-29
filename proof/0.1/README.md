# Timestamp proof: Capability Resolution draft 0.1

This folder proves that `spec-draft-v0.1.md` existed, byte for byte, on 28 October 2026.
Two independent timestamps cover the same SHA-256 hash. Only the hash was ever sent out, never the text.

| What | Value |
| --- | --- |
| File | `spec-draft-v0.1.md` |
| SHA-256 | `446a22ab318141fed73f5e6b921f5e162f87eb87864fa2055a18b77df4d27947` |
| RFC 3161 time (FreeTSA) | 2026-10-28 11:50:47 UTC |
| Bitcoin block (OpenTimestamps) | height 973549, mined 2026-10-28 12:15:16 UTC |
| Block hash | `00000000000000000001686234d9d5a3711c0cd548a206d138d254accc550777` |
| Block merkle root | `a9d45f74bee23a2076696f05f1fda9d7ed2d098cc020369d934702ed29e29fb8` |

## Files

- `spec-draft-v0.1.md`: the exact stamped copy.
- `spec-draft-v0.1.sha256`, `digest.bin`: the hash, as text and as 32 raw bytes.
- `spec.tsq`, `spec.tsr`: the RFC 3161 request and the signed reply from FreeTSA.
- `spec-draft-v0.1.md.ots`: the complete OpenTimestamps proof, anchored in Bitcoin through two calendars (alice and bob).
- `ots-a.bin`, `ots-b.bin`: the original pending calendar receipts, kept as received.

## 1. Check the hash

```sh
sha256sum spec-draft-v0.1.md
# 446a22ab318141fed73f5e6b921f5e162f87eb87864fa2055a18b77df4d27947
```

On Windows: `certutil -hashfile spec-draft-v0.1.md SHA256`.

## 2. Verify the RFC 3161 timestamp (FreeTSA)

Get the FreeTSA root and signing certificates from https://freetsa.org/index_en.php (`cacert.pem` and `tsa.crt`), then:

```sh
openssl ts -reply -in spec.tsr -text
openssl ts -verify -data spec-draft-v0.1.md -in spec.tsr -CAfile cacert.pem -untrusted tsa.crt
# Verification: OK
```

The first command prints the signed time and the hash it covers. The second checks the signature and that the hash matches the file.

## 3. Verify the Bitcoin anchor (OpenTimestamps)

With the official client (https://github.com/opentimestamps/opentimestamps-client):

```sh
ots info spec-draft-v0.1.md.ots
ots verify spec-draft-v0.1.md.ots
```

`ots verify` needs a local Bitcoin node. Without one, use the web verifier at https://opentimestamps.org (drop in both the file and the `.ots`), or check by hand: `ots info` shows both paths ending in a Bitcoin attestation at block 973549, and the value they compute must equal that block's merkle root (shown above) on any block explorer.

Note: Bitcoin block times can be off by up to about two hours, so the anchor proves the file existed no later than roughly the time of block 973549. The RFC 3161 reply gives the precise time.
