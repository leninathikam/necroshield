# Signed evidence: what a signature proves, and what it does not

Signing is **optional and off by default**. The public demo does not hold a signing key, so its signing endpoints answer "not configured".

## How it works
- Algorithm: Ed25519 (RFC 8032). Signing uses the `cryptography` package, which is constant-time. Verification is done by the standalone verifier in pure Python (`scripts/verify_evidence.py`), which uses only public data.
- Format `necroshield.signed/1`: `{format, payload, signature: {alg, key_id, signed_at, sig}}`. The payload is a pair export, a benchmark bundle, or a live run.
- The signed bytes are the canonical JSON of `{format, key_id, signed_at, payload_sha256}`, where `payload_sha256` is the hash of the payload's canonical JSON. This binds the content, the key, and the claimed time together, and the payload's own `format` field is inside the hash, so a signature for a pair cannot be re-labelled as a bundle.
- `key_id` is the first 16 hex characters of the SHA-256 of the public key.
- Keys: create with `python -m necroshield keygen --out KEYFILE` (file mode 0600, never overwrites). The server reads a base64 seed from `NECROSHIELD_SIGNING_KEY`. The key is never written to the repository, never returned by the API, and never sent to the browser. An unusable key disables signing instead of half-working.
- Evidence that fails verification is never signed.

## Verifying
```
python scripts/verify_evidence.py signed.json --public-key <hex or base64 or file> [--pins pins.json]
```
- A signed file requires `--public-key`. A signature is never checked against a key taken from the file itself.
- Supplying `--public-key` for an unsigned file fails, so stripping a signature is detected when you expect one.
- The payload is then verified in full: the hash chain, decisions against the policy, outcomes re-derived from recorded effects, bundle arithmetic, and any pinned digests.
- The verifier rejects non-canonical `S`, malformed points, and small-order public keys or nonces.

## What a valid signature proves
- The holder of the private key attested to this exact payload (byte-for-byte canonical content) together with the claimed signing time.
- The payload has not changed since it was signed.
- Combined with the payload checks: the evidence is internally consistent, and its outcomes follow from the recorded effects.

## What it does not prove
- **That the run was honest.** Whoever holds the key can sign fabricated evidence. The signature moves trust to the key holder; it does not remove it.
- **Who holds the key.** Trust in the public key is established out of band: get it from the publisher by a channel other than the signed file. The server's `/api/signing` endpoint publishes the key, but a compromised server would publish a different one.
- **When it was signed.** `signed_at` is the signer's claim. There is no timestamp authority.
- **Freshness.** An older valid bundle still verifies. Check pair ids and dates yourself.
- **Revocation.** There is none. If a key is stolen, publish a new key and stop trusting the old one.
- **That the policy or scenario is good.** A signed bundle with a forged summary fails because the summary is recomputed; a signed bundle of a bad policy is still bad. A valid signature never makes an invalid summary valid (tested).
- **That the live-model behaviour is reproducible.** Live runs are signed as recorded, not re-executed.

## Tests
Altered evidence, altered claimed time, missing signature (when a key is demanded), a signed file with no key, the wrong key, an attacker re-signing forged content with their own key, a signature moved to another payload, a substituted policy, an invalid benchmark summary under a valid signature, malformed and non-canonical signatures, small-order keys, and the RFC 8032 published vectors are all covered in `backend/tests/test_signing.py`. CI additionally cross-checks signatures made by the `cryptography` package against the pure-Python verifier.
