# vantaq: Evidence Verification Tool

The `vantaq` tool verifies attestation evidence signatures off-device.

For full operational flow (mTLS setup, challenge/evidence APIs, and compose examples), see `docs/RUNBOOK.md`.

## Build

From repository root:

```bash
make build
```

Binary path:

```bash
./bin/verify_evidence
```

## Usage

```bash
./bin/verify_evidence <evidence.json> <device_public_key_or_cert.pem>
```

- `<evidence.json>`: Evidence JSON retrieved from `vantaqd`.
- `<device_public_key_or_cert.pem>`: Device public key or certificate in PEM format.

## Getting Evidence JSON

Evidence is typically created via:

- `POST /v1/attestation/evidence` (requires `challenge_id`, `nonce`, and non-empty `claims`)

and can later be retrieved via:

- `GET /v1/attestation/evidence/latest`
- `GET /v1/attestation/evidence/{evidence_id}`

## Exit Codes

- `0`: Signature is valid.
- `1`: Signature is invalid, or an error occurred (missing file, malformed JSON, invalid key input).

## How It Works

1. Parses evidence JSON fields.
2. Reconstructs the canonical signed payload exactly as the device signed it.
3. Verifies the base64 signature using the supplied public key/certificate.

## License

This tool is licensed under:

- `AGPL-3.0-only`, or
- `LicenseRef-Commercial`

See repository license files and source SPDX headers for details.
See `LICENSES/` for full license texts.
