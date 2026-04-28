# Verifier CLI: Evidence Verification Tool

This tool allows off-device verification of attestation evidence signatures.

## Usage

```bash
./verify_evidence <evidence.json> <public_key.pem>
```

- `<evidence.json>`: The JSON evidence file retrieved from the device.
- `<public_key.pem>`: The device's public key (PEM format) or certificate.

## Exit Codes

- `0`: Signature is valid.
- `1`: Signature is invalid, or an error occurred (missing file, malformed JSON).

## How it works

1. Parses the evidence JSON to extract all fields.
2. Reconstructs the canonical signed payload exactly as the device did.
3. Verifies the base64-encoded signature against the payload using the provided public key.
