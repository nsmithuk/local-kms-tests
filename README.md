# Local KMS Tests

Test suite for AWS KMS operations against [Local KMS](https://github.com/nsmithuk/local-kms), a local implementation of AWS Key Management Service.

## Purpose

This repository contains integration tests that verify KMS functionality against a local KMS instance. Tests are organized by operation type:

- **management/** - Key lifecycle, aliases, scheduling deletion
- **seeded/** - Operations requiring pre-configured keys (sign/verify, encrypt/decrypt)
- **unseeded/** - Operations on fresh keys (key import, rotation, random generation)
- **asymmetric/** - Public key operations

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Start Local KMS (see [Local KMS documentation](https://github.com/nsmithuk/local-kms))

3. Create an `envvar` file with AWS credentials (for testing against real AWS KMS if needed):
   ```bash
   AWS_ACCESS_KEY_ID="your-access-key"
   AWS_SECRET_ACCESS_KEY="your-secret-key"
   AWS_SESSION_TOKEN="your-session-token"  # optional
   ```
   **Note:** The `envvar` file is gitignored. Use test/dummy credentials only.

## Running Tests

```bash
pytest
```

Run specific test categories:
```bash
pytest tests/management/
pytest tests/seeded/
pytest tests/unseeded/
```

## Configuration

The test suite uses a custom KMS client (`client/client.py`) that can target either:
- Local KMS instance (default)
- Real AWS KMS (set `real_kms=True`)

Tests load credentials from environment variables or the `envvar` file.
