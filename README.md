# Local KMS Tests

Test suite for AWS KMS operations against [Local KMS](https://github.com/nsmithuk/local-kms), a local implementation of AWS Key Management Service.

## Test categories

- **management/** - Key lifecycle, aliases, scheduling deletion
- **seeded/** - Operations requiring pre-configured keys (sign/verify, encrypt/decrypt)
- **unseeded/** - Operations on fresh keys (key import, rotation, random generation)
- **asymmetric/** - Public key operations

---

## Running against Local KMS

### 1. Set up the Python environment

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Start Local KMS

See [Local KMS documentation](https://github.com/nsmithuk/local-kms). Local KMS must be running with a seed file that provisions the aliases listed in `tests/constants.py` (e.g. `alias/seed_rsa_2048_sign_verify`).

### 3. Run the tests

```bash
pytest
```

Run a specific category or file:

```bash
pytest tests/management/
pytest tests/seeded/
pytest tests/unseeded/
pytest tests/management/test_create_key_defaults.py
pytest tests/management/test_create_key_defaults.py::test_create_key_defaults_to_symmetric
```

The default target is `http://localhost:8080`. Override with `KMS_URL`:

```bash
KMS_URL=http://localhost:9090 pytest
```

---

## Running against real AWS KMS

### 1. Set up the Python environment (if not already done)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Export AWS credentials

Paste your credentials into the terminal as environment variables:

```bash
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
```

### 3. Provision seed keys

The `tests/seeded/` and `tests/asymmetric/` tests require pre-existing keys with specific aliases. Create them once per AWS account/region:

```bash
python scripts/setup_aws_seeds.py
```

This is idempotent — safe to re-run; it skips aliases that already exist.

### 4. Run the tests

```bash
REAL_KMS=true pytest
```

### 5. Clean up

Schedule deletion of all customer-managed keys created by the tests (including seed keys):

```bash
# Dry run first — review what will be deleted
python scripts/kms_cleanup.py

# Then execute
python scripts/kms_cleanup.py --execute
```
