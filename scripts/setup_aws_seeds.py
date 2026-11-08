#!/usr/bin/env python3
"""
Provision the seeded KMS keys required by tests/seeded/ and tests/asymmetric/
when running the test suite against real AWS KMS. Idempotent: skips any alias
that already exists.

To clean up afterwards, run: python scripts/kms_cleanup.py --execute

Usage:
    python scripts/setup_aws_seeds.py
"""

import os
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client import KmsClient


# (alias, KeySpec, KeyUsage)
SEED_KEYS = [
    ("alias/seed_symmetric_default_encrypt_decrypt",  "SYMMETRIC_DEFAULT",     "ENCRYPT_DECRYPT"),
    ("alias/seed_rsa_2048_encrypt_decrypt",           "RSA_2048",              "ENCRYPT_DECRYPT"),
    ("alias/seed_rsa_3072_encrypt_decrypt",           "RSA_3072",              "ENCRYPT_DECRYPT"),
    ("alias/seed_rsa_4096_encrypt_decrypt",           "RSA_4096",              "ENCRYPT_DECRYPT"),
    ("alias/seed_rsa_2048_sign_verify",               "RSA_2048",              "SIGN_VERIFY"),
    ("alias/seed_rsa_3072_sign_verify",               "RSA_3072",              "SIGN_VERIFY"),
    ("alias/seed_rsa_4096_sign_verify",               "RSA_4096",              "SIGN_VERIFY"),
    ("alias/seed_ecc_nist_p256_sign_verify",          "ECC_NIST_P256",         "SIGN_VERIFY"),
    ("alias/seed_ecc_nist_p384_sign_verify",          "ECC_NIST_P384",         "SIGN_VERIFY"),
    ("alias/seed_ecc_nist_p521_sign_verify",          "ECC_NIST_P521",         "SIGN_VERIFY"),
    ("alias/seed_ecc_secg_p256k1_sign_verify",        "ECC_SECG_P256K1",       "SIGN_VERIFY"),
    ("alias/seed_ecc_nist_edwards25519_sign_verify",  "ECC_NIST_EDWARDS25519", "SIGN_VERIFY"),
    ("alias/seed_ml_dsa_44_sign_verify",              "ML_DSA_44",             "SIGN_VERIFY"),
    ("alias/seed_ml_dsa_65_sign_verify",              "ML_DSA_65",             "SIGN_VERIFY"),
    ("alias/seed_ml_dsa_87_sign_verify",              "ML_DSA_87",             "SIGN_VERIFY"),
    ("alias/seed_hmac_224_generate_verify_mac",       "HMAC_224",              "GENERATE_VERIFY_MAC"),
    ("alias/seed_hmac_256_generate_verify_mac",       "HMAC_256",              "GENERATE_VERIFY_MAC"),
    ("alias/seed_hmac_384_generate_verify_mac",       "HMAC_384",              "GENERATE_VERIFY_MAC"),
    ("alias/seed_hmac_512_generate_verify_mac",       "HMAC_512",              "GENERATE_VERIFY_MAC"),
    ("alias/seed_ecc_nist_p256_key_agreement",        "ECC_NIST_P256",         "KEY_AGREEMENT"),
    ("alias/seed_ecc_nist_p384_key_agreement",        "ECC_NIST_P384",         "KEY_AGREEMENT"),
    ("alias/seed_ecc_nist_p521_key_agreement",        "ECC_NIST_P521",         "KEY_AGREEMENT"),
]


def _alias_exists(client: KmsClient, alias: str) -> tuple[bool, str | None]:
    """Returns (exists, key_id). key_id is None if the alias does not exist."""
    code, content = client.post("DescribeKey", {"KeyId": alias})
    if code == 200:
        return True, content["KeyMetadata"]["KeyId"]
    return False, None


def provision(client: KmsClient) -> None:
    created = skipped = failed = 0

    for alias, key_spec, key_usage in SEED_KEYS:
        exists, _ = _alias_exists(client, alias)
        if exists:
            print(f"[SKIP]   {alias} (already exists)")
            skipped += 1
            continue

        code, content = client.post("CreateKey", {"KeySpec": key_spec, "KeyUsage": key_usage})
        if code != 200:
            print(f"[FAIL]   CreateKey for {alias}: {content}")
            failed += 1
            continue

        key_id = content["KeyMetadata"]["KeyId"]

        code, content = client.post("CreateAlias", {"AliasName": alias, "TargetKeyId": key_id})
        if code != 200:
            print(f"[FAIL]   CreateAlias {alias} -> {key_id}: {content}")
            failed += 1
            continue

        print(f"[CREATE] {alias}  ({key_spec} / {key_usage})  KeyId: {key_id}")
        created += 1

    print(f"\nDone. created={created}  skipped={skipped}  failed={failed}")
    if failed:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.parse_args()

    client = KmsClient(
        kms_url="",
        aws_access_key=os.environ["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        aws_session_token=os.getenv("AWS_SESSION_TOKEN"),
        real_kms=True,
    )

    provision(client)


if __name__ == "__main__":
    main()
