import re
import pytest
import uuid
from tests.generic import ALLOWED_KEY_USAGE_BY_SPEC

VALID_CREATE_KEY_CASES = [
    pytest.param(
        key_spec,
        key_usage,
        id=f"{key_spec}-{key_usage.lower()}",
    )
    for key_spec, usages in ALLOWED_KEY_USAGE_BY_SPEC.items()
    for key_usage in usages
]

# --- Expected algorithm lists (AWS KMS behaviour) ---

EXPECTED_ENCRYPTION_ALGS = {
    "SYMMETRIC_DEFAULT": {"SYMMETRIC_DEFAULT"},
    # RSA encryption keys support OAEP SHA-1 and SHA-256 in KMS.
    "RSA_2048": {"RSAES_OAEP_SHA_1", "RSAES_OAEP_SHA_256"},
    "RSA_3072": {"RSAES_OAEP_SHA_1", "RSAES_OAEP_SHA_256"},
    "RSA_4096": {"RSAES_OAEP_SHA_1", "RSAES_OAEP_SHA_256"},
    # (SM2 would be SM2PKE, but you’re not supporting it.)
}

EXPECTED_SIGNING_ALGS = {
    # RSA signing keys support PSS + PKCS1 variants.
    "RSA_2048": {
        "RSASSA_PSS_SHA_256",
        "RSASSA_PSS_SHA_384",
        "RSASSA_PSS_SHA_512",
        "RSASSA_PKCS1_V1_5_SHA_256",
        "RSASSA_PKCS1_V1_5_SHA_384",
        "RSASSA_PKCS1_V1_5_SHA_512",
    },
    "RSA_3072": {
        "RSASSA_PSS_SHA_256",
        "RSASSA_PSS_SHA_384",
        "RSASSA_PSS_SHA_512",
        "RSASSA_PKCS1_V1_5_SHA_256",
        "RSASSA_PKCS1_V1_5_SHA_384",
        "RSASSA_PKCS1_V1_5_SHA_512",
    },
    "RSA_4096": {
        "RSASSA_PSS_SHA_256",
        "RSASSA_PSS_SHA_384",
        "RSASSA_PSS_SHA_512",
        "RSASSA_PKCS1_V1_5_SHA_256",
        "RSASSA_PKCS1_V1_5_SHA_384",
        "RSASSA_PKCS1_V1_5_SHA_512",
    },

    # NIST ECC signing alg is curve-dependent.
    "ECC_NIST_P256": {"ECDSA_SHA_256"},
    "ECC_NIST_P384": {"ECDSA_SHA_384"},
    "ECC_NIST_P521": {"ECDSA_SHA_512"},

    # secp256k1 signs with ECDSA SHA-256 in KMS.
    "ECC_SECG_P256K1": {"ECDSA_SHA_256"},

    # ML-DSA
    "ML_DSA_44": {"ML_DSA_SHAKE_256"},
    "ML_DSA_65": {"ML_DSA_SHAKE_256"},
    "ML_DSA_87": {"ML_DSA_SHAKE_256"},

    # Edwards25519 supports both RAW and pre-hash signing algorithms in KMS.
    "ECC_NIST_EDWARDS25519": {"ED25519_SHA_512", "ED25519_PH_SHA_512"},
}

EXPECTED_MAC_ALGS = {
    "HMAC_224": {"HMAC_SHA_224"},
    "HMAC_256": {"HMAC_SHA_256"},
    "HMAC_384": {"HMAC_SHA_384"},
    "HMAC_512": {"HMAC_SHA_512"},
}

EXPECTED_KEY_AGREEMENT_ALGS = {"ECDH"}


def _assert_optional_absent(md: dict, *keys: str) -> None:
    for k in keys:
        assert k not in md or md[k] in (None, "", [], {}), f"did not expect {k} in KeyMetadata (got {md.get(k)!r})"


def _assert_key_metadata_from_create_key(md: dict, key_spec: str, key_usage: str) -> None:
    assert isinstance(md, dict)

    # ---- Core fields (CreateKey examples include these) ----
    # KeyId is required by the API model.
    assert "KeyId" in md and isinstance(md["KeyId"], str) and md["KeyId"]
    # Arn + AWSAccountId are "not required" in the model, but are typically present in CreateKey output.
    assert "Arn" in md and isinstance(md["Arn"], str) and md["Arn"]
    assert "AWSAccountId" in md and isinstance(md["AWSAccountId"], str) and md["AWSAccountId"]

    # CreationDate is a Timestamp, which your JSON client will likely represent as a string.
    assert "CreationDate" in md
    assert isinstance(md["CreationDate"], (int, float))
    assert md["CreationDate"] > 0 # example float 1766856943.524

    assert md.get("Description") == ""  # default for CreateKey when not set
    assert md.get("Enabled") is True
    assert md.get("KeyManager") == "CUSTOMER"
    assert md.get("KeyState") == "Enabled"
    assert md.get("Origin") == "AWS_KMS"
    assert md.get("MultiRegion") in (False, True)  # default is False; keep type-safe
    assert md.get("MultiRegion") is False  # you’re not creating MRKs in this test

    # Echoed request values
    assert md.get("KeyUsage") == key_usage
    assert md.get("KeySpec") == key_spec

    # Legacy field: if present, it should match KeySpec
    if "CustomerMasterKeySpec" in md and md["CustomerMasterKeySpec"] is not None:
        assert md["CustomerMasterKeySpec"] == key_spec

    # ---- Algorithm fields are conditional on KeyUsage ----
    if key_usage == "ENCRYPT_DECRYPT":
        assert "EncryptionAlgorithms" in md and isinstance(md["EncryptionAlgorithms"], list)
        expected = EXPECTED_ENCRYPTION_ALGS.get(key_spec)
        assert expected is not None, f"missing expected encryption algorithms mapping for {key_spec}"
        assert expected.issubset(set(md["EncryptionAlgorithms"])), (
            f"EncryptionAlgorithms for {key_spec} missing expected values; "
            f"expected ⊆ {sorted(expected)}, got {md['EncryptionAlgorithms']}"
        )

        # Commonly present for symmetric keys (and EXTERNAL-origin symmetric keys); if you return it, validate it.
        if key_spec == "SYMMETRIC_DEFAULT" and "CurrentKeyMaterialId" in md:
            assert isinstance(md["CurrentKeyMaterialId"], str)
            assert re.fullmatch(r"[a-f0-9]{64}", md["CurrentKeyMaterialId"]), md["CurrentKeyMaterialId"]

        _assert_optional_absent(md, "SigningAlgorithms", "MacAlgorithms", "KeyAgreementAlgorithms")

    elif key_usage == "SIGN_VERIFY":
        assert "SigningAlgorithms" in md and isinstance(md["SigningAlgorithms"], list)
        expected = EXPECTED_SIGNING_ALGS.get(key_spec)
        assert expected is not None, f"missing expected signing algorithms mapping for {key_spec}"
        assert expected.issubset(set(md["SigningAlgorithms"])), (
            f"SigningAlgorithms for {key_spec} missing expected values; "
            f"expected ⊆ {sorted(expected)}, got {md['SigningAlgorithms']}"
        )
        _assert_optional_absent(md, "EncryptionAlgorithms", "MacAlgorithms", "KeyAgreementAlgorithms")

    elif key_usage == "GENERATE_VERIFY_MAC":
        assert "MacAlgorithms" in md and isinstance(md["MacAlgorithms"], list)
        expected = EXPECTED_MAC_ALGS.get(key_spec)
        assert expected is not None, f"missing expected mac algorithms mapping for {key_spec}"
        assert expected.issubset(set(md["MacAlgorithms"])), (
            f"MacAlgorithms for {key_spec} missing expected values; "
            f"expected ⊆ {sorted(expected)}, got {md['MacAlgorithms']}"
        )
        _assert_optional_absent(md, "EncryptionAlgorithms", "SigningAlgorithms", "KeyAgreementAlgorithms")

    elif key_usage == "KEY_AGREEMENT":
        assert "KeyAgreementAlgorithms" in md and isinstance(md["KeyAgreementAlgorithms"], list)
        assert EXPECTED_KEY_AGREEMENT_ALGS.issubset(set(md["KeyAgreementAlgorithms"])), (
            f"KeyAgreementAlgorithms missing expected values; expected ⊆ {sorted(EXPECTED_KEY_AGREEMENT_ALGS)}, "
            f"got {md['KeyAgreementAlgorithms']}"
        )
        _assert_optional_absent(md, "EncryptionAlgorithms", "SigningAlgorithms", "MacAlgorithms")

    else:
        raise AssertionError(f"Unhandled KeyUsage: {key_usage}")

    # ---- Fields that should not appear in this basic CreateKey path ----
    # (Only present for custom key stores, external key stores, scheduled deletion, imported key material, multi-region, etc.)
    _assert_optional_absent(
        md,
        "CloudHsmClusterId",
        "CustomKeyStoreId",
        "DeletionDate",
        "ExpirationModel",
        "ValidTo",
        "XksKeyConfiguration",
        "MultiRegionConfiguration",
        "PendingDeletionWindowInDays",
    )


def _assert_schedule_key_deletion_response(
    resp: dict,
    expected_key_id: str,
    pending_window_days: int,
) -> None:
    assert isinstance(resp, dict)

    # --- Required fields ---
    required_fields = {
        "KeyId",
        "KeyState",
        "DeletionDate",
        "PendingWindowInDays",
    }

    missing = required_fields - resp.keys()
    assert not missing, f"Missing required fields: {missing}"

    # ---

    # KeyId
    assert resp["KeyId"] == expected_key_id

    # KeyState (AWS sets this immediately)
    assert resp["KeyState"] == "PendingDeletion"

    # PendingWindowInDays
    assert resp["PendingWindowInDays"] == pending_window_days

    # DeletionDate
    deletion_date = resp["DeletionDate"]
    assert isinstance(deletion_date, (int, float))
    assert deletion_date > 0

    # # DeletionDate ≈ now + pending_window_days
    # now = time.time()
    # expected = now + (pending_window_days * 86400)
    #
    # # Allow reasonable execution / clock skew
    # tolerance_seconds = 5 * 60  # ±5 minutes
    #
    # assert expected - tolerance_seconds <= deletion_date <= expected + tolerance_seconds, (
    #     f"DeletionDate out of range: got={deletion_date}, "
    #     f"expected≈{expected} ±{tolerance_seconds}s"
    # )


@pytest.mark.parametrize("key_spec,key_usage", VALID_CREATE_KEY_CASES)
def test_create_key_valid_combinations(kms_client, key_spec, key_usage):
    # if key_spec != "ML_DSA_44":
    #     pytest.skip("Temporarily only testing ML_DSA_44 keys")

    print(f"Creating key with spec {key_spec} and usage {key_usage}")

    code, content = kms_client.post(
        "CreateKey",
        {
            "KeySpec": key_spec,
            "KeyUsage": key_usage,
        },
    )
    assert code == 200
    assert isinstance(content, dict)

    assert "KeyMetadata" in content
    md = content["KeyMetadata"]
    _assert_key_metadata_from_create_key(md, key_spec=key_spec, key_usage=key_usage)

    # Keep your existing basics too (redundant, but fine)
    assert md.get("KeyUsage") == key_usage
    assert md.get("KeySpec") == key_spec

    # ---

    alias_name = f"alias/test-{key_spec.lower()}-{key_usage.lower()}-{uuid.uuid4().hex[:8]}"
    key_id = md["KeyId"]
    key_arn = md["Arn"]

    code, content = kms_client.post(
        "CreateAlias",
        {
            "TargetKeyId": key_id,
            "AliasName": alias_name,
        },
    )
    assert code == 200

    # ---

    code, content = kms_client.post(
        "DescribeKey",
        {
            "KeyId": alias_name,
        },
    )
    assert code == 200
    assert isinstance(content, dict)

    # ---

    code, content = kms_client.post(
        "DeleteAlias",
        {
            "AliasName": alias_name,
        },
    )
    assert code == 200

    # ---

    pending_window_days = 7
    code, content = kms_client.post(
        "ScheduleKeyDeletion",
        {
            "KeyId": key_id,
            "PendingWindowInDays": pending_window_days,
        },
    )
    assert code == 200
    _assert_schedule_key_deletion_response(
        content,
        expected_key_id=key_arn,
        pending_window_days=pending_window_days,
    )
