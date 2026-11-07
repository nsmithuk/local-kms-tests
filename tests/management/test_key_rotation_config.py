def test_enable_disable_key_rotation(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT"},
    )
    assert code == 200
    key_id = content["KeyMetadata"]["KeyId"]

    code, content = kms_client.post(
        "EnableKeyRotation",
        {"KeyId": key_id},
    )
    assert code == 200

    code, content = kms_client.post(
        "GetKeyRotationStatus",
        {"KeyId": key_id},
    )
    assert code == 200
    assert isinstance(content, dict)
    assert content.get("KeyRotationEnabled") is True

    code, content = kms_client.post(
        "DisableKeyRotation",
        {"KeyId": key_id},
    )
    assert code == 200

    code, content = kms_client.post(
        "GetKeyRotationStatus",
        {"KeyId": key_id},
    )
    assert code == 200
    assert isinstance(content, dict)
    assert content.get("KeyRotationEnabled") is False


def test_get_key_rotation_status_default(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT"},
    )
    assert code == 200
    key_id = content["KeyMetadata"]["KeyId"]

    code, content = kms_client.post(
        "GetKeyRotationStatus",
        {"KeyId": key_id},
    )
    assert code == 200
    assert isinstance(content, dict)
    assert "KeyRotationEnabled" in content
    assert isinstance(content["KeyRotationEnabled"], bool)


def test_enable_key_rotation_with_period(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT"},
    )
    assert code == 200
    key_id = content["KeyMetadata"]["KeyId"]

    code, content = kms_client.post(
        "EnableKeyRotation",
        {"KeyId": key_id, "RotationPeriodInDays": 180},
    )
    assert code == 200

    code, content = kms_client.post(
        "GetKeyRotationStatus",
        {"KeyId": key_id},
    )
    assert code == 200
    assert content.get("KeyRotationEnabled") is True
    if "RotationPeriodInDays" in content:
        assert content["RotationPeriodInDays"] == 180


def test_enable_rotation_on_asymmetric_key_fails(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY"},
    )
    assert code == 200
    key_id = content["KeyMetadata"]["KeyId"]

    code, content = kms_client.post(
        "EnableKeyRotation",
        {"KeyId": key_id},
    )
    assert code != 200
    assert isinstance(content, dict)
    assert "__type" in content
