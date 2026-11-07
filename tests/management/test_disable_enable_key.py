from base64 import b64encode


def test_disable_key_prevents_usage(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT"},
    )
    assert code == 200
    key_id = content["KeyMetadata"]["KeyId"]

    code, _ = kms_client.post("DisableKey", {"KeyId": key_id})
    assert code == 200

    code, content = kms_client.post("DescribeKey", {"KeyId": key_id})
    assert code == 200
    assert content["KeyMetadata"]["Enabled"] is False
    assert content["KeyMetadata"]["KeyState"] == "Disabled"

    code, content = kms_client.post(
        "Encrypt",
        {
            "KeyId": key_id,
            "Plaintext": b64encode(b"test").decode("ascii"),
        },
    )
    assert code != 200


def test_enable_key_after_disable(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT"},
    )
    assert code == 200
    key_id = content["KeyMetadata"]["KeyId"]

    code, _ = kms_client.post("DisableKey", {"KeyId": key_id})
    assert code == 200

    code, _ = kms_client.post("EnableKey", {"KeyId": key_id})
    assert code == 200

    code, content = kms_client.post("DescribeKey", {"KeyId": key_id})
    assert code == 200
    assert content["KeyMetadata"]["Enabled"] is True
    assert content["KeyMetadata"]["KeyState"] == "Enabled"

    code, content = kms_client.post(
        "Encrypt",
        {
            "KeyId": key_id,
            "Plaintext": b64encode(b"re-enabled").decode("ascii"),
        },
    )
    assert code == 200
    assert len(content.get("CiphertextBlob", "")) > 0


def test_disable_enable_asymmetric_key(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY"},
    )
    assert code == 200
    key_id = content["KeyMetadata"]["KeyId"]

    code, _ = kms_client.post("DisableKey", {"KeyId": key_id})
    assert code == 200

    code, content = kms_client.post("DescribeKey", {"KeyId": key_id})
    assert code == 200
    assert content["KeyMetadata"]["Enabled"] is False

    code, _ = kms_client.post("EnableKey", {"KeyId": key_id})
    assert code == 200

    code, content = kms_client.post("DescribeKey", {"KeyId": key_id})
    assert code == 200
    assert content["KeyMetadata"]["Enabled"] is True
