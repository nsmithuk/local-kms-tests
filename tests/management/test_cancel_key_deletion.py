from base64 import b64encode, b64decode


def test_cancel_key_deletion_restores_key(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT"},
    )
    assert code == 200
    key_id = content["KeyMetadata"]["KeyId"]

    code, content = kms_client.post(
        "ScheduleKeyDeletion",
        {"KeyId": key_id, "PendingWindowInDays": 7},
    )
    assert code == 200
    assert content.get("KeyState") == "PendingDeletion"

    code, content = kms_client.post("CancelKeyDeletion", {"KeyId": key_id})
    assert code == 200
    assert isinstance(content, dict)
    assert content.get("KeyId") is not None

    code, content = kms_client.post("DescribeKey", {"KeyId": key_id})
    assert code == 200
    md = content["KeyMetadata"]
    assert md["KeyState"] == "Disabled"

    code, _ = kms_client.post("EnableKey", {"KeyId": key_id})
    assert code == 200

    plaintext = b"cancel deletion test"
    code, content = kms_client.post(
        "Encrypt",
        {
            "KeyId": key_id,
            "Plaintext": b64encode(plaintext).decode("ascii"),
        },
    )
    assert code == 200
    assert len(content.get("CiphertextBlob", "")) > 0

    code, content = kms_client.post(
        "Decrypt",
        {"CiphertextBlob": content["CiphertextBlob"]},
    )
    assert code == 200
    assert b64decode(content["Plaintext"]) == plaintext


def test_cancel_key_deletion_on_enabled_key_fails(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT"},
    )
    assert code == 200
    key_id = content["KeyMetadata"]["KeyId"]

    code, content = kms_client.post("CancelKeyDeletion", {"KeyId": key_id})
    assert code != 200
    assert isinstance(content, dict)
    assert "__type" in content
