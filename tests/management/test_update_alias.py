import uuid
from base64 import b64encode, b64decode


def test_update_alias_retargets_key(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT"},
    )
    assert code == 200
    key_id_1 = content["KeyMetadata"]["KeyId"]

    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT"},
    )
    assert code == 200
    key_id_2 = content["KeyMetadata"]["KeyId"]

    alias_name = f"alias/test-update-{uuid.uuid4().hex[:8]}"

    code, _ = kms_client.post(
        "CreateAlias",
        {"AliasName": alias_name, "TargetKeyId": key_id_1},
    )
    assert code == 200

    code, content = kms_client.post("DescribeKey", {"KeyId": alias_name})
    assert code == 200
    assert content["KeyMetadata"]["KeyId"] == key_id_1

    code, _ = kms_client.post(
        "UpdateAlias",
        {"AliasName": alias_name, "TargetKeyId": key_id_2},
    )
    assert code == 200

    code, content = kms_client.post("DescribeKey", {"KeyId": alias_name})
    assert code == 200
    assert content["KeyMetadata"]["KeyId"] == key_id_2


def test_update_alias_encrypt_uses_new_key(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT"},
    )
    assert code == 200
    key_id_1 = content["KeyMetadata"]["KeyId"]
    key_arn_1 = content["KeyMetadata"]["Arn"]

    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT"},
    )
    assert code == 200
    key_id_2 = content["KeyMetadata"]["KeyId"]
    key_arn_2 = content["KeyMetadata"]["Arn"]

    alias_name = f"alias/test-update-enc-{uuid.uuid4().hex[:8]}"

    code, _ = kms_client.post(
        "CreateAlias",
        {"AliasName": alias_name, "TargetKeyId": key_id_1},
    )
    assert code == 200

    plaintext = b"before update"
    code, content = kms_client.post(
        "Encrypt",
        {"KeyId": alias_name, "Plaintext": b64encode(plaintext).decode("ascii")},
    )
    assert code == 200
    cipher_before = content["CiphertextBlob"]
    assert content.get("KeyId") == key_arn_1

    code, _ = kms_client.post(
        "UpdateAlias",
        {"AliasName": alias_name, "TargetKeyId": key_id_2},
    )
    assert code == 200

    plaintext2 = b"after update"
    code, content = kms_client.post(
        "Encrypt",
        {"KeyId": alias_name, "Plaintext": b64encode(plaintext2).decode("ascii")},
    )
    assert code == 200
    assert content.get("KeyId") == key_arn_2

    code, content = kms_client.post(
        "Decrypt",
        {"CiphertextBlob": cipher_before},
    )
    assert code == 200
    assert b64decode(content["Plaintext"]) == plaintext
