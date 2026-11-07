def test_update_key_description(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {
            "KeySpec": "SYMMETRIC_DEFAULT",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "Description": "original description",
        },
    )
    assert code == 200
    key_id = content["KeyMetadata"]["KeyId"]
    assert content["KeyMetadata"]["Description"] == "original description"

    code, _ = kms_client.post(
        "UpdateKeyDescription",
        {"KeyId": key_id, "Description": "updated description"},
    )
    assert code == 200

    code, content = kms_client.post("DescribeKey", {"KeyId": key_id})
    assert code == 200
    assert content["KeyMetadata"]["Description"] == "updated description"


def test_update_key_description_to_empty(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {
            "KeySpec": "SYMMETRIC_DEFAULT",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "Description": "will be cleared",
        },
    )
    assert code == 200
    key_id = content["KeyMetadata"]["KeyId"]

    code, _ = kms_client.post(
        "UpdateKeyDescription",
        {"KeyId": key_id, "Description": ""},
    )
    assert code == 200

    code, content = kms_client.post("DescribeKey", {"KeyId": key_id})
    assert code == 200
    assert content["KeyMetadata"]["Description"] == ""


def test_update_description_on_asymmetric_key(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY"},
    )
    assert code == 200
    key_id = content["KeyMetadata"]["KeyId"]

    code, _ = kms_client.post(
        "UpdateKeyDescription",
        {"KeyId": key_id, "Description": "asymmetric key description"},
    )
    assert code == 200

    code, content = kms_client.post("DescribeKey", {"KeyId": key_id})
    assert code == 200
    assert content["KeyMetadata"]["Description"] == "asymmetric key description"
