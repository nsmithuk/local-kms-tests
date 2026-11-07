def test_list_key_rotations_returns_list(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {
            "KeySpec": "SYMMETRIC_DEFAULT",
            "KeyUsage": "ENCRYPT_DECRYPT",
        },
    )
    assert code == 200
    assert isinstance(content, dict)
    key_id = content["KeyMetadata"]["KeyId"]

    code, content = kms_client.post("ListKeyRotations", {"KeyId": key_id})
    assert code == 200
    assert isinstance(content, dict)
    assert "Rotations" in content
    assert isinstance(content["Rotations"], list)
