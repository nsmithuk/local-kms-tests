def test_alias_create_delete_recreate(kms_client) -> None:
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

    import uuid
    alias_name = f"alias/test-alias-lifecycle-{uuid.uuid4().hex[:8]}"

    code, _ = kms_client.post(
        "CreateAlias",
        {
            "AliasName": alias_name,
            "TargetKeyId": key_id,
        },
    )
    assert code == 200

    code, content = kms_client.post(
        "DescribeKey",
        {
            "KeyId": alias_name,
        },
    )
    assert code == 200
    assert isinstance(content, dict)
    assert content["KeyMetadata"]["KeyId"] == key_id

    code, _ = kms_client.post(
        "DeleteAlias",
        {
            "AliasName": alias_name,
        },
    )
    assert code == 200

    code, _ = kms_client.post(
        "CreateAlias",
        {
            "AliasName": alias_name,
            "TargetKeyId": key_id,
        },
    )
    assert code == 200
