def test_describe_key_returns_metadata(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {
            "KeySpec": "SYMMETRIC_DEFAULT",
            "KeyUsage": "ENCRYPT_DECRYPT",
        },
    )

    assert code == 200
    assert isinstance(content, dict)
    key_metadata = content["KeyMetadata"]

    code, content = kms_client.post(
        "DescribeKey",
        {
            "KeyId": key_metadata["KeyId"],
        },
    )

    assert code == 200
    assert isinstance(content, dict)
    assert "KeyMetadata" in content

    described = content["KeyMetadata"]
    assert described["KeyId"] == key_metadata["KeyId"]
    assert described["Arn"] == key_metadata["Arn"]
    assert described["KeySpec"] == "SYMMETRIC_DEFAULT"
    assert described["KeyUsage"] == "ENCRYPT_DECRYPT"
    assert described["Enabled"] is True
