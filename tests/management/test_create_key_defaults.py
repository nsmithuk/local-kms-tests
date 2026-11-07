def test_create_key_defaults_to_symmetric(kms_client) -> None:
    code, content = kms_client.post("CreateKey", {})

    assert code == 200
    assert isinstance(content, dict)
    assert "KeyMetadata" in content

    md = content["KeyMetadata"]
    assert md.get("KeySpec") == "SYMMETRIC_DEFAULT"
    assert md.get("KeyUsage") == "ENCRYPT_DECRYPT"
    assert md.get("Enabled") is True
