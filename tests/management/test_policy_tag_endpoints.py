def _assert_endpoint_not_enabled(code: int, content: object) -> None:
    assert code != 200
    assert isinstance(content, dict)
    assert "__type" in content


def test_key_policy_endpoints_are_not_enabled(kms_client) -> None:
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

    code, content = kms_client.post(
        "PutKeyPolicy",
        {
            "KeyId": key_id,
            "PolicyName": "default",
            "Policy": "{}",
        },
    )
    _assert_endpoint_not_enabled(code, content)

    code, content = kms_client.post(
        "GetKeyPolicy",
        {
            "KeyId": key_id,
            "PolicyName": "default",
        },
    )
    _assert_endpoint_not_enabled(code, content)

    code, content = kms_client.post(
        "ListKeyPolicies",
        {
            "KeyId": key_id,
        },
    )
    _assert_endpoint_not_enabled(code, content)


def test_tag_endpoints_are_not_enabled(kms_client) -> None:
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

    code, content = kms_client.post(
        "TagResource",
        {
            "KeyId": key_id,
            "Tags": [{"TagKey": "env", "TagValue": "test"}],
        },
    )
    _assert_endpoint_not_enabled(code, content)

    code, content = kms_client.post(
        "ListResourceTags",
        {
            "KeyId": key_id,
        },
    )
    _assert_endpoint_not_enabled(code, content)

    code, content = kms_client.post(
        "UntagResource",
        {
            "KeyId": key_id,
            "TagKeys": ["env"],
        },
    )
    _assert_endpoint_not_enabled(code, content)
