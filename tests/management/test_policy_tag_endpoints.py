import uuid


def _create_key(kms_client) -> str:
    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT"},
    )
    assert code == 200
    return content["KeyMetadata"]["KeyId"]


def test_tag_resource_and_list_resource_tags(kms_client) -> None:
    key_id = _create_key(kms_client)

    code, content = kms_client.post(
        "TagResource",
        {
            "KeyId": key_id,
            "Tags": [
                {"TagKey": "env", "TagValue": "test"},
                {"TagKey": "project", "TagValue": "lkms"},
            ],
        },
    )
    assert code == 200

    code, content = kms_client.post("ListResourceTags", {"KeyId": key_id})
    assert code == 200
    assert isinstance(content, dict)
    assert "Tags" in content
    tags = content["Tags"]
    assert isinstance(tags, list)

    tag_map = {t["TagKey"]: t["TagValue"] for t in tags}
    assert tag_map["env"] == "test"
    assert tag_map["project"] == "lkms"


def test_untag_resource(kms_client) -> None:
    key_id = _create_key(kms_client)

    code, _ = kms_client.post(
        "TagResource",
        {
            "KeyId": key_id,
            "Tags": [
                {"TagKey": "keep", "TagValue": "yes"},
                {"TagKey": "remove", "TagValue": "yes"},
            ],
        },
    )
    assert code == 200

    code, _ = kms_client.post(
        "UntagResource",
        {"KeyId": key_id, "TagKeys": ["remove"]},
    )
    assert code == 200

    code, content = kms_client.post("ListResourceTags", {"KeyId": key_id})
    assert code == 200
    tag_keys = [t["TagKey"] for t in content["Tags"]]
    assert "keep" in tag_keys
    assert "remove" not in tag_keys


def test_tag_resource_overwrite(kms_client) -> None:
    key_id = _create_key(kms_client)

    code, _ = kms_client.post(
        "TagResource",
        {"KeyId": key_id, "Tags": [{"TagKey": "env", "TagValue": "dev"}]},
    )
    assert code == 200

    code, _ = kms_client.post(
        "TagResource",
        {"KeyId": key_id, "Tags": [{"TagKey": "env", "TagValue": "prod"}]},
    )
    assert code == 200

    code, content = kms_client.post("ListResourceTags", {"KeyId": key_id})
    assert code == 200
    tag_map = {t["TagKey"]: t["TagValue"] for t in content["Tags"]}
    assert tag_map["env"] == "prod"


def test_create_key_with_tags(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {
            "KeySpec": "SYMMETRIC_DEFAULT",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "Tags": [{"TagKey": "created-with", "TagValue": "tags"}],
        },
    )
    assert code == 200
    key_id = content["KeyMetadata"]["KeyId"]

    code, content = kms_client.post("ListResourceTags", {"KeyId": key_id})
    assert code == 200
    tag_map = {t["TagKey"]: t["TagValue"] for t in content["Tags"]}
    assert tag_map["created-with"] == "tags"


def test_get_key_policy(kms_client) -> None:
    key_id = _create_key(kms_client)

    code, content = kms_client.post(
        "GetKeyPolicy",
        {"KeyId": key_id, "PolicyName": "default"},
    )
    assert code == 200
    assert isinstance(content, dict)
    assert "Policy" in content
    assert isinstance(content["Policy"], str)
    assert len(content["Policy"]) > 0


def test_put_key_policy(kms_client) -> None:
    key_id = _create_key(kms_client)

    new_policy = '{"Version":"2012-10-17","Statement":[{"Sid":"test","Effect":"Allow","Principal":"*","Action":"kms:*","Resource":"*"}]}'

    code, _ = kms_client.post(
        "PutKeyPolicy",
        {
            "KeyId": key_id,
            "PolicyName": "default",
            "Policy": new_policy,
        },
    )
    assert code == 200

    code, content = kms_client.post(
        "GetKeyPolicy",
        {"KeyId": key_id, "PolicyName": "default"},
    )
    assert code == 200
    assert content["Policy"] == new_policy


def test_list_key_policies(kms_client) -> None:
    key_id = _create_key(kms_client)

    code, content = kms_client.post("ListKeyPolicies", {"KeyId": key_id})
    assert code == 200
    assert isinstance(content, dict)
    assert "PolicyNames" in content
    assert isinstance(content["PolicyNames"], list)
    assert "default" in content["PolicyNames"]
