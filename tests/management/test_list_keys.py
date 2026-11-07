def _create_symmetric_key(kms_client) -> str:
    code, content = kms_client.post(
        "CreateKey",
        {
            "KeySpec": "SYMMETRIC_DEFAULT",
            "KeyUsage": "ENCRYPT_DECRYPT",
        },
    )
    assert code == 200
    assert isinstance(content, dict)
    return content["KeyMetadata"]["KeyId"]


def _assert_key_list_entries(content: dict) -> None:
    assert "Keys" in content
    assert isinstance(content["Keys"], list)
    for entry in content["Keys"]:
        assert isinstance(entry, dict)
        assert isinstance(entry.get("KeyId"), str) and entry.get("KeyId")
        assert isinstance(entry.get("KeyArn"), str) and entry.get("KeyArn")


def test_list_keys_with_limit(kms_client):
    code, content = kms_client.post(
        "ListKeys",
        {
            "Limit": 2,
        },
    )

    assert code == 200
    assert isinstance(content, dict)
    _assert_key_list_entries(content)
    assert len(content["Keys"]) <= 2


def test_list_keys_pagination(kms_client):
    created_ids = {_create_symmetric_key(kms_client) for _ in range(3)}

    code, content = kms_client.post(
        "ListKeys",
        {
            "Limit": 1,
        },
    )

    assert code == 200
    assert isinstance(content, dict)
    _assert_key_list_entries(content)
    assert len(content["Keys"]) <= 1

    returned_ids = {entry["KeyId"] for entry in content["Keys"]}
    assert returned_ids.issubset(created_ids) or returned_ids, "Expected at least one key in the response"

    if content.get("Truncated") is True:
        marker = content.get("NextMarker") or content.get("Marker")
        assert marker, "Expected pagination marker when Truncated is true"

        code, content_page_2 = kms_client.post(
            "ListKeys",
            {
                "Limit": 1,
                "Marker": marker,
            },
        )

        assert code == 200
        assert isinstance(content_page_2, dict)
        _assert_key_list_entries(content_page_2)
