import uuid


def test_list_aliases_returns_seeded(kms_client) -> None:
    code, content = kms_client.post("ListAliases", {})
    assert code == 200
    assert isinstance(content, dict)
    assert "Aliases" in content
    assert isinstance(content["Aliases"], list)
    assert len(content["Aliases"]) > 0

    for alias in content["Aliases"]:
        assert "AliasName" in alias
        assert "AliasArn" in alias


def test_list_aliases_for_specific_key(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT"},
    )
    assert code == 200
    key_id = content["KeyMetadata"]["KeyId"]

    alias_name = f"alias/test-list-{uuid.uuid4().hex[:8]}"
    code, _ = kms_client.post(
        "CreateAlias",
        {"AliasName": alias_name, "TargetKeyId": key_id},
    )
    assert code == 200

    code, content = kms_client.post("ListAliases", {"KeyId": key_id})
    assert code == 200
    assert isinstance(content, dict)
    aliases = content["Aliases"]
    assert isinstance(aliases, list)
    assert len(aliases) >= 1

    alias_names = [a["AliasName"] for a in aliases]
    assert alias_name in alias_names

    for alias in aliases:
        assert alias.get("TargetKeyId") is not None


def test_list_aliases_pagination(kms_client) -> None:
    code, content = kms_client.post("ListAliases", {"Limit": 2})
    assert code == 200
    assert isinstance(content, dict)
    assert "Aliases" in content
    assert len(content["Aliases"]) <= 2

    if content.get("Truncated") is True:
        marker = content.get("NextMarker")
        assert marker is not None

        code, content_page_2 = kms_client.post(
            "ListAliases",
            {"Limit": 2, "Marker": marker},
        )
        assert code == 200
        assert isinstance(content_page_2, dict)
        assert "Aliases" in content_page_2


def test_list_aliases_for_key_with_no_aliases(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {"KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT"},
    )
    assert code == 200
    key_id = content["KeyMetadata"]["KeyId"]

    code, content = kms_client.post("ListAliases", {"KeyId": key_id})
    assert code == 200
    assert isinstance(content, dict)
    assert content["Aliases"] == [] or len(content["Aliases"]) == 0
