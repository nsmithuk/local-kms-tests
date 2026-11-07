def test_schedule_key_deletion_updates_key_state(kms_client) -> None:
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
        "ScheduleKeyDeletion",
        {
            "KeyId": key_id,
            "PendingWindowInDays": 7,
        },
    )
    assert code == 200
    assert isinstance(content, dict)
    assert content.get("KeyState") == "PendingDeletion"

    code, content = kms_client.post(
        "DescribeKey",
        {
            "KeyId": key_id,
        },
    )
    assert code == 200
    assert isinstance(content, dict)
    assert content["KeyMetadata"]["KeyState"] == "PendingDeletion"
