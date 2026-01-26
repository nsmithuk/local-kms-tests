import time


def test_rotate_key_on_demand_basic(kms_client) -> None:
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
        "RotateKeyOnDemand",
        {
            "KeyId": key_id,
        },
    )
    assert code == 200
    assert isinstance(content, dict)

    if kms_client.is_real_kms():
        time.sleep(5)

    code, content = kms_client.post(
        "ListKeyRotations",
        {
            "KeyId": key_id,
        },
    )
    assert code == 200
    assert isinstance(content, dict)
    assert isinstance(content.get("Rotations"), list)
