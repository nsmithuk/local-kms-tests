from base64 import b64decode


def test_generate_random_length_matches_request(kms_client) -> None:
    byte_count = 32
    code, content = kms_client.post(
        "GenerateRandom",
        {
            "NumberOfBytes": byte_count,
        },
    )

    assert code == 200
    assert isinstance(content, dict)
    plaintext_b64 = content.get("Plaintext", "")
    assert plaintext_b64
    assert len(b64decode(plaintext_b64)) == byte_count
