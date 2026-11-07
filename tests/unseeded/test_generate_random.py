
def test_encrypt_decrypt(
    kms_client,
) -> None:

    plaintext = b"Test Message"

    code, content = kms_client.post('GenerateRandom',{
        'NumberOfBytes': 1024,
    })

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get('Plaintext', '')) > 0
