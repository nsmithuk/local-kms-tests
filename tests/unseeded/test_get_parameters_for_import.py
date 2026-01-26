from base64 import b64decode

from cryptography.hazmat.primitives.serialization import load_der_public_key


def test_get_parameters_for_import_returns_wrapping_material(kms_client) -> None:
    code, content = kms_client.post(
        "CreateKey",
        {
            "KeySpec": "SYMMETRIC_DEFAULT",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "Origin": "EXTERNAL",
        },
    )
    assert code == 200
    assert isinstance(content, dict)
    key_id = content["KeyMetadata"]["KeyId"]

    code, content = kms_client.post(
        "GetParametersForImport",
        {
            "KeyId": key_id,
            "WrappingKeySpec": "RSA_2048",
            "WrappingAlgorithm": "RSAES_OAEP_SHA_256",
        },
    )

    assert code == 200
    assert isinstance(content, dict)
    assert isinstance(content.get("ImportToken"), str)
    assert isinstance(content.get("PublicKey"), str)

    public_key_der = b64decode(content["PublicKey"])
    wrapping_key = load_der_public_key(public_key_der)
    assert wrapping_key is not None
