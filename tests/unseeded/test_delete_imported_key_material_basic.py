import os
from base64 import b64decode, b64encode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key


def test_delete_imported_key_material_returns_success(kms_client) -> None:
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
    public_key_der = b64decode(content["PublicKey"])

    plaintext_material = os.urandom(32)
    public_key = load_der_public_key(public_key_der)
    encrypted_material = public_key.encrypt(
        plaintext_material,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    code, content = kms_client.post(
        "ImportKeyMaterial",
        {
            "KeyId": key_id,
            "EncryptedKeyMaterial": b64encode(encrypted_material).decode("ascii"),
            "ImportToken": content["ImportToken"],
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
            "ImportType": "NEW_KEY_MATERIAL",
        },
    )
    assert code == 200
    assert isinstance(content, dict)

    code, content = kms_client.post(
        "DeleteImportedKeyMaterial",
        {
            "KeyId": key_id,
        },
    )
    assert code == 200
    assert isinstance(content, dict)
