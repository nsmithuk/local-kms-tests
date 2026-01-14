from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

import os
from base64 import b64decode, b64encode

def test_import_key(
    kms_client,
) -> None:

    code, content = kms_client.post(
        "CreateKey",
        {
            "KeySpec": "SYMMETRIC_DEFAULT",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "Origin": "EXTERNAL"
        },
    )
    assert code == 200
    assert isinstance(content, dict)
    assert content.get("KeyMetadata") is not None

    metadata = content.get("KeyMetadata")

    code, content = kms_client.post(
        "GetParametersForImport",
        {
            "KeyId": metadata.get("KeyId"),
            "WrappingKeySpec": "RSA_2048",
            "WrappingAlgorithm": "RSAES_OAEP_SHA_256",
        },
    )
    assert code == 200
    assert isinstance(content, dict)
    print(metadata.get("KeyId"))

    import_token_b64 = content.get("ImportToken")
    pubkey_der_b64 = content.get("PublicKey")

    assert isinstance(import_token_b64, str) and import_token_b64
    assert isinstance(pubkey_der_b64, str) and pubkey_der_b64

    import_token = b64decode(import_token_b64)
    pubkey_der = b64decode(pubkey_der_b64)

    # 3) Generate the key material we want to import.
    # For SYMMETRIC_DEFAULT, AWS expects 256-bit (32 bytes) key material.
    plaintext_key_material = os.urandom(32)

    # 4) Load the RSA public key returned by GetParametersForImport.
    # AWS returns this as a DER-encoded SubjectPublicKeyInfo.
    wrapping_pubkey = serialization.load_der_public_key(pubkey_der)
    assert wrapping_pubkey is not None

    # 5) Wrap the key material using RSAES-OAEP with SHA-256
    wrapped_key_material = wrapping_pubkey.encrypt(
        plaintext_key_material,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    code, content = kms_client.post(
        "ImportKeyMaterial",
        {
            "KeyId": metadata.get("KeyId"),
            "ImportToken": import_token_b64,
            "EncryptedKeyMaterial": b64encode(wrapped_key_material).decode("ascii"),
            "ImportType": "NEW_KEY_MATERIAL",
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
            # If you want it to expire instead:
            # "ExpirationModel": "KEY_MATERIAL_EXPIRES",
            # "ValidTo": "2030-01-01T00:00:00Z",
        },
    )
    assert code == 200
    assert isinstance(content, dict)


ECC_TEST_CASES = [
    # pytest.param("ECC_NIST_P256", "RSAES_OAEP_SHA_1", "RSA_4096", id="ecc_nist_p256_rsaes_oaep_sha_1"),
    # pytest.param("ECC_NIST_P256", "RSAES_OAEP_SHA_256", "RSA_3072", id="ecc_nist_p256_rsaes_oaep_sha_256"),
    pytest.param("ECC_NIST_P256", "RSA_AES_KEY_WRAP_SHA_1", "RSA_3072", id="ecc_nist_p256_rsa_aes_key_wrap_sha_1"),
    pytest.param("ECC_NIST_P256", "RSA_AES_KEY_WRAP_SHA_256", "RSA_2048", id="ecc_nist_p256_rsa_aes_key_wrap_sha_256"),

    # pytest.param("ECC_NIST_P384", "RSAES_OAEP_SHA_1", "RSA_4096", id="ecc_nist_p384_rsaes_oaep_sha_1"),
    # pytest.param("ECC_NIST_P384", "RSAES_OAEP_SHA_256", "RSA_3072", id="ecc_nist_p384_rsaes_oaep_sha_256"),
    pytest.param("ECC_NIST_P384", "RSA_AES_KEY_WRAP_SHA_1", "RSA_3072", id="ecc_nist_p384_rsa_aes_key_wrap_sha_1"),
    pytest.param("ECC_NIST_P384", "RSA_AES_KEY_WRAP_SHA_256", "RSA_2048", id="ecc_nist_p384_rsa_aes_key_wrap_sha_256"),

    # pytest.param("ECC_NIST_P521", "RSAES_OAEP_SHA_1", "RSA_4096", id="ecc_nist_p521_rsaes_oaep_sha_1"),
    # pytest.param("ECC_NIST_P521", "RSAES_OAEP_SHA_256", "RSA_3072", id="ecc_nist_p521_rsaes_oaep_sha_256"),
    pytest.param("ECC_NIST_P521", "RSA_AES_KEY_WRAP_SHA_1", "RSA_3072", id="ecc_nist_p521_rsa_aes_key_wrap_sha_1"),
    pytest.param("ECC_NIST_P521", "RSA_AES_KEY_WRAP_SHA_256", "RSA_2048", id="ecc_nist_p521_rsa_aes_key_wrap_sha_256"),

    # pytest.param("ECC_SECG_P256K1", "RSAES_OAEP_SHA_1", "RSA_4096", id="ecc_nist_p256k_rsaes_oaep_sha_1"),
    # pytest.param("ECC_SECG_P256K1", "RSAES_OAEP_SHA_256", "RSA_3072", id="ecc_nist_p256k_rsaes_oaep_sha_256"),
    pytest.param("ECC_SECG_P256K1", "RSA_AES_KEY_WRAP_SHA_1", "RSA_3072", id="ecc_nist_p256k_rsa_aes_key_wrap_sha_1"),
    pytest.param("ECC_SECG_P256K1", "RSA_AES_KEY_WRAP_SHA_256", "RSA_2048", id="ecc_nist_p256k_rsa_aes_key_wrap_sha_256"),
]

@pytest.mark.parametrize("key_spec,wrapping_algorithm,wrapping_key_spec", ECC_TEST_CASES)
def test_ecc_key_import(
    kms_client,
    key_spec: str,
    wrapping_algorithm: str,
    wrapping_key_spec: str,
) -> None:

    # 1) Create an external-origin ECC P-256 key
    code, content = kms_client.post(
        "CreateKey",
        {
            "KeySpec": key_spec,
            "KeyUsage": "SIGN_VERIFY",
            "Origin": "EXTERNAL",
        },
    )
    assert code == 200
    metadata = content["KeyMetadata"]
    key_id = metadata["KeyId"]

    # 2) Get import parameters for RSA_AES_KEY_WRAP_SHA_256
    code, content = kms_client.post(
        "GetParametersForImport",
        {
            "KeyId": key_id,
            "WrappingKeySpec": wrapping_key_spec,
            "WrappingAlgorithm": wrapping_algorithm,
        },
    )
    assert code == 200

    import_token_b64 = content["ImportToken"]
    pubkey_der_b64 = content["PublicKey"]
    pubkey_der = b64decode(pubkey_der_b64)

    # 3) Generate an external private key
    if key_spec == "ECC_NIST_P256":
        curve = ec.SECP256R1()
    elif key_spec == "ECC_NIST_P384":
        curve = ec.SECP384R1()
    elif key_spec == "ECC_NIST_P521":
        curve = ec.SECP521R1()
    elif key_spec == "ECC_SECG_P256K1":
        curve = ec.SECP256K1()
    else:
        raise ValueError(f"Unknown key spec: {key_spec}")

    ecc_private_key = ec.generate_private_key(curve)

    # KMS expects PKCS#8 DER for ECC imported key material
    plaintext_key_material = ecc_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # 4) Load KMS wrapping RSA public key (SPKI DER)
    wrapping_pubkey = serialization.load_der_public_key(pubkey_der)
    assert wrapping_pubkey is not None

    # 5) Generate a 256-bit AES Key-Encryption Key (KEK)
    aes_kek = os.urandom(32)

    # 6) AES Key Wrap with padding (RFC 5649)
    wrapped_key_material = aes_key_wrap_with_padding(aes_kek, plaintext_key_material)

    # 7) RSAES-OAEP-SHA256 encrypt the AES KEK
    if wrapping_algorithm == "RSA_AES_KEY_WRAP_SHA_1":
        padding_algorithm = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
    elif wrapping_algorithm == "RSA_AES_KEY_WRAP_SHA_256":
        padding_algorithm = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    else:
        raise ValueError(f"Unknown wrapping algorithm: {wrapping_algorithm}")

    encrypted_kek = wrapping_pubkey.encrypt(aes_kek, padding_algorithm)

    # 8) Concatenate RSA(encrypted KEK) || AES-wrapped key material
    encrypted_key_material = encrypted_kek + wrapped_key_material

    # 9) Import into KMS
    code, content = kms_client.post(
        "ImportKeyMaterial",
        {
            "KeyId": key_id,
            "ImportToken": import_token_b64,
            "ImportType": "NEW_KEY_MATERIAL",
            "EncryptedKeyMaterial": b64encode(encrypted_key_material).decode("ascii"),
            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
        },
    )

    assert code == 200
    assert isinstance(content, dict)

    # ---------------------------------------------------------------------
    # 10) Ask KMS to sign a message with the imported key
    message = b"test message"

    if key_spec == "ECC_NIST_P256":
        signing_algorithm = "ECDSA_SHA_256"
        h = hashes.SHA256()
    elif key_spec == "ECC_NIST_P384":
        signing_algorithm = "ECDSA_SHA_384"
        h = hashes.SHA384()
    elif key_spec == "ECC_NIST_P521":
        signing_algorithm = "ECDSA_SHA_512"
        h = hashes.SHA512()
    elif key_spec == "ECC_SECG_P256K1":
        signing_algorithm = "ECDSA_SHA_256"
        h = hashes.SHA256()
    else:
        raise ValueError(f"Unknown key spec: {key_spec}")

    code, content = kms_client.post(
        "Sign",
        {
            "KeyId": key_id,
            "Message": b64encode(message).decode("ascii"),
            "MessageType": "RAW",
            "SigningAlgorithm": signing_algorithm,
        },
    )
    assert code == 200
    assert isinstance(content, dict)

    signature_b64 = content["Signature"]
    signature = b64decode(signature_b64)

    # ---------------------------------------------------------------------
    # 11) Verify locally using the public key we already have (from ecc_private_key)
    pub = ecc_private_key.public_key()

    # Throws an exception if not valid
    pub.verify(signature, message, ec.ECDSA(h))

    # ---------------------------------------------------------------------
    # 12) Schedule the key for deletion (AWS requires 7 days)
    code, content = kms_client.post(
        "ScheduleKeyDeletion",
        {
            "KeyId": key_id,
            "PendingWindowInDays": 7,
        },
    )
    assert code == 200
