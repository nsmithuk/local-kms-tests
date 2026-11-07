import pytest
from base64 import b64decode
from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
    load_der_private_key,
)
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

DATA_KEY_CASES = [
    pytest.param("RSA_2048", id="rsa_2048"),
    pytest.param("RSA_3072", id="rsa_3072"),
    pytest.param("RSA_4096", id="rsa_4096"),
    pytest.param("ECC_NIST_P256", id="ecc_nist_p256"),
    pytest.param("ECC_NIST_P384", id="ecc_nist_p384"),
    pytest.param("ECC_NIST_P521", id="ecc_nist_p521"),
    pytest.param("ECC_SECG_P256K1", id="ecc_secg_p256k1"),
    pytest.param("ECC_NIST_EDWARDS25519", id="ecc_nist_edwards25519"),
]


def _assert_keypair_matches_spec(public_key_der: bytes, private_key_der: bytes, spec: str) -> None:

    pub = load_der_public_key(public_key_der)
    priv = load_der_private_key(private_key_der, password=None)

    if spec.startswith("RSA_"):
        expected_bits = int(spec.split("_", 1)[1])
        assert isinstance(pub, rsa.RSAPublicKey), f"PublicKey type mismatch: {type(pub)!r}"
        assert isinstance(priv, rsa.RSAPrivateKey), f"PrivateKey type mismatch: {type(priv)!r}"
        assert pub.key_size == expected_bits, f"PublicKey size {pub.key_size} != {expected_bits}"
        assert priv.key_size == expected_bits, f"PrivateKey size {priv.key_size} != {expected_bits}"
        return

    if spec == "ECC_NIST_EDWARDS25519":
        assert isinstance(pub, ed25519.Ed25519PublicKey), f"PublicKey type mismatch: {type(pub)!r}"
        assert isinstance(priv, ed25519.Ed25519PrivateKey), f"PrivateKey type mismatch: {type(priv)!r}"
        return

    # ECDSA/ECDH-style keys
    assert isinstance(pub, ec.EllipticCurvePublicKey), f"PublicKey type mismatch: {type(pub)!r}"
    assert isinstance(priv, ec.EllipticCurvePrivateKey), f"PrivateKey type mismatch: {type(priv)!r}"

    expected_curve_name = {
        "ECC_NIST_P256": "secp256r1",
        "ECC_NIST_P384": "secp384r1",
        "ECC_NIST_P521": "secp521r1",
        "ECC_SECG_P256K1": "secp256k1",
    }[spec]

    assert pub.curve.name == expected_curve_name, f"PublicKey curve {pub.curve.name} != {expected_curve_name}"
    assert priv.curve.name == expected_curve_name, f"PrivateKey curve {priv.curve.name} != {expected_curve_name}"


@pytest.mark.parametrize("data_key_pair_spec", DATA_KEY_CASES)
def test_generate_data_key_spec(
    kms_client,
    data_key_pair_spec: str,
) -> None:
    key_id = "alias/seed_symmetric_default_encrypt_decrypt"

    code, content = kms_client.post(
        "GenerateDataKeyPair",
        {
            "KeyId": key_id,
            "KeyPairSpec": data_key_pair_spec,
        },
    )

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get("PublicKey", "")) > 0
    assert len(content.get("PrivateKeyPlaintext", "")) > 0
    assert len(content.get("PrivateKeyCiphertextBlob", "")) > 0

    # --- NEW: decode + validate key formats/types/sizes/curves ---
    public_key_der = b64decode(content["PublicKey"])
    private_key_der = b64decode(content["PrivateKeyPlaintext"])
    _assert_keypair_matches_spec(public_key_der, private_key_der, data_key_pair_spec)

    plaintext = content.get("PrivateKeyPlaintext")

    #---

    code, content = kms_client.post(
        "Decrypt",
        {
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
            "CiphertextBlob": content.get("PrivateKeyCiphertextBlob"),
        },
    )

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get("Plaintext", "")) > 0

    assert content.get("Plaintext") == plaintext

    new_private_key_der = b64decode(content.get("Plaintext"))
    _assert_keypair_matches_spec(public_key_der, new_private_key_der, data_key_pair_spec)

    #--------------------------------------------
    # GenerateDataKeyWithoutPlaintext

    code, content = kms_client.post(
        "GenerateDataKeyPairWithoutPlaintext",
        {
            "KeyId": key_id,
            "KeyPairSpec": data_key_pair_spec,
        },
    )

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get("PublicKey", "")) > 0
    assert len(content.get("PrivateKeyPlaintext", "")) == 0
    assert len(content.get("PrivateKeyCiphertextBlob", "")) > 0

    public_key_der = b64decode(content["PublicKey"])

    #---

    code, content = kms_client.post(
        "Decrypt",
        {
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
            "CiphertextBlob": content.get("PrivateKeyCiphertextBlob"),
        },
    )

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get("Plaintext", "")) > 0

    private_key_der = b64decode(content["Plaintext"])
    _assert_keypair_matches_spec(public_key_der, private_key_der, data_key_pair_spec)
    