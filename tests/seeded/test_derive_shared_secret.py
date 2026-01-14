import hashlib

import pytest
from base64 import b64encode, b64decode
import mldsa_mu
import random
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DERIVE_SHARED_SECRET_CASES = [
    pytest.param("ECC_NIST_P256", "alias/seed_ecc_nist_p256_key_agreement", id="p256"),
    pytest.param("ECC_NIST_P384", "alias/seed_ecc_nist_p384_key_agreement", id="p384"),
    pytest.param("ECC_NIST_P521", "alias/seed_ecc_nist_p521_key_agreement", id="p521"),
]

def _curve_from_kms_spec(key_spec: str):
    # KMS KeySpec values for ECDH are NIST curves (e.g., ECC_NIST_P256/P384/P521).
    # Map them to cryptography curves.
    if key_spec == "ECC_NIST_P256":
        return ec.SECP256R1()  # a.k.a. P-256
    if key_spec == "ECC_NIST_P384":
        return ec.SECP384R1()  # P-384
    if key_spec == "ECC_NIST_P521":
        return ec.SECP521R1()  # P-521
    raise ValueError(f"Unsupported/unknown KMS KeySpec for ECDH: {key_spec}")

@pytest.mark.parametrize("key_spec,key_id", DERIVE_SHARED_SECRET_CASES)
def test_derive_shared_secret(
    kms_client,
    key_spec: str,
    key_id: str,
) -> None:

    # ---------------------------------------------------
    # Test GetPublicKey

    code, content = kms_client.post('GetPublicKey',{
        'KeyId': key_id,
    })

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get('PublicKey', '')) > 0

    kms_pub_spki_der: bytes = b64decode(content.get('PublicKey'))

    # ---------------------------------------------------
    # Create and Derive Locally

    curve = _curve_from_kms_spec(key_spec)

    local_priv = ec.generate_private_key(curve)
    local_pub = local_priv.public_key()

    local_pub_spki_der = local_pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    kms_pub = serialization.load_der_public_key(kms_pub_spki_der)

    local_shared = local_priv.exchange(ec.ECDH(), kms_pub)
    local_shared_b64 = b64encode(local_shared)

    # ---------------------------------------------------
    # Derive in KMS

    code, content = kms_client.post('DeriveSharedSecret',{
        'KeyId': key_id,
        'KeyAgreementAlgorithm': "ECDH",
        'PublicKey': b64encode(local_pub_spki_der).decode('ascii'),
    })

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get('SharedSecret', '')) > 0
    assert content.get('KeyAgreementAlgorithm') == "ECDH"

    assert content.get('SharedSecret') == local_shared_b64.decode('ascii')
