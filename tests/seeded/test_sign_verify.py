import hashlib

import pytest
from base64 import b64encode, b64decode
import mldsa_mu
import random

# (key_spec, signing_algorithm, message_type, key_id_alias)
SIGN_VERIFY_CASES = [
    # -----------------
    # RSA_* (SIGN_VERIFY)
    # RAW or DIGEST are both valid for these RSA signing algorithms.
    # -----------------
    pytest.param("RSA_2048", "RSASSA_PSS_SHA_256", "RAW",    "alias/seed_rsa_2048_sign_verify", id="rsa2048-pss256-raw"),
    pytest.param("RSA_2048", "RSASSA_PSS_SHA_256", "DIGEST", "alias/seed_rsa_2048_sign_verify", id="rsa2048-pss256-digest"),
    pytest.param("RSA_2048", "RSASSA_PSS_SHA_384", "RAW",    "alias/seed_rsa_2048_sign_verify", id="rsa2048-pss384-raw"),
    pytest.param("RSA_2048", "RSASSA_PSS_SHA_384", "DIGEST", "alias/seed_rsa_2048_sign_verify", id="rsa2048-pss384-digest"),
    pytest.param("RSA_2048", "RSASSA_PSS_SHA_512", "RAW",    "alias/seed_rsa_2048_sign_verify", id="rsa2048-pss512-raw"),
    pytest.param("RSA_2048", "RSASSA_PSS_SHA_512", "DIGEST", "alias/seed_rsa_2048_sign_verify", id="rsa2048-pss512-digest"),
    pytest.param("RSA_2048", "RSASSA_PKCS1_V1_5_SHA_256", "RAW",    "alias/seed_rsa_2048_sign_verify", id="rsa2048-pkcs1v15-256-raw"),
    pytest.param("RSA_2048", "RSASSA_PKCS1_V1_5_SHA_256", "DIGEST", "alias/seed_rsa_2048_sign_verify", id="rsa2048-pkcs1v15-256-digest"),
    pytest.param("RSA_2048", "RSASSA_PKCS1_V1_5_SHA_384", "RAW",    "alias/seed_rsa_2048_sign_verify", id="rsa2048-pkcs1v15-384-raw"),
    pytest.param("RSA_2048", "RSASSA_PKCS1_V1_5_SHA_384", "DIGEST", "alias/seed_rsa_2048_sign_verify", id="rsa2048-pkcs1v15-384-digest"),
    pytest.param("RSA_2048", "RSASSA_PKCS1_V1_5_SHA_512", "RAW",    "alias/seed_rsa_2048_sign_verify", id="rsa2048-pkcs1v15-512-raw"),
    pytest.param("RSA_2048", "RSASSA_PKCS1_V1_5_SHA_512", "DIGEST", "alias/seed_rsa_2048_sign_verify", id="rsa2048-pkcs1v15-512-digest"),

    pytest.param("RSA_3072", "RSASSA_PSS_SHA_256", "RAW",    "alias/seed_rsa_3072_sign_verify", id="rsa3072-pss256-raw"),
    pytest.param("RSA_3072", "RSASSA_PSS_SHA_256", "DIGEST", "alias/seed_rsa_3072_sign_verify", id="rsa3072-pss256-digest"),
    pytest.param("RSA_3072", "RSASSA_PSS_SHA_384", "RAW",    "alias/seed_rsa_3072_sign_verify", id="rsa3072-pss384-raw"),
    pytest.param("RSA_3072", "RSASSA_PSS_SHA_384", "DIGEST", "alias/seed_rsa_3072_sign_verify", id="rsa3072-pss384-digest"),
    pytest.param("RSA_3072", "RSASSA_PSS_SHA_512", "RAW",    "alias/seed_rsa_3072_sign_verify", id="rsa3072-pss512-raw"),
    pytest.param("RSA_3072", "RSASSA_PSS_SHA_512", "DIGEST", "alias/seed_rsa_3072_sign_verify", id="rsa3072-pss512-digest"),
    pytest.param("RSA_3072", "RSASSA_PKCS1_V1_5_SHA_256", "RAW",    "alias/seed_rsa_3072_sign_verify", id="rsa3072-pkcs1v15-256-raw"),
    pytest.param("RSA_3072", "RSASSA_PKCS1_V1_5_SHA_256", "DIGEST", "alias/seed_rsa_3072_sign_verify", id="rsa3072-pkcs1v15-256-digest"),
    pytest.param("RSA_3072", "RSASSA_PKCS1_V1_5_SHA_384", "RAW",    "alias/seed_rsa_3072_sign_verify", id="rsa3072-pkcs1v15-384-raw"),
    pytest.param("RSA_3072", "RSASSA_PKCS1_V1_5_SHA_384", "DIGEST", "alias/seed_rsa_3072_sign_verify", id="rsa3072-pkcs1v15-384-digest"),
    pytest.param("RSA_3072", "RSASSA_PKCS1_V1_5_SHA_512", "RAW",    "alias/seed_rsa_3072_sign_verify", id="rsa3072-pkcs1v15-512-raw"),
    pytest.param("RSA_3072", "RSASSA_PKCS1_V1_5_SHA_512", "DIGEST", "alias/seed_rsa_3072_sign_verify", id="rsa3072-pkcs1v15-512-digest"),

    pytest.param("RSA_4096", "RSASSA_PSS_SHA_256", "RAW",    "alias/seed_rsa_4096_sign_verify", id="rsa4096-pss256-raw"),
    pytest.param("RSA_4096", "RSASSA_PSS_SHA_256", "DIGEST", "alias/seed_rsa_4096_sign_verify", id="rsa4096-pss256-digest"),
    pytest.param("RSA_4096", "RSASSA_PSS_SHA_384", "RAW",    "alias/seed_rsa_4096_sign_verify", id="rsa4096-pss384-raw"),
    pytest.param("RSA_4096", "RSASSA_PSS_SHA_384", "DIGEST", "alias/seed_rsa_4096_sign_verify", id="rsa4096-pss384-digest"),
    pytest.param("RSA_4096", "RSASSA_PSS_SHA_512", "RAW",    "alias/seed_rsa_4096_sign_verify", id="rsa4096-pss512-raw"),
    pytest.param("RSA_4096", "RSASSA_PSS_SHA_512", "DIGEST", "alias/seed_rsa_4096_sign_verify", id="rsa4096-pss512-digest"),
    pytest.param("RSA_4096", "RSASSA_PKCS1_V1_5_SHA_256", "RAW",    "alias/seed_rsa_4096_sign_verify", id="rsa4096-pkcs1v15-256-raw"),
    pytest.param("RSA_4096", "RSASSA_PKCS1_V1_5_SHA_256", "DIGEST", "alias/seed_rsa_4096_sign_verify", id="rsa4096-pkcs1v15-256-digest"),
    pytest.param("RSA_4096", "RSASSA_PKCS1_V1_5_SHA_384", "RAW",    "alias/seed_rsa_4096_sign_verify", id="rsa4096-pkcs1v15-384-raw"),
    pytest.param("RSA_4096", "RSASSA_PKCS1_V1_5_SHA_384", "DIGEST", "alias/seed_rsa_4096_sign_verify", id="rsa4096-pkcs1v15-384-digest"),
    pytest.param("RSA_4096", "RSASSA_PKCS1_V1_5_SHA_512", "RAW",    "alias/seed_rsa_4096_sign_verify", id="rsa4096-pkcs1v15-512-raw"),
    pytest.param("RSA_4096", "RSASSA_PKCS1_V1_5_SHA_512", "DIGEST", "alias/seed_rsa_4096_sign_verify", id="rsa4096-pkcs1v15-512-digest"),

    # -----------------
    # ECDSA (SIGN_VERIFY)
    # ECDSA_SHA_256 applies to P-256 and secp256k1; 384->P-384; 512->P-521.
    # RAW or DIGEST valid.
    # -----------------
    pytest.param("ECC_NIST_P256", "ECDSA_SHA_256", "RAW",    "alias/seed_ecc_nist_p256_sign_verify", id="p256-ecdsa256-raw"),
    pytest.param("ECC_NIST_P256", "ECDSA_SHA_256", "DIGEST", "alias/seed_ecc_nist_p256_sign_verify", id="p256-ecdsa256-digest"),

    pytest.param("ECC_NIST_P384", "ECDSA_SHA_384", "RAW",    "alias/seed_ecc_nist_p384_sign_verify", id="p384-ecdsa384-raw"),
    pytest.param("ECC_NIST_P384", "ECDSA_SHA_384", "DIGEST", "alias/seed_ecc_nist_p384_sign_verify", id="p384-ecdsa384-digest"),

    pytest.param("ECC_NIST_P521", "ECDSA_SHA_512", "RAW",    "alias/seed_ecc_nist_p521_sign_verify", id="p521-ecdsa512-raw"),
    pytest.param("ECC_NIST_P521", "ECDSA_SHA_512", "DIGEST", "alias/seed_ecc_nist_p521_sign_verify", id="p521-ecdsa512-digest"),

    pytest.param("ECC_SECG_P256K1", "ECDSA_SHA_256", "RAW",    "alias/seed_ecc_secg_p256k1_sign_verify", id="secp256k1-ecdsa256-raw"),
    pytest.param("ECC_SECG_P256K1", "ECDSA_SHA_256", "DIGEST", "alias/seed_ecc_secg_p256k1_sign_verify", id="secp256k1-ecdsa256-digest"),

    # -----------------
    # Ed25519 (SIGN_VERIFY)
    # ED25519_SHA_512 => RAW only
    # ED25519_PH_SHA_512 => DIGEST only
    # -----------------
    pytest.param("ECC_NIST_EDWARDS25519", "ED25519_SHA_512",    "RAW",    "alias/seed_ecc_nist_edwards25519_sign_verify", id="ed25519-sha512-raw"),
    pytest.param("ECC_NIST_EDWARDS25519", "ED25519_PH_SHA_512", "DIGEST", "alias/seed_ecc_nist_edwards25519_sign_verify", id="ed25519-phsha512-digest"),

    # -----------------
    # ML-DSA (SIGN_VERIFY)
    # RAW or EXTERNAL_MU valid for the ML-DSA algorithm
    # -----------------
    pytest.param("ML_DSA_44", "ML_DSA_SHAKE_256", "RAW",         "alias/seed_ml_dsa_44_sign_verify", id="mldsa44-raw"),
    pytest.param("ML_DSA_44", "ML_DSA_SHAKE_256", "EXTERNAL_MU", "alias/seed_ml_dsa_44_sign_verify", id="mldsa44-external-mu"),

    pytest.param("ML_DSA_65", "ML_DSA_SHAKE_256", "RAW",         "alias/seed_ml_dsa_65_sign_verify", id="mldsa65-raw"),
    pytest.param("ML_DSA_65", "ML_DSA_SHAKE_256", "EXTERNAL_MU", "alias/seed_ml_dsa_65_sign_verify", id="mldsa65-external-mu"),

    pytest.param("ML_DSA_87", "ML_DSA_SHAKE_256", "RAW",         "alias/seed_ml_dsa_87_sign_verify", id="mldsa87-raw"),
    pytest.param("ML_DSA_87", "ML_DSA_SHAKE_256", "EXTERNAL_MU", "alias/seed_ml_dsa_87_sign_verify", id="mldsa87-external-mu"),
]


@pytest.mark.parametrize("key_spec,signing_algorithm,message_type,key_id", SIGN_VERIFY_CASES)
def test_local_kms_sign_then_verify(
    kms_client,
    key_spec: str,
    signing_algorithm: str,
    message_type: str,
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

    # ---------------------------------------------------
    # Test Sign

    if message_type == "RAW":
        message = bytes(random.getrandbits(8) for _ in range(4096))
    elif message_type == "EXTERNAL_MU":
        # Message longer than 4096 bytes
        message = bytes(random.getrandbits(8) for _ in range(5000))
        public_key = mldsa_mu.public_key_from_pkix_b64(content.get('PublicKey'))
        message = mldsa_mu.generate(public_key, message)
    else:
        message = bytes(random.getrandbits(8) for _ in range(5000))
        if '256' in signing_algorithm:
            message = hashlib.sha256(message).digest()
        elif '384' in signing_algorithm:
            message = hashlib.sha384(message).digest()
        else:
            message = hashlib.sha512(message).digest()

    code, content = kms_client.post('Sign',{
        'KeyId': key_id,
        'MessageType': message_type,
        'SigningAlgorithm' : signing_algorithm,
        'Message': b64encode(message).decode('ascii')
    })

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get('Signature', '')) > 0
    assert content.get('SigningAlgorithm') == signing_algorithm

    signature = content.get('Signature')

    # ---------------------------------------------------
    # Test Verify

    code, content = kms_client.post('Verify',{
        'KeyId': key_id,
        'MessageType': message_type,
        'SigningAlgorithm' : signing_algorithm,
        'Signature': signature,
        'Message': b64encode(message).decode('ascii')
    })

    assert code == 200
    assert isinstance(content, dict)
    assert content.get('SignatureValid', False) is True
    assert content.get('SigningAlgorithm') == signing_algorithm

    # ---------------------------------------------------
    # Negative Test Verify

    # We "break" the signature so it should fail verification.

    signature_bytes = bytearray(b64decode(signature))
    signature_bytes[0] ^= 0x01  # flip the lowest bit of the first byte
    broken_signature = b64encode(signature_bytes).decode('ascii')

    code, content = kms_client.post('Verify',{
        'KeyId': key_id,
        'MessageType': message_type,
        'SigningAlgorithm' : signing_algorithm,
        'Signature': broken_signature,
        'Message': b64encode(message).decode('ascii')
    })

    assert code == 200
    assert isinstance(content, dict)
    assert content.get('SignatureValid', True) is False
    assert content.get('SigningAlgorithm') == signing_algorithm
