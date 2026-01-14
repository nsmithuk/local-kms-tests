import hashlib

import pytest
from base64 import b64encode, b64decode
import mldsa_mu
import random

HMAC_CASES = [
    pytest.param("HMAC_224", "HMAC_SHA_224", "alias/seed_hmac_224_generate_verify_mac", id="hmac_224"),
    pytest.param("HMAC_256", "HMAC_SHA_256", "alias/seed_hmac_256_generate_verify_mac", id="hmac_256"),
    pytest.param("HMAC_384", "HMAC_SHA_384", "alias/seed_hmac_384_generate_verify_mac", id="hmac_384"),
    pytest.param("HMAC_512", "HMAC_SHA_512", "alias/seed_hmac_512_generate_verify_mac", id="hmac_512"),
]

@pytest.mark.parametrize("key_spec,mac_algorithm,key_id", HMAC_CASES)
def test_local_kms_sign_then_verify(
    kms_client,
    key_spec: str,
    mac_algorithm: str,
    key_id: str,
) -> None:

    # ---------------------------------------------------
    # Generate Verify

    message = b"Test Message"

    code, content = kms_client.post('GenerateMac',{
        'KeyId': key_id,
        'MacAlgorithm': mac_algorithm,
        'Message': b64encode(message).decode('ascii')
    })

    assert code == 200
    assert isinstance(content, dict)
    assert len(content.get('Mac', '')) > 0
    assert content.get('MacAlgorithm') == mac_algorithm

    mac = b64decode(content.get('Mac'))

    if mac_algorithm == "HMAC_SHA_224":
        assert len(mac) == 28
    elif mac_algorithm == "HMAC_SHA_256":
        assert len(mac) == 32
    elif mac_algorithm == "HMAC_SHA_384":
        assert len(mac) == 48
    elif mac_algorithm == "HMAC_SHA_512":
        assert len(mac) == 64


    # ---------------------------------------------------
    # Test Verify

    code, content = kms_client.post('VerifyMac',{
        'KeyId': key_id,
        'MacAlgorithm': mac_algorithm,
        'Message': b64encode(message).decode('ascii'),
        'Mac': b64encode(mac).decode('ascii')
    })

    assert code == 200
    assert isinstance(content, dict)
    assert content.get('MacValid', False) is True
    assert content.get('MacAlgorithm') == mac_algorithm

    # ---------------------------------------------------
    # Negative Test Verify

    # We "break" the signature so it should fail verification.
    mac_bytes = bytearray(mac)
    mac_bytes[0] ^= 0x01  # flip the lowest bit of the first byte
    broken_mac = b64encode(mac_bytes).decode('ascii')

    code, content = kms_client.post('VerifyMac',{
        'KeyId': key_id,
        'MacAlgorithm': mac_algorithm,
        'Message': b64encode(message).decode('ascii'),
        'Mac': broken_mac
    })

    assert code == 200
    assert isinstance(content, dict)
    assert content.get('MacValid', True) is False
    assert content.get('MacAlgorithm') == mac_algorithm
